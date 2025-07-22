import asyncio
import httpx
import re
import os
import csv
import hashlib
import yaml
import base64
import json
import ipaddress
import dns.resolver
import logging
from typing import Dict, Set, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from aiofiles import open as aio_open
from playwright.async_api import async_playwright, Playwright
from concurrent.futures import ThreadPoolExecutor
import socket

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxy_scraper.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('proxy_scraper')

class ProxyScraperConfig:
    """代理抓取器配置类"""
    def __init__(self, config_file: str = "config.yaml"):
        self.output_dir: str = "data"
        self.cache_dir: str = "cache"
        self.cache_expiration_hours: int = 24
        self.max_concurrent_requests: int = 5
        self.request_timeout_seconds: int = 30
        self.retry_attempts: int = 1
        self.tcp_test_timeout: int = 5  # TCP 测试超时时间
        self.max_dns_threads: int = 10  # DNS 解析最大线程数
        self.load_config(config_file)

    def load_config(self, config_file: str) -> None:
        """从 YAML 文件加载配置"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            self.output_dir = config.get('output_dir', self.output_dir)
            self.cache_dir = config.get('cache_dir', self.cache_dir)
            self.cache_expiration_hours = config.get('cache_expiration_hours', self.cache_expiration_hours)
            self.max_concurrent_requests = config.get('max_concurrent_requests', self.max_concurrent_requests)
            self.request_timeout_seconds = config.get('request_timeout_seconds', self.request_timeout_seconds)
            self.retry_attempts = config.get('retry_attempts', self.retry_attempts)
            self.tcp_test_timeout = config.get('tcp_test_timeout', self.tcp_test_timeout)
            self.max_dns_threads = config.get('max_dns_threads', self.max_dns_threads)
            logger.info(f"Loaded configuration from {config_file}")
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using default settings")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")

class ProxyScraper:
    """代理抓取器主类"""
    USER_AGENTS: Dict[str, List[str]] = {
        "desktop": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        ],
        "mobile": [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ]
    }

    NODE_REGEXES: Dict[str, str] = {
        "hysteria2": r"hysteria2:\/\/(?:[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?([a-zA-Z0-9\-\.]+)(?::(\d+))?\/?\?.*",
        "vmess": r"vmess:\/\/([a-zA-Z0-9+\/=]+)",
        "trojan": r"trojan:\/\/([a-zA-Z0-9\-_.~%]+)@([a-zA-Z0-9\-\.]+):(\d+)(?:\/\?.*)?",
        "ss": r"ss:\/\/([a-zA-Z0-9+\/=]+)@([a-zA-Z0-9\-\.]+):(\d+)(?:#(.*))?",
        "ssr": r"ssr:\/\/([a-zA-Z0-9+\/=]+)",
        "vless": r"vless:\/\/([0-9a-fA-F\-]+)@([a-zA-Z0-9\-\.]+):(\d+)\?(?:.*&)?type=([a-zA-Z0-9]+)(?:&security=([a-zA-Z0-9]+))?.*",
        "tuic": r"tuic:\/\/([0-9a-fA-F\-]+):([a-zA-Z0-9\-_.~%]+)@([a-zA-Z0-9\-\.]+):(\d+)\?(?:.*&)?(?:udp_relay=([^&]*))?",
        "wg": r"wg:\/\/([a-zA-Z0-9+\/=]+)",
    }

    def __init__(self, config: ProxyScraperConfig):
        self.config = config
        self.cache_lock = asyncio.Lock()
        self.processed_urls: Set[str] = set()
        self.global_valid_nodes: Dict[str, str] = {}  # 仅存储通过可用性测试的节点
        self.global_unique_nodes: Dict[str, str] = {}  # 存储所有唯一节点
        self.all_nodes_count: Dict[str, int] = {}

    async def read_cache(self, url: str) -> Optional[str]:
        """读取缓存内容"""
        cache_path = os.path.join(self.config.cache_dir, hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache")
        if not os.path.exists(cache_path):
            return None

        mod_time = datetime.fromtimestamp(os.path.getmtime(cache_path))
        if datetime.now() - mod_time > timedelta(hours=self.config.cache_expiration_hours):
            try:
                os.remove(cache_path)
                logger.info(f"Cache for {url} expired and removed")
            except Exception as e:
                logger.warning(f"Failed to remove expired cache {cache_path}: {e}")
            return None

        async with self.cache_lock:
            try:
                async with aio_open(cache_path, 'r', encoding='utf-8') as f:
                    return await f.read()
            except Exception as e:
                logger.error(f"Failed to read cache for {url}: {e}")
                return None

    async def write_cache(self, url: str, content: str) -> None:
        """写入缓存内容"""
        cache_path = os.path.join(self.config.cache_dir, hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache")
        os.makedirs(self.config.cache_dir, exist_ok=True)
        async with self.cache_lock:
            try:
                async with aio_open(cache_path, 'w', encoding='utf-8') as f:
                    await f.write(content)
                logger.info(f"Cached content for {url}")
            except Exception as e:
                logger.error(f"Failed to write cache for {url}: {e}")

    async def fetch_url(self, url: str, http_client: httpx.AsyncClient, playwright: Playwright) -> Optional[str]:
        """获取 URL 内容，先用 httpx，失败则用 Playwright"""
        cached_content = await self.read_cache(url)
        if cached_content:
            return cached_content

        parsed_url = urlparse(url)
        full_urls = [f"https://{url}" if not parsed_url.scheme else url,
                     f"http://{url.replace('https://', '', 1)}" if parsed_url.scheme == "https" else url]

        content = None
        for full_url in full_urls:
            for attempt in range(self.config.retry_attempts):
                try:
                    async with asyncio.timeout(self.config.request_timeout_seconds):
                        headers = {"User-Agent": random.choice(self.USER_AGENTS[random.choice(list(self.USER_AGENTS.keys()))])}
                        response = await http_client.get(full_url, headers=headers)
                        response.raise_for_status()
                        content = response.text
                        logger.info(f"Successfully fetched {full_url} with httpx")
                        break
                except (asyncio.TimeoutError, httpx.HTTPStatusError, httpx.RequestError) as e:
                    logger.warning(f"httpx failed for {full_url} (attempt {attempt + 1}): {e}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                except Exception as e:
                    logger.error(f"Unexpected error fetching {full_url} with httpx: {e}")
                    break
            if content:
                break

        if not content:
            for attempt in range(self.config.retry_attempts):
                browser = None
                try:
                    async with asyncio.timeout(self.config.request_timeout_seconds * 2):
                        browser = await playwright.chromium.launch()
                        page = await browser.new_page()
                        await page.set_extra_http_headers(headers)
                        await page.goto(full_url, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Successfully fetched {full_url} with Playwright")
                        break
                except Exception as e:
                    logger.warning(f"Playwright failed for {full_url} (attempt {attempt + 1}): {e}")
                    await asyncio.sleep(2 ** attempt)
                finally:
                    if browser:
                        await browser.close()

        if content:
            await self.write_cache(url, content)
        return content

    def is_valid_ip(self, address: str) -> bool:
        """验证 IP 地址有效性"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    async def test_node_connectivity(self, host: str, port: int) -> bool:
        """测试节点可用性（异步 TCP 连接）"""
        try:
            async with asyncio.timeout(self.config.tcp_test_timeout):
                reader, writer = await asyncio.open_connection(host, port)
                writer.close()
                await writer.wait_closed()
                logger.info(f"TCP connection succeeded for {host}:{port}")
                return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.warning(f"TCP connection failed for {host}:{port}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error testing {host}:{port}: {e}")
            return False

    def validate_node(self, protocol: str, data: Dict[str, str]) -> bool:
        """验证节点有效性"""
        try:
            if protocol == "hysteria2":
                return (
                    all(k in data for k in ['host', 'port']) and
                    data['host'] and data['port'].isdigit() and
                    (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or self.is_valid_ip(data['host'])) and
                    1 <= int(data['port']) <= 65535
                )
            elif protocol == "vmess":
                try:
                    decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8')
                    json_data = json.loads(decoded)
                    return (
                        all(k in json_data for k in ['add', 'port', 'id']) and
                        json_data['add'] and json_data['port'] and json_data['id'] and
                        (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or self.is_valid_ip(json_data['add'])) and
                        isinstance(json_data['port'], (int, str)) and
                        1 <= int(json_data['port']) <= 65535 and
                        re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id'])
                    )
                except Exception:
                    logger.debug(f"Invalid vmess node: {data.get('data', '')[:50]}...")
                    return False
            elif protocol == "trojan":
                return (
                    all(k in data for k in ['password', 'host', 'port']) and
                    data['password'] and data['host'] and data['port'].isdigit() and
                    (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or self.is_valid_ip(data['host'])) and
                    1 <= int(data['port']) <= 65535
                )
            elif protocol == "ss":
                if not all(k in data for k in ['method_password', 'host', 'port']):
                    return False
                try:
                    padded_mp = data['method_password'] + '=' * (4 - len(data['method_password']) % 4)
                    decoded_mp = base64.b64decode(padded_mp).decode('utf-8')
                    if ':' not in decoded_mp:
                        return False
                    return (
                        data['host'] and data['port'].isdigit() and
                        (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or self.is_valid_ip(data['host'])) and
                        1 <= int(data['port']) <= 65535
                    )
                except Exception:
                    logger.debug(f"Invalid ss node: {data.get('method_password', '')[:50]}...")
                    return False
            elif protocol == "ssr":
                try:
                    decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8')
                    parts = decoded.split(':')
                    if len(parts) < 6:
                        return False
                    server, port = parts[0], parts[1]
                    password = base64.b64decode(parts[5] + '=' * (4 - len(parts[5]) % 4)).decode('utf-8')
                    return (
                        server and port.isdigit() and password and
                        (re.match(r"^[a-zA-Z0-9\-\.]+$", server) or self.is_valid_ip(server)) and
                        1 <= int(port) <= 65535
                    )
                except Exception:
                    logger.debug(f"Invalid ssr node: {data.get('data', '')[:50]}...")
                    return False
            elif protocol == "vless":
                return (
                    all(k in data for k in ['uuid', 'host', 'port', 'type']) and
                    data['uuid'] and data['host'] and data['port'].isdigit() and data['type'] and
                    re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']) and
                    (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or self.is_valid_ip(data['host'])) and
                    1 <= int(data['port']) <= 65535
                )
            elif protocol == "tuic":
                return (
                    all(k in data for k in ['uuid', 'password', 'host', 'port']) and
                    data['uuid'] and data['password'] and data['host'] and data['port'].isdigit() and
                    re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']) and
                    (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or self.is_valid_ip(data['host'])) and
                    1 <= int(data['port']) <= 65535
                )
            elif protocol == "wg":
                try:
                    decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8')
                    return "PrivateKey" in decoded and "Address" in decoded and "Endpoint" in decoded
                except Exception:
                    logger.debug(f"Invalid wg node: {data.get('data', '')[:50]}...")
                    return False
            return False
        except Exception as e:
            logger.debug(f"Validation failed for {protocol} node: {e}")
            return False

    def get_node_canonical_fingerprint(self, node_url: str) -> Optional[str]:
        """生成节点唯一指纹"""
        base_url = node_url.split('#', 1)[0]
        try:
            parsed_url = urlparse(base_url)
            scheme = parsed_url.scheme
            if not scheme:
                return None

            if scheme == "ss":
                method_password, server_port = parsed_url.netloc.split('@', 1)
                decoded_mp = base64.b64decode(method_password + '=' * (4 - len(method_password) % 4)).decode('utf-8')
                method, password = decoded_mp.split(':', 1)
                return f"ss://{method}:{password}@{server_port}"
            elif scheme == "ssr":
                encoded_params = base_url[len("ssr://"):]
                decoded_params = base64.b64decode(encoded_params + '=' * (4 - len(encoded_params) % 4)).decode('utf-8')
                parts = decoded_params.split(':')
                if len(parts) >= 6:
                    password = base64.b64decode(parts[5] + '=' * (4 - len(parts[5]) % 4)).decode('utf-8')
                    parts[5] = password
                return f"ssr://{':'.join(parts)}"
            elif scheme == "vmess":
                encoded_json = base_url[len("vmess://"):]
                decoded_json = base64.b64decode(encoded_json + '=' * (4 - len(encoded_json) % 4)).decode('utf-8')
                vmess_config = json.loads(decoded_json)
                fingerprint_data = {
                    "add": vmess_config.get("add"),
                    "port": vmess_config.get("port"),
                    "id": vmess_config.get("id"),
                }
                for key in sorted(["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]):
                    if key in vmess_config and vmess_config[key] is not None:
                        fingerprint_data[key] = vmess_config[key]
                return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"
            elif scheme in ["vless", "trojan", "hysteria2", "tuic"]:
                query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
                sorted_query_params = [(key, value) for key in sorted(query_params_list.keys()) for value in sorted(query_params_list[key])]
                sorted_query_string = urlencode(sorted_query_params)
                canonical_url_parts = [scheme, "://"]
                if parsed_url.username:
                    canonical_url_parts.append(parsed_url.username)
                    if parsed_url.password:
                        canonical_url_parts.append(f":{parsed_url.password}")
                    canonical_url_parts.append("@")
                canonical_url_parts.append(parsed_url.netloc)
                if parsed_url.path:
                    canonical_url_parts.append(parsed_url.path)
                if sorted_query_string:
                    canonical_url_parts.append("?")
                    canonical_url_parts.append(sorted_query_string)
                return "".join(canonical_url_parts)
            elif scheme == "wg":
                return f"wg://{base_url[len('wg://'):]}"
            return None
        except Exception as e:
            logger.debug(f"Failed to generate fingerprint for {node_url[:50]}...: {e}")
            return None

    def extract_nodes_from_text(self, text: str) -> Set[str]:
        """从文本中提取节点"""
        nodes = set()
        for protocol, regex in self.NODE_REGEXES.items():
            for match in re.finditer(regex, text, re.IGNORECASE):
                node = match.group(0)
                if self.validate_node(protocol, match.groupdict()):
                    nodes.add(node)

        base64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/])", text)
        for b64 in base64_candidates:
            if len(b64) > 30:
                try:
                    decoded = base64.b64decode(b64).decode('utf-8')
                    nodes.update(self.extract_nodes_from_text(decoded))
                except Exception:
                    pass

        try:
            yaml_content = yaml.safe_load(text)
            if isinstance(yaml_content, (dict, list)):
                def extract_from_nested(data):
                    if isinstance(data, dict):
                        for value in data.values():
                            if isinstance(value, str):
                                nodes.update(self.extract_nodes_from_text(value))
                            elif isinstance(value, (dict, list)):
                                extract_from_nested(value)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                nodes.update(self.extract_nodes_from_text(item))
                            elif isinstance(item, (dict, list)):
                                extract_from_nested(item)
                extract_from_nested(yaml_content)
        except yaml.YAMLError:
            pass

        try:
            json_content = json.loads(text)
            if isinstance(json_content, (dict, list)):
                def extract_from_nested(data):
                    if isinstance(data, dict):
                        for value in data.values():
                            if isinstance(value, str):
                                nodes.update(self.extract_nodes_from_text(value))
                            elif isinstance(value, (dict, list)):
                                extract_from_nested(value)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                nodes.update(self.extract_nodes_from_text(item))
                            elif isinstance(item, (dict, list)):
                                extract_from_nested(item)
                extract_from_nested(json_content)
        except json.JSONDecodeError:
            pass

        return nodes

    async def process_url(self, url: str, http_client: httpx.AsyncClient, playwright: Playwright, semaphore: asyncio.Semaphore) -> Set[str]:
        """处理单个 URL"""
        if url in self.processed_urls:
            logger.debug(f"Skipping already processed URL: {url}")
            return set()

        self.processed_urls.add(url)
        content = await self.fetch_url(url, http_client, playwright)
        if not content:
            logger.error(f"Failed to fetch content from {url}")
            return set()

        soup = BeautifulSoup(content, 'html.parser')
        nodes = set()
        for tag_name in ['pre', 'code', 'textarea', 'script']:
            for tag in soup.find_all(tag_name):
                text_content = tag.get_text(separator='\n', strip=True)
                if text_content:
                    nodes.update(self.extract_nodes_from_text(text_content))
        if not nodes:
            nodes.update(self.extract_nodes_from_text(soup.get_text(separator='\n', strip=True)))

        valid_nodes = set()
        for node in nodes:
            fingerprint = self.get_node_canonical_fingerprint(node)
            if fingerprint and fingerprint not in self.global_unique_nodes:
                parsed_url = urlparse(node)
                host = parsed_url.hostname or (parsed_url.netloc.split('@')[-1] if '@' in parsed_url.netloc else parsed_url.netloc)
                port = parsed_url.port or (parsed_url.netloc.split(':')[-1] if ':' in parsed_url.netloc else None)
                if host and port and await self.test_node_connectivity(host, int(port)):
                    self.global_valid_nodes[fingerprint] = node
                    self.global_unique_nodes[fingerprint] = node
                    valid_nodes.add(node)
                else:
                    self.global_unique_nodes[fingerprint] = node
                    valid_nodes.add(node)  # 仍保留不可连接节点，供后续分析

        output_file = os.path.join(self.config.output_dir, f"{urlparse(url).netloc or 'unknown'}.txt")
        os.makedirs(self.config.output_dir, exist_ok=True)
        if valid_nodes:
            async with aio_open(output_file, 'w', encoding='utf-8') as f:
                for node in valid_nodes:
                    await f.write(node + '\n')
            logger.info(f"Saved {len(valid_nodes)} nodes from {url} to {output_file}")
        self.all_nodes_count[url] = len(valid_nodes)
        return valid_nodes

    async def run(self, urls: List[str]) -> None:
        """运行抓取器"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        os.makedirs(self.config.cache_dir, exist_ok=True)

        valid_urls = await self.check_dns_resolution(urls)
        async with async_playwright() as p:
            async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
                semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
                tasks = [self.process_url(url, client, p, semaphore) for url in valid_urls]
                await asyncio.gather(*tasks, return_exceptions=True)

        with open("all_unique_nodes.txt", 'w', encoding='utf-8') as f:
            for node in sorted(self.global_unique_nodes.values()):
                f.write(node + '\n')
        logger.info(f"Saved {len(self.global_unique_nodes)} unique nodes to all_unique_nodes.txt")

        with open("valid_nodes.txt", 'w', encoding='utf-8') as f:
            for node in sorted(self.global_valid_nodes.values()):
                f.write(node + '\n')
        logger.info(f"Saved {len(self.global_valid_nodes)} valid nodes to valid_nodes.txt")

        with open("nodes_summary.csv", 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['URL', '节点数量'])
            writer.writeheader()
            for url, count in self.all_nodes_count.items():
                writer.writerow({'URL': url, '节点数量': count})
        logger.info("Saved node summary to nodes_summary.csv")

    def resolve_dns(self, hostname: str) -> bool:
        """同步 DNS 解析，用于线程池"""
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            return bool(answers)
        except Exception as e:
            logger.warning(f"DNS resolution failed for {hostname}: {e}")
            return False

    async def check_dns_resolution(self, urls: List[str]) -> List[str]:
        """多线程 DNS 解析"""
        valid_urls = []
        with ThreadPoolExecutor(max_workers=self.config.max_dns_threads) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(executor, self.resolve_dns, urlparse(url).hostname or urlparse(f"http://{url}").hostname) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for url, result in zip(urls, results):
                if isinstance(result, Exception) or not result:
                    logger.warning(f"DNS resolution failed for {url}")
                else:
                    valid_urls.append(url)
        logger.info(f"Resolved {len(valid_urls)} valid URLs via DNS")
        return valid_urls

async def main():
    config = ProxyScraperConfig()
    scraper = ProxyScraper(config)
    try:
        with open("sources.list", 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.critical("sources.list file not found")
        return
    await scraper.run(urls)

if __name__ == "__main__":
    asyncio.run(main())
