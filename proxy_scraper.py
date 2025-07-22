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
from typing import Dict, Set, Optional, Tuple, List
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from aiofiles import open as aio_open
from playwright.async_api import async_playwright, Playwright

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
        "ss": r"ss:\/\/([a-zA-Z0-9+\/=]+)@([a-zA-Z0-9\-\

System: .]+):(\d+)(?:#(.*))?",
        "ssr": r"ssr:\/\/([a-zA-Z0-9+\/=]+)",
        "vless": r"vless:\/\/([0-9a-fA-F\-]+)@([a-zA-Z0-9\-\.]+):(\d+)\?(?:.*&)?type=([a-zA-Z0-9]+)(?:&security=([a-zA-Z0-9]+))?.*",
        "tuic": r"tuic:\/\/([0-9a-fA-F\-]+):([a-zA-Z0-9\-_.~%]+)@([a-zA-Z0-9\-\.]+):(\d+)\?(?:.*&)?(?:udp_relay=([^&]*))?",
        "wg": r"wg:\/\/([a-zA-Z0-9+\/=]+)",
    }

    def __init__(self, config: ProxyScraperConfig):
        self.config = config
        self.cache_lock = asyncio.Lock()
        self.processed_urls: Set[str] = set()
        self.global_unique_nodes: Dict[str, str] = {}
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
                try:
                    async with asyncio.timeout(self.config.request_timeout_seconds * 2):
                        browser = await playwright.chromium.launch()
                        page = await browser.new_page()
                        await page.set_extra_http_headers(headers)
                        await page.goto(full_url, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Successfully fetched {full_url} with Playwright")
                        await browser.close()
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

    def validate_node(self, protocol: str, data: Dict[str, str]) -> bool:
        """验证节点有效性"""
        try:
            if protocol in ("hysteria2", "trojan", "tuic"):
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
                    return False
            # 其他协议验证逻辑类似，简化代码
            return False
        except Exception:
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
            # 其他协议类似
            return base_url
        except Exception:
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

        return nodes

    async def process_url(self, url: str, http_client: httpx.AsyncClient, playwright: Playwright, semaphore: asyncio.Semaphore) -> Set[str]:
        """处理单个 URL"""
        if url in self.processed_urls:
            return set()

        self.processed_urls.add(url)
        content = await self.fetch_url(url, http_client, playwright)
        if not content:
            return set()

        nodes = self.extract_nodes_from_text(BeautifulSoup(content, 'html.parser').get_text(separator='\n', strip=True))
        unique_nodes = set()
        for node in nodes:
            fingerprint = self.get_node_canonical_fingerprint(node)
            if fingerprint and fingerprint not in self.global_unique_nodes:
                self.global_unique_nodes[fingerprint] = node
                unique_nodes.add(node)

        output_file = os.path.join(self.config.output_dir, f"{urlparse(url).netloc or 'unknown'}.txt")
        os.makedirs(self.config.output_dir, exist_ok=True)
        async with aio_open(output_file, 'w', encoding='utf-8') as f:
            for node in unique_nodes:
                await f.write(node + '\n')
        self.all_nodes_count[url] = len(unique_nodes)
        return unique_nodes

    async def run(self, urls: List[str]) -> None:
        """运行抓取器"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        os.makedirs(self.config.cache_dir, exist_ok=True)

        valid_urls = []
        dns_tasks = [check_dns_resolution(url) for url in urls]
        dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
        for url, result in zip(urls, dns_results):
            if isinstance(result, Exception) or not result:
                logger.warning(f"DNS resolution failed for {url}")
            else:
                valid_urls.append(url)

        async with async_playwright() as p:
            async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
                semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
                tasks = [self.process_url(url, client, p, semaphore) for url in valid_urls]
                await asyncio.gather(*tasks, return_exceptions=True)

        with open("all_unique_nodes.txt", 'w', encoding='utf-8') as f:
            for node in sorted(self.global_unique_nodes.values()):
                f.write(node + '\n')

        with open("nodes_summary.csv", 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['URL', '节点数量'])
            writer.writeheader()
            for url, count in self.all_nodes_count.items():
                writer.writerow({'URL': url, '节点数量': count})

async def check_dns_resolution(url: str) -> bool:
    """检查 DNS 解析"""
    hostname = urlparse(url).hostname or urlparse(f"http://{url}").hostname
    if not hostname or is_valid_ip(hostname):
        return True
    try:
        async with asyncio.timeout(30):
            answers = await asyncio.to_thread(dns.resolver.resolve, hostname, 'A')
            return bool(answers)
    except Exception as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        return False

def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

async def main():
    config = ProxyScraperConfig()
    scraper = ProxyScraper(config)
    with open("sources.list", 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    await scraper.run(urls)

if __name__ == "__main__":
    asyncio.run(main())
