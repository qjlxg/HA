import re
import os
import csv
import base64
import yaml
import json
import hashlib
import random
import warnings
import time
import asyncio
from urllib.parse import unquote, urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup
import logging
import httpx
import urllib3
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
import aiofiles
import geoip2.database
import socket
import aiodns
from functools import lru_cache

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 数据类定义 ---
@dataclass
class CrawlerConfig:
    """爬虫配置类"""
    data_dir: str = "data"
    sources_file: str = "sources.list"
    node_counts_file: str = field(default_factory=lambda: os.path.join("data", "node_counts.csv"))
    cache_file: str = field(default_factory=lambda: os.path.join("data", "url_cache.json"))
    failed_urls_file: str = field(default_factory=lambda: os.path.join("data", "failed_urls.log"))
    concurrent_requests_limit: int = 20
    request_timeout: float = 20.0
    retry_attempts: int = 3
    cache_save_interval: int = 50
    max_recursion_depth: int = 2
    max_crawl_depth_per_site: int = 1
    proxies: Optional[Dict] = None
    user_agents: List[str] = field(default_factory=list)
    node_test: Dict = field(default_factory=dict)
    geoip: Dict = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理，确保目录存在和路径正确"""
        os.makedirs(self.data_dir, exist_ok=True)
        if not os.path.isabs(self.node_counts_file) and not self.node_counts_file.startswith(self.data_dir):
            self.node_counts_file = os.path.join(self.data_dir, os.path.basename(self.node_counts_file))
        if not os.path.isabs(self.cache_file) and not self.cache_file.startswith(self.data_dir):
            self.cache_file = os.path.join(self.data_dir, os.path.basename(self.cache_file))
        if not os.path.isabs(self.failed_urls_file) and not self.failed_urls_file.startswith(self.data_dir):
            self.failed_urls_file = os.path.join(self.data_dir, os.path.basename(self.failed_urls_file))
        if not self.user_agents:
            self.user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
            ]
        self.geoip.setdefault('enable_geo_rename', False)
        self.geoip.setdefault('database_path', os.path.join(self.data_dir, 'GeoLite2-Country.mmdb'))
        self.geoip.setdefault('default_country', 'UNKNOWN')
        self.geoip.setdefault('dns_timeout', 5.0)
        self.geoip.setdefault('dns_servers', ['8.8.8.8', '1.1.1.1'])
        self.geoip.setdefault('cache_size', 10000)
        self.geoip.setdefault('max_age_days', 30)
        self.geoip.setdefault('license_key', None)

# --- 节点协议正则表达式 ---
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}', re.IGNORECASE)

# --- 辅助函数 ---

async def load_config(config_file: str) -> CrawlerConfig:
    """从 YAML 文件加载配置"""
    try:
        async with aiofiles.open(config_file, mode='r', encoding='utf-8') as f:
            content = await f.read()
            config_data = yaml.safe_load(content)
            return CrawlerConfig(**config_data)
    except FileNotFoundError:
        logger.error(f"配置文件 '{config_file}' 未找到，将使用默认配置。")
        return CrawlerConfig()
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}，将使用默认配置。")
        return CrawlerConfig()

async def read_sources(file_path: str) -> List[str]:
    """异步读取 sources.list 文件中的 URL"""
    try:
        async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
            lines = await f.readlines()
        urls = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        logger.info(f"成功读取 {len(urls)} 个源 URL。")
        return urls
    except FileNotFoundError:
        logger.error(f"源文件 '{file_path}' 未找到。")
        return []
    except Exception as e:
        logger.error(f"读取源文件失败: {e}。")
        return []

async def load_cache(cache_file: str) -> Dict:
    """异步加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            async with aiofiles.open(cache_file, mode='r', encoding='utf-8') as f:
                content = await f.read()
            return json.loads(content)
        except json.JSONDecodeError:
            logger.warning(f"缓存文件 '{cache_file}' 损坏，将重新生成。")
            return {}
        except Exception as e:
            logger.error(f"加载缓存失败 '{cache_file}': {e}。")
            return {}
    return {}

async def save_cache(cache_file: str, cache_data: Dict) -> None:
    """异步保存 URL 缓存"""
    try:
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        async with aiofiles.open(cache_file, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(cache_data, indent=4, ensure_ascii=False))
    except Exception as e:
        logger.error(f"保存缓存失败 '{cache_file}': {e}。")

async def log_failed_url(url: str, reason: str, config: CrawlerConfig) -> None:
    """异步记录失败的 URL 及其原因到文件"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        os.makedirs(os.path.dirname(config.failed_urls_file), exist_ok=True)
        async with aiofiles.open(config.failed_urls_file, mode='a', encoding='utf-8') as f:
            await f.write(f"[{timestamp}] {url}: {reason}\n")
    except Exception as e:
        logger.error(f"记录失败 URL 失败 '{config.failed_urls_file}': {e}。")

def decode_base64_recursive(data: str) -> Optional[str]:
    """尝试递归解码 Base64 字符串"""
    if not isinstance(data, str) or not data.strip() or len(data) < 20:
        return None
    current_decoded = data
    for _ in range(5):
        try:
            decoded_bytes = base64.urlsafe_b64decode(current_decoded + '==')
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if not temp_decoded or temp_decoded == current_decoded:
                break
            if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                current_decoded = temp_decoded
                break
            current_decoded = temp_decoded
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
                decoded_bytes = base64.b64decode(current_decoded + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded:
                    break
                if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                    current_decoded = temp_decoded
                    break
                current_decoded = temp_decoded
            except (base64.binascii.Error, UnicodeDecodeError):
                break
        except Exception as e:
            logger.debug(f"Base64 解码错误: {e}")
            break
    return current_decoded

@lru_cache(maxsize=None)
async def resolve_hostname_async(hostname: str) -> Optional[str]:
    """异步解析域名到 IP 地址，带缓存"""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return hostname
    try:
        resolver = aiodns.Resolver(timeout=5.0, nameservers=['8.8.8.8', '1.1.1.1'])
        result = await resolver.query(hostname, 'A')
        return result[0].host if result else None
    except aiodns.error.DNSError:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            logger.debug(f"同步 DNS 解析失败 {hostname}")
            return None
    except Exception as e:
        logger.debug(f"解析 {hostname} 时发生意外错误: {e}")
        return None

async def fetch_content(url: str, client: httpx.AsyncClient, config: CrawlerConfig, cache_data: Dict = None) -> Tuple[Optional[str], Optional[Dict], str]:
    """异步获取 URL 内容，包含重试机制"""
    headers = {
        'User-Agent': random.choice(config.user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'DNT': '1',
        'Connection': 'keep-alive'
    }
    if cache_data:
        etag = cache_data.get('etag')
        if etag is not None:
            headers['If-None-Match'] = etag
        last_modified = cache_data.get('last_modified')
        if last_modified is not None:
            headers['If-Modified-Since'] = last_modified

    test_urls = []
    parsed = urlparse(url)
    if not parsed.scheme:
        test_urls.extend([f"https://{url}", f"http://{url}"])
    else:
        test_urls.append(url)

    for attempt in range(config.retry_attempts):
        for test_url in test_urls:
            try:
                response = await client.get(test_url, headers=headers, follow_redirects=True)
                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                content_type = response.headers.get('Content-Type', '').lower()
                content_hash = hashlib.sha256(response.content).hexdigest()
                if cache_data and cache_data.get('content_hash') == content_hash:
                    logger.info(f"{url} 内容未变更，跳过解析。")
                    return None, {
                        'etag': new_etag,
                        'last_modified': new_last_modified,
                        'content_hash': content_hash,
                        'content_type': content_type,
                        'last_updated_timestamp': cache_data.get('last_updated_timestamp', 'N/A')
                    }, "SKIPPED_UNCHANGED"
                response.raise_for_status()
                current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                return response.text, {
                    'etag': new_etag,
                    'last_modified': new_last_modified,
                    'content_hash': content_hash,
                    'content_type': content_type,
                    'last_updated_timestamp': current_time
                }, "FETCH_SUCCESS"
            except httpx.TimeoutException:
                logger.warning(f"{url} 请求超时 (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = "FETCH_FAILED_TIMEOUT"
            except httpx.HTTPStatusError as e:
                logger.warning(f"{url} HTTP错误 ({e.response.status_code}) (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = f"FETCH_FAILED_HTTP_{e.response.status_code}"
            except httpx.ConnectError as e:
                logger.warning(f"{url} 连接错误 ({e}) (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = "FETCH_FAILED_CONNECTION_ERROR"
            except Exception as e:
                logger.error(f"{url} 未知错误: {e} (尝试 {attempt + 1}/{config.retry_attempts})。", exc_info=True)
                status = "FETCH_FAILED_UNEXPECTED_ERROR"
        if attempt < config.retry_attempts - 1:
            await asyncio.sleep(2 ** attempt + random.uniform(0.5, 1.5))
    logger.error(f"{url} 所有尝试均失败。")
    await log_failed_url(url, status, config)
    return None, None, status

def standardize_node_url(node_url: str) -> str:
    """标准化节点链接，确保一致性"""
    if not isinstance(node_url, str):
        return ""
    try:
        parsed = urlparse(node_url)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
            encoded_query = urlencode(sorted_params, doseq=True)
            parsed = parsed._replace(query=encoded_query)
        if node_url.lower().startswith("vmess://"):
            try:
                b64_content = parsed.netloc
                decoded = decode_base64_recursive(b64_content)
                if decoded:
                    vmess_json = json.loads(decoded)
                    sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                    normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                    return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}"
            except Exception as e:
                logger.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
        return parsed.geturl().replace('\n', '').replace('\r', '')
    except ValueError as e:
        logger.warning(f"标准化节点URL时遇到无效格式错误: {e} - URL: {node_url}")
        return node_url.replace('\n', '').replace('\r', '')

def is_valid_hysteria2_node(node_link: str) -> bool:
    """校验 Hysteria2 链接有效性"""
    if not node_link.lower().startswith("hysteria2://"):
        return False
    try:
        parsed = urlparse(node_link)
        netloc = parsed.netloc
        if '@' not in netloc:
            logger.debug(f"Hysteria2 节点缺少认证信息: {node_link}")
            return False
        auth_info, addr_port = netloc.split('@', 1)
        if not auth_info.strip():
            logger.debug(f"Hysteria2 节点认证信息为空: {node_link}")
            return False
        if ':' not in addr_port:
            logger.debug(f"Hysteria2 节点缺少端口: {node_link}")
            return False
        server, port_str = addr_port.rsplit(':', 1)
        if not server:
            logger.debug(f"Hysteria2 节点服务器地址为空: {node_link}")
            return False
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            logger.debug(f"Hysteria2 节点端口无效: {node_link}")
            return False
        return True
    except ValueError:
        logger.debug(f"Hysteria2 链接格式不正确: {node_link}")
        return False

def is_valid_node(node_url: str) -> bool:
    """检查节点 URL 的有效性"""
    if not isinstance(node_url, str) or len(node_url) < 10:
        logger.debug(f"节点URL太短或不是字符串: {node_url}")
        return False
    parsed = urlparse(node_url)
    scheme = parsed.scheme.lower()
    if scheme not in NODE_PATTERNS:
        logger.debug(f"不支持的节点协议: {scheme} - {node_url}")
        return False
    node_info = parse_node_url_to_info(node_url)
    if not node_info:
        logger.debug(f"无法解析节点信息: {node_url}")
        return False
    server = node_info.get('server')
    port = node_info.get('port')
    if not server:
        logger.debug(f"{scheme} 节点缺少服务器地址: {node_url}")
        return False
    if port is None or not isinstance(port, int) or not (1 <= port <= 65535):
        logger.debug(f"{scheme} 节点端口无效: {port} - {node_url}")
        return False
    if scheme == "hysteria2":
        return is_valid_hysteria2_node(node_url)
    elif scheme == "vmess":
        if not node_info.get('id'):
            logger.debug(f"VMess 节点缺少 UUID: {node_url}")
            return False
        return True
    elif scheme == "trojan":
        if not node_info.get('password'):
            logger.debug(f"Trojan 节点缺少密码: {node_url}")
            return False
        return True
    elif scheme == "ss":
        if not (node_info.get('cipher') and node_info.get('password')):
            logger.debug(f"SS 节点缺少加密方法或密码: {node_url}")
            return False
        return True
    elif scheme == "ssr":
        try:
            decoded_ssr_content = decode_base64_recursive(parsed.netloc)
            if not decoded_ssr_content:
                logger.debug(f"SSR 节点 Base64 解码失败或为空: {node_url}")
                return False
            parts = decoded_ssr_content.split(':')
            if len(parts) < 6:
                logger.debug(f"SSR 节点内部结构不完整: {node_url}")
                return False
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535):
                logger.debug(f"SSR 节点内部端口无效: {node_url}")
                return False
            password_b64_part = parts[5].split('/?')[0].split('/#')[0]
            try:
                base64.urlsafe_b64decode(password_b64_part + '==').decode('utf-8', errors='ignore')
            except (base64.binascii.Error, UnicodeDecodeError):
                logger.debug(f"SSR 节点密码 Base64 解码失败: {node_url}")
                return False
            if not all(parts[i].strip() for i in [2, 3, 4]):
                logger.debug(f"SSR 节点协议、加密方法或混淆为空: {node_url}")
                return False
            return True
        except Exception as e:
            logger.debug(f"SSR 节点解析异常: {e} - {node_url}")
            return False
    elif scheme == "vless":
        if not node_info.get('id'):
            logger.debug(f"Vless 节点缺少 UUID: {node_url}")
            return False
        return True
    return True

def convert_dict_to_node_link(node_dict: Dict) -> Optional[str]:
    """将字典形式的节点数据转换为标准节点链接"""
    if not isinstance(node_dict, dict):
        return None
    node_type = node_dict.get('type', '').lower()
    server = node_dict.get('server') or node_dict.get('add')
    port = node_dict.get('port')
    password = node_dict.get('password')
    uuid = node_dict.get('uuid') or node_dict.get('id')
    name = node_dict.get('name') or node_dict.get('ps', '')
    try:
        port = int(port) if port is not None else None
        if port and not (1 <= port <= 65535):
            logger.debug(f"无效端口号: {port} for node {name}")
            return None
    except (ValueError, TypeError):
        logger.debug(f"端口号非整数: {port} for node {name}")
        return None
    if not server:
        return None
    if node_type == 'vmess':
        if not (uuid and port):
            return None
        vmess_obj = {
            "v": node_dict.get('v', '2'),
            "ps": name,
            "add": server,
            "port": port,
            "id": uuid,
            "aid": int(node_dict.get('alterId', node_dict.get('aid', 0))),
            "net": node_dict.get('network', node_dict.get('net', 'tcp')),
            "type": node_dict.get('type', 'none'),
            "host": node_dict.get('udp', node_dict.get('host', '')),
            "path": node_dict.get('path', ''),
            "tls": "tls" if node_dict.get('tls') else "none",
            "sni": node_dict.get('servername', node_dict.get('sni', '')),
            "scy": node_dict.get('cipher', ''),
            "fp": node_dict.get('fingerprint', '')
        }
        vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]}
        try:
            sorted_vmess = dict(sorted(vmess_obj.items()))
            b64_encoded = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f"vmess://{b64_encoded.replace('\n', '').replace('\r', '')}"
        except Exception as e:
            logger.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}")
            return None
    elif node_type in ['vless', 'trojan']:
        auth = uuid if node_type == 'vless' else password
        if not (auth and port):
            return None
        link = f"{node_type}://{auth}@{server}:{port}"
        params = {}
        if node_dict.get('security') or node_dict.get('tls'):
            params['security'] = node_dict.get('security', 'tls')
        for key in ['flow', 'network', 'path', 'host', 'servername', 'alpn', 'fingerprint']:
            if node_dict.get(key):
                params[key if key != 'servername' else 'sni'] = node_dict[key]
        if name:
            params['remarks'] = name
        params = {k: v for k, v in params.items() if v}
        if params:
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'ss':
        if not (password and node_dict.get('cipher') and port):
            return None
        method_pwd = f"{node_dict['cipher']}:{password}"
        encoded = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')
        link = f"ss://{encoded}@{server}:{port}"
        if name:
            link += f"#{name}"
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'ssr':
        if not all(k in node_dict for k in ['server', 'port', 'protocol', 'method', 'obfs', 'password']):
            logger.debug(f"SSR 节点缺少关键字段: {node_dict}")
            return None
        ssr_password_b64 = base64.urlsafe_b64encode(node_dict['password'].encode()).decode().rstrip('=')
        core_parts = [
            str(server),
            str(port),
            node_dict.get('protocol', 'origin'),
            node_dict.get('method', 'none'),
            node_dict.get('obfs', 'plain'),
            ssr_password_b64
        ]
        ssr_link_base = ":".join(core_parts)
        params = {}
        if node_dict.get('obfsparam'):
            params['obfsparam'] = base64.urlsafe_b64encode(node_dict['obfsparam'].encode()).decode().rstrip('=')
        if node_dict.get('protoparam'):
            params['protoparam'] = base64.urlsafe_b64encode(node_dict['protoparam'].encode()).decode().rstrip('=')
        query_string = urlencode(sorted(params.items()), doseq=True)
        if query_string:
            ssr_link_base += f"/?{query_string}"
        encoded_full_ssr = base64.urlsafe_b64encode(ssr_link_base.encode()).decode().rstrip('=')
        final_link = f"ssr://{encoded_full_ssr}"
        if name:
            final_link += f"#{name}"
        return final_link.replace('\n', '').replace('\r', '')
    elif node_type == 'hysteria2':
        auth = uuid or password
        if not (auth and port):
            return None
        link = f"hysteria2://{auth}@{server}:{port}"
        params = {}
        if node_dict.get('insecure') is not None:
            params['insecure'] = int(bool(node_dict['insecure']))
        for key in ['obfs', 'obfs-password', 'sni', 'up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open']:
            if node_dict.get(key):
                params[key.replace('_', '-')] = node_dict[key]
        params = {k: v for k, v in params.items() if v}
        if params:
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        if name:
            link += f"#{urlparse(name).path.replace(' ', '%20')}"
        return link.replace('\n', '').replace('\r', '')
    return None

def parse_node_url_to_info(node_url: str) -> Optional[Dict]:
    """解析节点 URL，提取关键信息"""
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        node_info = {"protocol": scheme, "original_url": node_url}
        if scheme == "vmess":
            decoded = decode_base64_recursive(parsed.netloc)
            if decoded:
                vmess_obj = json.loads(decoded)
                node_info.update(vmess_obj)
                node_info["server"] = vmess_obj.get("add")
                node_info["port"] = vmess_obj.get("port")
                node_info["name"] = vmess_obj.get("ps", "")
        elif scheme in ["vless", "trojan", "ss", "ssr", "hysteria2"]:
            netloc_parts = parsed.netloc.split('@', 1)
            if len(netloc_parts) == 2:
                auth_info, addr_port_str = netloc_parts
            else:
                auth_info = ""
                addr_port_str = netloc_parts[0] if netloc_parts else ""
            if ':' in addr_port_str:
                server, port_str = addr_port_str.rsplit(':', 1)
                node_info["server"] = server
                node_info["port"] = int(port_str) if port_str.isdigit() else None
            else:
                node_info["server"] = addr_port_str
                node_info["port"] = None
            if parsed.fragment:
                node_info["name"] = unquote(parsed.fragment)
            else:
                node_info["name"] = node_info.get("server", "")
            if scheme == "ss":
                try:
                    decoded_auth = base64.b64decode(auth_info).decode('utf-8', errors='ignore')
                    if ':' in decoded_auth:
                        cipher, password = decoded_auth.split(':', 1)
                        node_info["cipher"] = cipher
                        node_info["password"] = password
                except Exception as e:
                    logger.debug(f"解码 SS 认证信息失败: {e}")
            elif scheme == "hysteria2":
                node_info["auth_str"] = auth_info
            elif scheme == "ssr":
                try:
                    decoded_ssr_content = decode_base64_recursive(parsed.netloc)
                    if decoded_ssr_content:
                        parts = decoded_ssr_content.split(':')
                        if len(parts) >= 6:
                            node_info["server"] = parts[0]
                            node_info["port"] = int(parts[1]) if parts[1].isdigit() else None
                            node_info["protocol"] = parts[2]
                            node_info["method"] = parts[3]
                            node_info["obfs"] = parts[4]
                            try:
                                password_b64 = parts[5].split('/?')[0].split('/#')[0]
                                node_info["password"] = base64.urlsafe_b64decode(password_b64 + '==').decode('utf-8', errors='ignore')
                            except Exception as e:
                                logger.debug(f"SSR 密码解码失败: {e}")
                        if '/?' in decoded_ssr_content:
                            query_str = decoded_ssr_content.split('/?', 1)[1].split('/#')[0]
                            query_params = parse_qs(query_str)
                            if 'obfsparam' in query_params and query_params['obfsparam']:
                                node_info['obfsparam'] = base64.urlsafe_b64decode(query_params['obfsparam'][0] + '==').decode('utf-8', errors='ignore')
                            if 'protoparam' in query_params and query_params['protoparam']:
                                node_info['protoparam'] = base64.urlsafe_b64decode(query_params['protoparam'][0] + '==').decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug(f"SSR 内部解析失败: {e}")
            elif scheme == "vless":
                node_info["id"] = auth_info
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for k, v in query_params.items():
                if v: node_info[k] = v[0]
        return node_info
    except Exception as e:
        logger.debug(f"解析节点URL失败: {node_url}, 错误: {e}")
        return None

def update_node_remark(node_url: str, new_remark: str) -> str:
    """更新节点 URL 中的备注字段"""
    parsed = urlparse(node_url)
    scheme = parsed.scheme.lower()
    if scheme == "vmess":
        try:
            b64_content = parsed.netloc
            decoded = decode_base64_recursive(b64_content)
            if decoded:
                vmess_json = json.loads(decoded)
                vmess_json['ps'] = new_remark
                sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}"
        except Exception as e:
            logger.debug(f"更新 VMess 备注失败: {e}")
            return node_url
    elif scheme in ["vless", "trojan", "ss", "ssr", "hysteria2"]:
        new_parsed = parsed._replace(fragment=new_remark)
        return new_parsed.geturl().replace('\n', '').replace('\r', '')
    return node_url

_geoip_reader = None

def initialize_geoip_reader(geoip_db_path: str) -> Optional[geoip2.database.Reader]:
    """初始化 GeoIP Reader 并验证数据库"""
    try:
        reader = geoip2.database.Reader(geoip_db_path)
        reader.country('8.8.8.8')
        logger.info(f"GeoIP 数据库加载成功: {geoip_db_path}")
        return reader
    except Exception as e:
        logger.error(f"GeoIP 数据库初始化失败: {e}")
        return None

@lru_cache(maxsize=None)
def get_country_code_from_ip(ip: str, geoip_db_path: str) -> str:
    """从 IP 地址获取国家代码，带缓存"""
    global _geoip_reader
    if not _geoip_reader:
        _geoip_reader = initialize_geoip_reader(geoip_db_path)
    if not _geoip_reader:
        return "ERR"
    try:
        response = _geoip_reader.country(ip)
        return response.country.iso_code or "UNKNOWN"
    except geoip2.errors.AddressNotFoundError:
        return "UNKNOWN"
    except Exception as e:
        logger.debug(f"查询 GeoIP 失败 {ip}: {e}")
        return "ERR"

async def check_and_update_geoip_db(config: CrawlerConfig) -> None:
    """检查并更新 GeoIP 数据库"""
    db_path = config.geoip.get('database_path')
    max_age_days = config.geoip.get('max_age_days', 30)
    license_key = config.geoip.get('license_key', None)
    if not os.path.exists(db_path):
        logger.error(f"GeoIP 数据库不存在: {db_path}")
        return
    last_modified = datetime.fromtimestamp(os.path.getmtime(db_path))
    if datetime.now() - last_modified > timedelta(days=max_age_days):
        logger.warning(f"GeoIP 数据库已过期 (最后修改: {last_modified})")
        if license_key:
            logger.info("尝试下载最新的 GeoLite2-Country.mmdb")
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
                    async with session.get(url) as response:
                        response.raise_for_status()
                        # 这里需要额外实现解压和保存逻辑
                        logger.info(f"成功下载 GeoIP 数据库到 {db_path}")
            except Exception as e:
                logger.error(f"更新 GeoIP 数据库失败: {e}")

async def rename_and_deduplicate_by_geo(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """根据地理位置重命名和去重节点，基于核心字段"""
    if not config.geoip.get('enable_geo_rename', False):
        logger.info("GeoIP 命名和去重功能未启用。")
        return nodes
    geoip_db_path = config.geoip.get('database_path')
    if not os.path.exists(geoip_db_path):
        logger.error(f"GeoIP 数据库文件 '{geoip_db_path}' 不存在，无法进行地理位置命名。")
        return nodes
    logger.info(f"开始 GeoIP 命名和去重，使用数据库: {geoip_db_path}")
    node_details = []
    ip_lookup_tasks = []
    for node_url in nodes:
        info = parse_node_url_to_info(node_url)
        if info and info.get('server'):
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country']})
            ip_lookup_tasks.append(resolve_hostname_async(info['server']))
        else:
            logger.debug(f"无法解析节点服务器信息: {node_url}")
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country']})
    logger.info(f"开始并发解析 {len(ip_lookup_tasks)} 个域名/IP。")
    resolved_ips = await asyncio.gather(*ip_lookup_tasks, return_exceptions=True)
    for i, ip_result in enumerate(resolved_ips):
        if not isinstance(ip_result, Exception) and ip_result:
            node_details[i]['ip'] = ip_result
        else:
            logger.debug(f"解析 {node_details[i]['info'].get('server', 'N/A')} 失败: {ip_result}")
    loop = asyncio.get_running_loop()
    geoip_tasks = []
    for detail in node_details:
        if detail['ip']:
            geoip_tasks.append(loop.run_in_executor(None, get_country_code_from_ip, detail['ip'], geoip_db_path))
        else:
            geoip_tasks.append(asyncio.sleep(0, result=config.geoip['default_country']))
    logger.info(f"开始并发查询 {len(geoip_tasks)} 个IP的地理位置。")
    country_codes = await asyncio.gather(*geoip_tasks)
    for i, country_code in enumerate(country_codes):
        node_details[i]['country'] = country_code
        logger.debug(f"节点 {node_details[i]['original_url'][:50]}... IP: {node_details[i]['ip']} -> 国家: {country_code}")
    grouped_nodes: Dict[str, List[Dict]] = defaultdict(list)
    seen_unique_identifiers = set()
    for detail in node_details:
        info = detail['info']
        if not info:
            continue
        protocol = info.get('protocol', '')
        server = detail['ip'] or info.get('server', '')
        port = str(info.get('port', ''))
        auth_id = ''
        if protocol == 'vmess' or protocol == 'vless':
            auth_id = info.get('id', '')
        elif protocol == 'trojan':
            auth_id = info.get('password', '')
        elif protocol == 'ss':
            auth_id = f"{info.get('cipher', '')}:{info.get('password', '')}"
        elif protocol == 'ssr':
            auth_id = f"{info.get('method', '')}:{info.get('protocol', '')}:{info.get('obfs', '')}:{info.get('password', '')}"
        elif protocol == 'hysteria2':
            auth_id = info.get('auth_str', info.get('password', ''))
        unique_key = f"{protocol}:{server}:{port}:{auth_id}"
        unique_identifier = hashlib.sha256(unique_key.encode('utf-8')).hexdigest()
        detail['unique_identifier'] = unique_identifier
        grouped_nodes[detail['country']].append(detail)
    final_renamed_nodes = set()
    for country_code, details_list in sorted(grouped_nodes.items()):
        details_list.sort(key=lambda x: hashlib.sha256(x['original_url'].encode()).hexdigest())
        counter = 0
        for detail in details_list:
            if detail['unique_identifier'] not in seen_unique_identifiers:
                counter += 1
                new_remark = f"{country_code}_{counter:02d}"
                updated_node_url = update_node_remark(detail['original_url'], new_remark)
                final_renamed_nodes.add(updated_node_url)
                seen_unique_identifiers.add(detail['unique_identifier'])
            else:
                logger.debug(f"发现功能性重复节点，跳过: {detail['original_url']}")
    logger.info(f"GeoIP 命名和去重完成，得到 {len(final_renamed_nodes)} 个唯一节点。")
    return final_renamed_nodes

def extract_nodes_from_json(parsed_json: Dict | List) -> List[str]:
    """从 JSON 数据中提取节点链接"""
    nodes = set()
    if isinstance(parsed_json, dict):
        if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list):
            for proxy in parsed_json['proxies']:
                if isinstance(proxy, dict):
                    node = convert_dict_to_node_link(proxy)
                    if node and is_valid_node(node):
                        nodes.add(node)
        for value in parsed_json.values():
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value))
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_json(value))
    elif isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item))
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_json(item))
    return list(nodes)

def extract_nodes_from_yaml(parsed_yaml: Dict | List) -> List[str]:
    """从 YAML 数据中提取节点链接"""
    nodes = set()
    if isinstance(parsed_yaml, dict):
        if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
            for proxy in parsed_yaml['proxies']:
                if isinstance(proxy, dict):
                    node = convert_dict_to_node_link(proxy)
                    if node and is_valid_node(node):
                        nodes.add(node)
        for value in parsed_yaml.values():
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value))
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_yaml(value))
    elif isinstance(parsed_yaml, list):
        for item in parsed_yaml:
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item))
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_yaml(item))
    return list(nodes)

def extract_nodes_from_html(html_content: str, base_url: str) -> Tuple[List[str], List[str]]:
    """从 HTML 内容中提取节点链接和潜在订阅 URL"""
    soup = BeautifulSoup(html_content, 'html.parser')
    nodes = set()
    new_urls = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        absolute_href = urljoin(base_url, href)
        standardized = standardize_node_url(unquote(absolute_href))
        if is_valid_node(standardized):
            nodes.add(standardized)
        else:
            if (absolute_href.startswith(('http://', 'https://')) and
                not absolute_href.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico')) and
                not absolute_href.startswith('mailto:') and
                (absolute_href.endswith(('.txt', '.yaml', '.yml', '.json')) or
                 'sub' in absolute_href.lower() or 'subscribe' in absolute_href.lower() or
                 'clash' in absolute_href.lower() or 'singbox' in absolute_href.lower() or
                 'v2ray' in absolute_href.lower() or 'trojan' in absolute_href.lower() or
                 'ss' in absolute_href.lower() or 'ssr' in absolute_href.lower() or
                 'hysteria' in absolute_href.lower())):
                new_urls.add(absolute_href)
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        text = tag.get_text().strip()
        if text:
            nodes.update(extract_and_validate_nodes(text))
            decoded = decode_base64_recursive(text)
            if decoded and decoded != text:
                nodes.update(extract_and_validate_nodes(decoded))
    for script in soup.find_all('script'):
        script_content = script.string
        if script_content:
            if script_content.strip().startswith(('{', '[')):
                try:
                    js_data = json.loads(script_content)
                    nodes.update(extract_nodes_from_json(js_data))
                except json.JSONDecodeError:
                    pass
            for b64 in BASE64_REGEX.findall(script_content):
                if len(b64) > 30 and '=' in b64:
                    decoded = decode_base64_recursive(b64)
                    if decoded and decoded != b64:
                        nodes.update(extract_and_validate_nodes(decoded))
    return list(nodes), list(new_urls)

def parse_content(content: str, base_url: str, content_type: str) -> Tuple[List[str], List[str]]:
    """智能解析内容，提取节点和潜在订阅 URL"""
    nodes = set()
    new_urls = set()
    if "json" in content_type or content.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(content)
            logger.info("内容被识别为 JSON 格式。")
            nodes.update(extract_nodes_from_json(parsed))
            nodes.update(extract_and_validate_nodes(content))
            return list(nodes), list(new_urls)
        except json.JSONDecodeError:
            logger.debug("内容尝试 JSON 解析失败。")
    if "yaml" in content_type or content.strip().startswith(("---", "- ", "proxies:", "outbounds:")):
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']):
                logger.info("内容被识别为 YAML 格式。")
                nodes.update(extract_nodes_from_yaml(parsed))
                nodes.update(extract_and_validate_nodes(content))
                return list(nodes), list(new_urls)
        except yaml.YAMLError:
            logger.debug("内容尝试 YAML 解析失败。")
    if "html" in content_type or any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html>']):
        logger.info("内容被识别为 HTML 格式。")
        html_nodes, html_urls = extract_nodes_from_html(content, base_url)
        nodes.update(html_nodes)
        new_urls.update(html_urls)
        nodes.update(extract_and_validate_nodes(content))
        return list(nodes), list(new_urls)
    logger.info("内容尝试纯文本/Base64 嗅探。")
    decoded = decode_base64_recursive(content)
    content_to_scan = decoded if decoded and decoded != content else content
    if decoded and decoded != content:
        logger.info("内容被识别为 Base64 编码，已递归解码。")
    try:
        parsed = json.loads(content_to_scan)
        nodes.update(extract_nodes_from_json(parsed))
    except json.JSONDecodeError:
        pass
    try:
        parsed = yaml.safe_load(content_to_scan)
        if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']):
            nodes.update(extract_nodes_from_yaml(parsed))
    except yaml.YAMLError:
        pass
    nodes.update(extract_and_validate_nodes(content_to_scan))
    return list(nodes), list(new_urls)

def extract_and_validate_nodes(content: str) -> List[str]:
    """提取并验证节点 URL"""
    if not content:
        return []
    nodes = set()
    for name, pattern in NODE_PATTERNS.items():
        for match in pattern.findall(content):
            normalized = standardize_node_url(unquote(match).strip())
            if is_valid_node(normalized):
                nodes.add(normalized)
    return list(nodes)

async def save_node_counts_to_csv(file_path: str, counts_data: Dict) -> None:
    """保存节点统计到 CSV 文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
            fieldnames = ['URL', 'Status', 'Extracted Nodes Count', 'New URLs Found Count', 'Last Updated']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            await f.write(','.join(writer.fieldnames) + '\n')
            for url, data in counts_data.items():
                await f.write(f"{url},{data.get('status', 'N/A')},{data.get('extracted_nodes_count', 0)},{data.get('new_urls_found_count', 0)},{data.get('last_updated_timestamp', 'N/A')}\n")
        logger.info(f"节点统计信息已保存到 {file_path}。")
    except Exception as e:
        logger.error(f"保存节点统计信息失败 '{file_path}': {e}。", exc_info=True)

def sanitize_filename(url: str) -> str:
    """从 URL 创建安全的文件名"""
    parsed = urlparse(url)
    prefix = parsed.hostname or "link"
    if parsed.path:
        path = parsed.path.strip('/').replace('/', '_')
        if path:
            prefix += f"_{path}"
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    max_prefix_len = 50
    if len(prefix) > max_prefix_len:
        prefix = prefix[:max_prefix_len] + "_"
    safe_prefix = "".join(c for c in prefix if c.isalnum() or c in ('_', '-')).strip()
    if not safe_prefix:
        safe_prefix = "url"
    return f"{safe_prefix}_{url_hash[:10]}.txt"

def is_same_domain(base_url: str, target_url: str) -> bool:
    """判断是否为同一主域名"""
    try:
        base_parsed = urlparse(base_url)
        target_parsed = urlparse(target_url)
        base_netloc = base_parsed.netloc
        target_netloc = target_parsed.netloc
        if not base_netloc or not target_netloc:
            return False
        base_domain = base_netloc.split(':')[0]
        target_domain = target_netloc.split(':')[0]
        if target_domain == base_domain:
            return True
        if target_domain.endswith(f".{base_domain}") or base_domain.endswith(f".{target_domain}"):
            return True
        return False
    except Exception as e:
        logger.debug(f"判断同域名失败: {base_url} vs {target_url} - {e}")
        return False

async def crawl_website(start_url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, 
                        url_cache: Dict, config: CrawlerConfig, current_overall_depth: int) -> Tuple[List[str], List[str]]:
    """爬行网站，发现内部链接和节点"""
    logger.info(f"开始爬行网站: {start_url} (网站内部最大深度: {config.max_crawl_depth_per_site})")
    base_domain_parsed = urlparse(start_url)
    base_domain = f"{base_domain_parsed.scheme}://{base_domain_parsed.netloc}"
    site_nodes = set()
    site_new_subscription_urls = set()
    site_queue = deque([(start_url, 0)])
    visited_pages_in_site = {start_url}
    while site_queue:
        current_page_url, current_site_crawl_depth = site_queue.popleft()
        if current_site_crawl_depth > config.max_crawl_depth_per_site:
            logger.debug(f"达到网站内部最大爬行深度，跳过: {current_page_url}")
            continue
        logger.info(f"  爬行网站页面: {current_page_url} (内部深度: {current_site_crawl_depth})")
        status, extracted_nodes, potential_new_urls = await process_url(
            current_page_url, client, semaphore, url_cache, config, current_overall_depth
        )
        site_nodes.update(extracted_nodes)
        if status.startswith("FETCH_FAILED") or status == "FETCH_SUCCESS_NO_CONTENT":
            logger.warning(f"  页面 {current_page_url} 获取或解析失败，跳过内部链接发现。")
            continue
        for new_url in potential_new_urls:
            if is_same_domain(base_domain, new_url):
                if new_url not in visited_pages_in_site:
                    visited_pages_in_site.add(new_url)
                    site_queue.append((new_url, current_site_crawl_depth + 1))
                    logger.debug(f"    发现内部链接，加入队列: {new_url}")
            else:
                site_new_subscription_urls.add(new_url)
                logger.debug(f"    发现外部订阅链接: {new_url}")
    logger.info(f"网站 {start_url} 爬行完成。发现节点数: {len(site_nodes)}, 新订阅URL数: {len(site_new_subscription_urls)}。")
    return list(site_nodes), list(site_new_subscription_urls)

async def process_url(url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, 
                     url_cache: Dict, config: CrawlerConfig, depth: int) -> Tuple[str, List[str], List[str]]:
    """处理单个 URL"""
    async with semaphore:
        logger.info(f"正在处理 URL: {url} (深度: {depth})。")
        cache_data = url_cache.get(url, {})
        content, cache_meta, status = await fetch_content(url, client, config, cache_data)
        if cache_meta:
            url_cache[url] = {**cache_data, **cache_meta}
        if status == "SKIPPED_UNCHANGED":
            nodes = cache_data.get('extracted_nodes', [])
            new_urls = cache_data.get('new_urls_found', [])
            logger.info(f"{url} 内容未变更，使用缓存数据。提取节点数: {len(nodes)}, 发现新URL数: {len(new_urls)}。")
            return status, nodes, new_urls
        elif status.startswith("FETCH_FAILED"):
            return status, [], []
        elif content is None:
            logger.error(f"{url} 内容抓取成功但返回内容为 None。")
            return "FETCH_SUCCESS_NO_CONTENT", [], []
        content_type = cache_meta.get('content_type', 'unknown') if cache_meta else 'unknown'
        nodes, new_urls = parse_content(content, url, content_type)
        url_cache[url].update({
            'extracted_nodes': nodes,
            'new_urls_found': new_urls,
            'parse_status': "PARSE_SUCCESS",
            'last_updated_timestamp': cache_meta.get('last_updated_timestamp', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        })
        if nodes:
            filename = os.path.join(config.data_dir, sanitize_filename(url))
            try:
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                async with aiofiles.open(filename, mode='w', encoding='utf-8') as f:
                    for node in nodes:
                        await f.write(f"{node}\n")
                logger.info(f"已将 {len(nodes)} 个节点保存到文件: {filename}。")
            except Exception as e:
                logger.error(f"保存节点到文件失败 ({filename}): {e}。", exc_info=True)
        return "PROCESSED_SUCCESS", nodes, new_urls

async def test_and_filter_nodes(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """测试节点活跃度（模拟框架）"""
    if not config.node_test.get('enable', False):
        logger.info("节点活跃度测试未启用，跳过。")
        return nodes
    logger.info(f"开始测试 {len(nodes)} 个节点，并发数: {config.node_test.get('concurrency', 10)}。")
    tested_good_nodes = set()
    semaphore = asyncio.Semaphore(config.node_test.get('concurrency', 10))
    async def _test_single_node(node: str) -> Optional[str]:
        async with semaphore:
            try:
                await asyncio.sleep(0.1)  # 模拟测试时间
                if random.random() > 0.1:  # 模拟90%成功率
                    return node
                else:
                    logger.debug(f"节点 {node[:30]}... 测试失败。")
                    return None
            except Exception as e:
                logger.debug(f"节点 {node[:30]}... 测试过程中出现错误: {e}")
                return None
    tasks = [_test_single_node(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    for result in results:
        if result:
            tested_good_nodes.add(result)
    logger.info(f"节点活跃度测试完成，发现 {len(tested_good_nodes)} 个可用节点。")
    return tested_good_nodes

async def save_nodes_as_clash_config(file_path: str, nodes: Set[str]) -> None:
    """保存节点为 Clash 配置"""
    clash_proxies = []
    for node_url in nodes:
        node_info = parse_node_url_to_info(node_url)
        if not node_info:
            continue
        proxy = {
            "name": node_info.get("name", f"{node_info['protocol']}-{node_info.get('server', 'unknown')}"),
            "type": node_info["protocol"],
            "server": node_info.get("server"),
            "port": node_info.get("port"),
        }
        if node_info["protocol"] == "vmess":
            proxy.update({
                "uuid": node_info.get("id"),
                "alterId": int(node_info.get("aid", 0)),
                "cipher": node_info.get("cipher", "auto"),
                "tls": bool(node_info.get("tls")),
                "network": node_info.get("network", "tcp"),
                "ws-path": node_info.get("path", ""),
                "ws-headers": {"Host": node_info.get("host", "")} if node_info.get("host") else {},
            })
        elif node_info["protocol"] == "vless":
            proxy.update({
                "uuid": node_info.get("id"),
                "flow": node_info.get("flow", ""),
                "tls": bool(node_info.get("tls")),
                "network": node_info.get("network", "tcp"),
                "sni": node_info.get("sni", ""),
            })
        elif node_info["protocol"] == "trojan":
            proxy.update({
                "password": node_info.get("password"),
                "sni": node_info.get("sni", ""),
                "tls": True,
            })
        elif node_info["protocol"] == "ss":
            proxy.update({
                "cipher": node_info.get("cipher"),
                "password": node_info.get("password"),
            })
        elif node_info["protocol"] == "ssr":
            proxy.update({
                "cipher": node_info.get("method"),
                "password": node_info.get("password"),
                "obfs": node_info.get("obfs"),
                "protocol": node_info.get("protocol"),
                "obfs-param": node_info.get("obfsparam", ""),
                "protocol-param": node_info.get("protoparam", ""),
            })
        elif node_info["protocol"] == "hysteria2":
            proxy.update({
                "password": node_info.get("auth_str", node_info.get("password", "")),
                "obfs": node_info.get("obfs", ""),
                "obfs-password": node_info.get("obfs-password", ""),
                "sni": node_info.get("sni", ""),
                "up": node_info.get("up", ""),
                "down": node_info.get("down", ""),
            })
        clash_proxies.append({k: v for k, v in proxy.items() if v is not None})
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "Proxy", "type": "select", "proxies": [p["name"] for p in clash_proxies]},
            {"name": "DIRECT", "type": "direct"},
        ],
        "rules": ["MATCH,Proxy"],
    }
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
            await f.write(yaml.dump(clash_config, indent=2, allow_unicode=True, sort_keys=False))
        logger.info(f"已将 Clash 配置保存到 {file_path}。")
    except Exception as e:
        logger.error(f"保存 Clash 配置失败: {e}。", exc_info=True)

async def debug_duplicate_nodes(nodes: Set[str]) -> None:
    """调试重复节点"""
    node_info_list = [parse_node_url_to_info(node) for node in nodes]
    unique_keys = {}
    duplicates = []
    for node, info in zip(nodes, node_info_list):
        if not info:
            continue
        protocol = info.get('protocol', '')
        server = info.get('server', '')
        port = str(info.get('port', ''))
        auth_id = ''
        if protocol == 'vmess' or protocol == 'vless':
            auth_id = info.get('id', '')
        elif protocol == 'trojan':
            auth_id = info.get('password', '')
        elif protocol == 'ss':
            auth_id = f"{info.get('cipher', '')}:{info.get('password', '')}"
        elif protocol == 'ssr':
            auth_id = f"{info.get('method', '')}:{info.get('protocol', '')}:{info.get('obfs', '')}:{info.get('password', '')}"
        elif protocol == 'hysteria2':
            auth_id = info.get('auth_str', info.get('password', ''))
        key = (protocol, server, port, auth_id)
        if key in unique_keys:
            duplicates.append((node, unique_keys[key]))
        else:
            unique_keys[key] = node
    if duplicates:
        logger.info(f"发现 {len(duplicates)} 个重复节点：")
        for dup_node, orig_node in duplicates[:10]:
            logger.info(f"重复: {dup_node} 与 {orig_node}")
    else:
        logger.info("未发现重复节点。")

async def main():
    """主函数"""
    start_time = time.time()
    config = await load_config("config.yaml")
    if config.geoip.get('enable_geo_rename', False):
        await check_and_update_geoip_db(config)
    sources_urls = await read_sources(config.sources_file)
    if not sources_urls:
        logger.error("无有效源 URL，退出程序。")
        return
    url_cache = await load_cache(config.cache_file)
    url_summary = defaultdict(int)
    url_details = {}
    processed_count = 0
    unique_nodes = set()
    async with httpx.AsyncClient(timeout=config.request_timeout, verify=False) as client:
        semaphore = asyncio.Semaphore(config.concurrent_requests_limit)
        main_queue = deque([(url, 0) for url in sources_urls])
        urls_in_main_queue = set(sources_urls)
        while main_queue:
            current_url, current_overall_depth = main_queue.popleft()
            if current_url in url_details and url_details[current_url].get('status') not in ["FETCH_FAILED_UNEXPECTED_ERROR", "UNEXPECTED_MAIN_ERROR"]:
                logger.debug(f"URL {current_url} 已处理或在处理中，跳过。")
                continue
            processed_count += 1
            logger.info(f"正在处理第 {processed_count} 个URL (总队列中): {current_url} (总深度: {current_overall_depth})。")
            try:
                parsed_url = urlparse(current_url)
                is_website = (not parsed_url.path.split('/')[-1].count('.') or 
                              parsed_url.path.endswith('/') or 
                              any(ext in parsed_url.path.lower() for ext in ['.html', '.htm', '.php', '.asp', '.aspx']))
                if is_website and current_overall_depth < config.max_recursion_depth:
                    site_nodes, site_new_subscription_urls = await crawl_website(
                        current_url, client, semaphore, url_cache, config, current_overall_depth
                    )
                    unique_nodes.update(site_nodes)
                    if current_overall_depth + 1 <= config.max_recursion_depth:
                        for new_sub_url in site_new_subscription_urls:
                            if new_sub_url not in urls_in_main_queue and new_sub_url not in url_details:
                                main_queue.append((new_sub_url, current_overall_depth + 1))
                                urls_in_main_queue.add(new_sub_url)
                                logger.info(f"    发现新的订阅URL，加入主队列: {new_sub_url} (总深度: {current_overall_depth + 1})")
                    url_details[current_url] = {
                        'status': "WEBSITE_CRAWLED_SUCCESS",
                        'extracted_nodes_count': len(site_nodes),
                        'new_urls_found_count': len(site_new_subscription_urls),
                        'last_updated_timestamp': url_cache.get(current_url, {}).get('last_updated_timestamp', 'N/A')
                    }
                    url_summary["WEBSITE_CRAWLED_SUCCESS"] += 1
                else:
                    status, nodes, new_urls = await process_url(current_url, client, semaphore, url_cache, config, current_overall_depth)
                    unique_nodes.update(nodes)
                    url_details[current_url] = {
                        'status': status,
                        'extracted_nodes_count': len(nodes),
                        'new_urls_found_count': len(new_urls),
                        'last_updated_timestamp': url_cache.get(current_url, {}).get('last_updated_timestamp', 'N/A')
                    }
                    url_summary[status] += 1
                    if current_overall_depth + 1 <= config.max_recursion_depth:
                        for new_sub_url in new_urls:
                            if not is_same_domain(current_url, new_sub_url) and \
                               new_sub_url not in urls_in_main_queue and new_sub_url not in url_details:
                                main_queue.append((new_sub_url, current_overall_depth + 1))
                                urls_in_main_queue.add(new_sub_url)
                                logger.info(f"    发现新的订阅URL，加入主队列: {new_sub_url} (总深度: {current_overall_depth + 1})")
                if processed_count % config.cache_save_interval == 0:
                    await save_cache(config.cache_file, url_cache)
            except Exception as e:
                logger.error(f"处理URL {current_url} 时发生意外主循环异常: {e}", exc_info=True)
                url_details[current_url] = {
                    'status': "UNEXPECTED_MAIN_ERROR",
                    'extracted_nodes_count': 0,
                    'new_urls_found_count': 0,
                    'last_updated_timestamp': url_cache.get(current_url, {}).get('last_updated_timestamp', 'N/A')
                }
                url_summary["UNEXPECTED_MAIN_ERROR"] += 1
                await log_failed_url(current_url, f"主循环错误: {e}", config)
                await save_cache(config.cache_file, url_cache)
    if config.geoip.get('enable_geo_rename', False):
        unique_nodes = await rename_and_deduplicate_by_geo(unique_nodes, config)
    await debug_duplicate_nodes(unique_nodes)
    if config.node_test.get('enable', False):
        unique_nodes = await test_and_filter_nodes(unique_nodes, config)
    total_nodes_file = os.path.join(config.data_dir, "all_nodes.txt")
    try:
        os.makedirs(os.path.dirname(total_nodes_file), exist_ok=True)
        async with aiofiles.open(total_nodes_file, mode='w', encoding='utf-8') as f:
            for node in sorted(unique_nodes):
                await f.write(f"{node}\n")
        logger.info(f"已将 {len(unique_nodes)} 个唯一节点保存到 {total_nodes_file}。")
    except Exception as e:
        logger.error(f"保存总节点文件失败: {e}。", exc_info=True)
    clash_config_file = os.path.join(config.data_dir, "clash_config.yaml")
    await save_nodes_as_clash_config(clash_config_file, unique_nodes)
    await save_cache(config.cache_file, url_cache)
    await save_node_counts_to_csv(config.node_counts_file, url_details)
    end_time = time.time()
    logger.info("\n--- 处理完成报告 ---")
    logger.info(f"总计处理 {processed_count} 个 URL。")
    logger.info(f"总计提取唯一节点: {len(unique_nodes)}。")
    logger.info("状态统计:")
    for status, count in sorted(url_summary.items()):
        logger.info(f"  {status}: {count} 个。")
    logger.info(f"总耗时: {end_time - start_time:.2f} 秒。")

if __name__ == "__main__":
    asyncio.run(main())
