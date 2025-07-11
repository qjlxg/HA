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
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
import aiofiles

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

# 忽略 SSL 警告
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 数据类定义 ---
@dataclass
class CrawlerConfig:
    """爬虫配置类"""
    data_dir: str = "data"
    sources_file: str = "sources.list"
    node_counts_file: str = os.path.join("data", "node_counts.csv")
    cache_file: str = os.path.join("data", "url_cache.json")
    failed_urls_file: str = os.path.join("data", "failed_urls.log")
    concurrent_requests_limit: int = 20
    request_timeout: float = 20.0
    retry_attempts: int = 3
    cache_save_interval: int = 50
    max_recursion_depth: int = 2
    proxies: Optional[Dict] = None
    user_agents: List[str] = field(default_factory=list) # 使用field和default_factory确保可变默认值正确初始化

    # 新增节点测试配置 (示例，实际逻辑需要额外实现)
    node_test: Dict = field(default_factory=dict)

    def __post_init__(self):
        # 确保目录存在
        os.makedirs(self.data_dir, exist_ok=True)
        # 确保路径基于data_dir
        self.node_counts_file = os.path.join(self.data_dir, os.path.basename(self.node_counts_file))
        self.cache_file = os.path.join(self.data_dir, os.path.basename(self.cache_file))
        self.failed_urls_file = os.path.join(self.data_dir, os.path.basename(self.failed_urls_file))

        if not self.user_agents:
            self.user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
            ]

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
        logger.info(f"成功读取 {len(urls)} 个源 URL。") # [cite: 1]
        return urls
    except FileNotFoundError:
        logger.error(f"源文件 '{file_path}' 未找到。") # [cite: 6]
        return []
    except Exception as e:
        logger.error(f"读取源文件失败: {e}。") # [cite: 6]
        return []

async def load_cache(cache_file: str) -> Dict:
    """异步加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            async with aiofiles.open(cache_file, mode='r', encoding='utf-8') as f:
                content = await f.read() # [cite: 7]
            return json.loads(content) # [cite: 7]
        except json.JSONDecodeError:
            logger.warning("缓存文件损坏，将重新生成。") # [cite: 7]
            return {}
        except Exception as e:
            logger.error(f"加载缓存失败: {e}。") # [cite: 7]
            return {}
    return {} # [cite: 8]

async def save_cache(cache_file: str, cache_data: Dict) -> None:
    """异步保存 URL 缓存"""
    try:
        async with aiofiles.open(cache_file, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(cache_data, indent=4, ensure_ascii=False))
    except Exception as e:
        logger.error(f"保存缓存失败: {e}。")

# 修正：传递 config 对象
async def log_failed_url(url: str, reason: str, config: CrawlerConfig) -> None:
    """异步记录失败的 URL"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        # 修正：使用 config.failed_urls_file
        async with aiofiles.open(config.failed_urls_file, mode='a', encoding='utf-8') as f: # [cite: 8, 9]
            await f.write(f"[{timestamp}] {url}: {reason}\n") # [cite: 9]
    except Exception as e:
        logger.error(f"记录失败 URL 失败: {e}。") # [cite: 9]

def decode_base64_recursive(data: str) -> Optional[str]:
    """递归解码 Base64 字符串"""
    if not isinstance(data, str) or not data.strip() or len(data) < 20:
        return None

    current_decoded = data
    for _ in range(5):
        try:
            decoded_bytes = base64.urlsafe_b64decode(current_decoded + '==') # [cite: 10]
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore') # [cite: 10]
            if not temp_decoded or temp_decoded == current_decoded:
                break
            if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                current_decoded = temp_decoded # [cite: 11]
                break
            current_decoded = temp_decoded # [cite: 11]
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
                decoded_bytes = base64.b64decode(current_decoded + '==') # [cite: 11]
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore') # [cite: 11]
                if not temp_decoded or temp_decoded == current_decoded:
                    break # [cite: 12]
                if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                    current_decoded = temp_decoded # [cite: 12]
                    break
                current_decoded = temp_decoded # [cite: 12]
            except (base64.binascii.Error, UnicodeDecodeError): # [cite: 13]
                break
        except Exception as e:
            logger.debug(f"Base64 解码错误: {e}") # [cite: 13]
            break
    return current_decoded # [cite: 13]

async def fetch_content(url: str, client: httpx.AsyncClient, config: CrawlerConfig, cache_data: Dict = None) -> Tuple[Optional[str], Optional[Dict], str]:
    """异步获取 URL 内容"""
    headers = {
        'User-Agent': random.choice(config.user_agents), # [cite: 14]
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', # [cite: 14]
        'Accept-Encoding': 'gzip, deflate, br', # [cite: 14]
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', # [cite: 14]
        'DNT': '1', # [cite: 14]
        'Connection': 'keep-alive' # [cite: 14]
    }

    if cache_data:
        if 'etag' in cache_data:
            headers['If-None-Match'] = cache_data['etag'] # [cite: 14]
        if 'last_modified' in cache_data:
            headers['If-Modified-Since'] = cache_data['last_modified'] # [cite: 15]

    test_urls = []
    parsed = urlparse(url)
    if not parsed.scheme:
        test_urls.extend([f"https://{url}", f"http://{url}"])
    else:
        test_urls.append(url)

    for attempt in range(config.retry_attempts):
        for test_url in test_urls:
            try:
                response = await client.get(test_url, headers=headers, follow_redirects=True) # [cite: 16]
                new_etag = response.headers.get('ETag') # [cite: 16]
                new_last_modified = response.headers.get('Last-Modified') # [cite: 16]
                content_type = response.headers.get('Content-Type', '').lower() # [cite: 16]
                content_hash = hashlib.sha256(response.content).hexdigest() # [cite: 16]

                if cache_data and cache_data.get('content_hash') == content_hash:
                    logger.info(f"{url} 内容未变更，跳过解析。") # [cite: 17]
                    return None, {
                        'etag': new_etag, # [cite: 17]
                        'last_modified': new_last_modified, # [cite: 17]
                        'content_hash': content_hash, # [cite: 18]
                        'content_type': content_type, # [cite: 18]
                        'last_updated_timestamp': cache_data.get('last_updated_timestamp', 'N/A') # [cite: 18]
                    }, "SKIPPED_UNCHANGED"

                response.raise_for_status() # [cite: 19]
                current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC") # [cite: 19]
                return response.text, {
                    'etag': new_etag, # [cite: 19]
                    'last_modified': new_last_modified, # [cite: 19]
                    'content_hash': content_hash, # [cite: 20]
                    'content_type': content_type, # [cite: 20]
                    'last_updated_timestamp': current_time # [cite: 20]
                }, "FETCH_SUCCESS"

            except httpx.TimeoutException:
                logger.warning(f"{url} 请求超时 (尝试 {attempt + 1}/{config.retry_attempts})。") # [cite: 20]
                status = "FETCH_FAILED_TIMEOUT" # [cite: 21]
            except httpx.HTTPStatusError as e:
                logger.warning(f"{url} HTTP 错误 {e.response.status_code} (尝试 {attempt + 1}/{config.retry_attempts})。") # [cite: 21]
                status = f"FETCH_FAILED_HTTP_{e.response.status_code}" # [cite: 21]
            except httpx.ConnectError as e:
                logger.warning(f"{url} 连接错误: {e} (尝试 {attempt + 1}/{config.retry_attempts})。") # [cite: 22]
                status = "FETCH_FAILED_CONNECTION_ERROR" # [cite: 22]
            except Exception as e:
                logger.error(f"{url} 未知错误: {e} (尝试 {attempt + 1}/{config.retry_attempts})。") # [cite: 22]
                status = "FETCH_FAILED_UNEXPECTED_ERROR" # [cite: 22]

        if attempt < config.retry_attempts - 1:
            await asyncio.sleep(2 ** attempt + random.uniform(0.5, 1.5)) # [cite: 23]

    logger.error(f"{url} 所有尝试失败。") # [cite: 23]
    # 修正：传递 config 对象
    await log_failed_url(url, status, config) # [cite: 23]
    return None, None, status

def standardize_node_url(node_url: str) -> str:
    """标准化节点 URL"""
    if not isinstance(node_url, str):
        return ""

    try:
        parsed = urlparse(node_url) # [cite: 23]
    except ValueError as e:
        logger.warning(f"无效 URL 格式: {e} - {node_url}") # [cite: 23]
        return node_url.replace('\n', '').replace('\r', '')

    if parsed.query:
        query_params = parse_qs(parsed.query, keep_blank_values=True) # [cite: 24]
        sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values]) # [cite: 24]
        encoded_query = urlencode(sorted_params, doseq=True) # [cite: 24]
        parsed = parsed._replace(query=encoded_query) # [cite: 24]

    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = parsed.netloc # [cite: 24]
            decoded = decode_base64_recursive(b64_content) # [cite: 25]
            if decoded:
                vmess_json = json.loads(decoded) # [cite: 25]
                sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0]))) # [cite: 25]
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8') # [cite: 25]
                return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}" # [cite: 25]
        except Exception as e:
            logger.debug(f"标准化 VMess 失败: {e}") # [cite: 26]
            return node_url.replace('\n', '').replace('\r', '')

    return parsed.geturl().replace('\n', '').replace('\r', '') # [cite: 26]

def is_valid_hysteria2_node(node_link: str) -> bool:
    """验证 Hysteria2 节点有效性"""
    if not node_link.lower().startswith("hysteria2://"): # [cite: 26]
        return False
    try:
        parsed = urlparse(node_link) # [cite: 27]
        netloc = parsed.netloc # [cite: 27]
        if '@' not in netloc:
            return False # [cite: 27]
        auth_info, addr_port = netloc.split('@', 1) # [cite: 27]
        if not auth_info.strip():
            return False
        if ':' not in addr_port:
            return False
        server, port = addr_port.rsplit(':', 1) # [cite: 27]
        if not server or not port.isdigit() or not (1 <= int(port) <= 65535): # [cite: 28]
            return False
        return True # [cite: 28]
    except ValueError: # [cite: 28]
        return False

def is_valid_node(node_url: str) -> bool:
    """验证节点 URL 有效性"""
    if not isinstance(node_url, str) or len(node_url) < 10: # [cite: 28]
        return False

    if not any(node_url.lower().startswith(f"{proto}://") for proto in NODE_PATTERNS): # [cite: 28]
        return False

    parsed = urlparse(node_url) # [cite: 29]
    if parsed.scheme.lower() == "hysteria2":
        return is_valid_hysteria2_node(node_url) # [cite: 29]

    if parsed.scheme not in ["ss", "ssr", "vmess"]:
        if not parsed.hostname or (parsed.port and not (1 <= parsed.port <= 65535)): # [cite: 29]
            return False
    elif parsed.scheme == "vmess":
        try:
            decoded = decode_base64_recursive(parsed.netloc) # [cite: 29]
            if not decoded:
                return False # [cite: 30]
            vmess_obj = json.loads(decoded) # [cite: 30]
            if not all(key in vmess_obj for key in ['add', 'port', 'id']): # [cite: 30]
                return False
            if not (1 <= int(vmess_obj['port']) <= 65535): # [cite: 30]
                return False
        except Exception: # [cite: 31]
            return False

    return True # [cite: 31]

def convert_dict_to_node_link(node_dict: Dict) -> Optional[str]:
    """将字典转换为节点链接"""
    if not isinstance(node_dict, dict): # [cite: 31]
        return None

    node_type = node_dict.get('type', '').lower() # [cite: 32]
    server = node_dict.get('server') or node_dict.get('add') # [cite: 32]
    port = node_dict.get('port') # [cite: 32]
    password = node_dict.get('password') # [cite: 32]
    uuid = node_dict.get('uuid') or node_dict.get('id') # [cite: 32]
    name = node_dict.get('name') or node_dict.get('ps', '') # [cite: 32]

    try:
        port = int(port) if port else None # [cite: 32]
        if port and not (1 <= port <= 65535):
            return None # [cite: 32]
    except (ValueError, TypeError):
        return None # [cite: 33]

    if not (server and port): # [cite: 33]
        return None

    if node_type == 'vmess':
        vmess_obj = {
            "v": node_dict.get('v', '2'), # [cite: 33]
            "ps": name, # [cite: 33]
            "add": server, # [cite: 33]
            "port": port, # [cite: 33]
            "id": uuid, # [cite: 33]
            "aid": int(node_dict.get('alterId', node_dict.get('aid', 0))), # [cite: 33]
            "net": node_dict.get('network', node_dict.get('net', 'tcp')), # [cite: 33]
            "type": node_dict.get('type', 'none'), # [cite: 33]
            "host": node_dict.get('udp', node_dict.get('host', '')), # [cite: 34]
            "path": node_dict.get('path', ''), # [cite: 34]
            "tls": "tls" if node_dict.get('tls') else "none", # [cite: 34]
            "sni": node_dict.get('servername', node_dict.get('sni', '')), # [cite: 34]
            "scy": node_dict.get('cipher', ''), # [cite: 34]
            "fp": node_dict.get('fingerprint', '') # [cite: 34]
        }
        vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]} # [cite: 35]
        try:
            sorted_vmess = dict(sorted(vmess_obj.items())) # [cite: 35]
            b64_encoded = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8') # [cite: 35]
            return f"vmess://{b64_encoded.replace('\n', '').replace('\r', '')}" # [cite: 35]
        except Exception as e:
            logger.debug(f"转换 VMess 失败: {e}") # [cite: 36]
            return None

    elif node_type in ['vless', 'trojan']:
        auth = uuid if node_type == 'vless' else password # [cite: 36]
        if not auth: # [cite: 36]
            return None
        link = f"{node_type}://{auth}@{server}:{port}" # [cite: 36]
        params = {}
        if node_dict.get('security') or node_dict.get('tls'):
            params['security'] = node_dict.get('security', 'tls') # [cite: 37]
        for key in ['flow', 'network', 'path', 'host', 'servername', 'alpn', 'fingerprint']:
            if node_dict.get(key):
                params[key if key != 'servername' else 'sni'] = node_dict[key] # [cite: 37]
        if name:
            params['remarks'] = name # [cite: 37]
        params = {k: v for k, v in params.items() if v} # [cite: 37]
        if params: # [cite: 38]
            link += "?" + urlencode(sorted(params.items()), doseq=True) # [cite: 39]
        return link.replace('\n', '').replace('\r', '') # [cite: 39]

    elif node_type == 'ss':
        if not (password and node_dict.get('cipher')): # [cite: 39]
            return None
        method_pwd = f"{node_dict['cipher']}:{password}" # [cite: 39]
        encoded = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8') # [cite: 39]
        link = f"ss://{encoded}@{server}:{port}" # [cite: 39]
        if name:
            link += f"#{name}" # [cite: 40]
        return link.replace('\n', '').replace('\r', '') # [cite: 40]

    elif node_type == 'hysteria2':
        auth = uuid or password # [cite: 40]
        if not auth: # [cite: 40]
            return None
        link = f"hysteria2://{auth}@{server}:{port}" # [cite: 40]
        params = {}
        if node_dict.get('insecure') is not None:
            params['insecure'] = int(bool(node_dict['insecure'])) # [cite: 40]
        for key in ['obfs', 'obfs-password', 'sni', 'up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open']:
            if node_dict.get(key):
                params[key.replace('_', '-')] = node_dict[key] # [cite: 41]
        params = {k: v for k, v in params.items() if v} # [cite: 41]
        if params: # [cite: 41]
            link += "?" + urlencode(sorted(params.items()), doseq=True) # [cite: 42]
        if name:
            link += f"#{urlparse(name).path.replace(' ', '%20')}" # [cite: 42]
        return link.replace('\n', '').replace('\r', '') # [cite: 42]

    return None

def extract_nodes_from_json(parsed_json: Dict | List) -> List[str]:
    """从 JSON 数据提取节点"""
    nodes = set() # [cite: 42]
    if isinstance(parsed_json, dict):
        if 'proxies' in parsed_json:
            for proxy in parsed_json['proxies']: # [cite: 42]
                if isinstance(proxy, dict): # 
                    node = convert_dict_to_node_link(proxy) # 
                    # 修正：is_valid_node16node -> is_valid_node
                    if node and is_valid_node(node): # 
                        nodes.add(node)
        for value in parsed_json.values(): # 
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value)) # [cite: 44]
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_json(value)) # [cite: 44]
    elif isinstance(parsed_json, list):
        for item in parsed_json: # [cite: 44]
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item)) # [cite: 45]
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_json(item)) # [cite: 45]
    return list(nodes)

def extract_nodes_from_yaml(parsed_yaml: Dict | List) -> List[str]: # [cite: 46]
    """从 YAML 数据提取节点"""
    nodes = set() # [cite: 46]
    if isinstance(parsed_yaml, dict):
        if 'proxies' in parsed_yaml:
            for proxy in parsed_yaml['proxies']: # [cite: 46]
                if isinstance(proxy, dict): # [cite: 47]
                    node = convert_dict_to_node_link(proxy) # [cite: 47]
                    if node and is_valid_node(node): # [cite: 47]
                        nodes.add(node)
        for value in parsed_yaml.values(): # [cite: 47]
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value)) # [cite: 47]
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_yaml(value)) # [cite: 48]
    elif isinstance(parsed_yaml, list):
        for item in parsed_yaml: # [cite: 48]
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item)) # [cite: 48]
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_yaml(item)) # [cite: 48]
    return list(nodes)

def extract_nodes_from_html(html_content: str, base_url: str) -> Tuple[List[str], List[str]]: # [cite: 49]
    """从 HTML 提取节点和潜在订阅 URL"""
    soup = BeautifulSoup(html_content, 'html.parser') # [cite: 49]
    nodes = set() # [cite: 49]
    new_urls = set() # [cite: 49]

    for a_tag in soup.find_all('a', href=True): # [cite: 49]
        href = urljoin(base_url, a_tag['href'].strip()) # [cite: 49]
        standardized = standardize_node_url(unquote(href)) # [cite: 49]
        if is_valid_node(standardized): # [cite: 49]
            nodes.add(standardized) # [cite: 49]
        elif (href.startswith(('http://', 'https://')) and # [cite: 49]
              not href.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico')) and # [cite: 50]
              not href.startswith('mailto:') and # [cite: 50]
              any(term in href.lower() for term in ['sub', 'subscribe', 'clash', 'singbox', 'v2ray', 'trojan', 'ss', 'ssr', 'hysteria'])): # [cite: 50]
            new_urls.add(href) # [cite: 50]

    for tag in soup.find_all(['pre', 'code', 'textarea']): # [cite: 50]
        text = tag.get_text().strip() # [cite: 51]
        if text:
            nodes.update(extract_and_validate_nodes(text)) # [cite: 51]
            decoded = decode_base64_recursive(text) # [cite: 51]
            if decoded and decoded != text:
                nodes.update(extract_and_validate_nodes(decoded)) # [cite: 51]

    for script in soup.find_all('script'): # [cite: 51]
        if script.string:
            if script.string.strip().startswith(('{', '[')): # [cite: 52]
                try:
                    js_data = json.loads(script.string) # [cite: 52]
                    nodes.update(extract_nodes_from_json(js_data)) # [cite: 52]
                except json.JSONDecodeError:
                    pass
            for b64 in BASE64_REGEX.findall(script.string): # [cite: 52]
                if len(b64) > 30 and '=' in b64: # [cite: 53]
                    decoded = decode_base64_recursive(b64) # [cite: 53]
                    if decoded and decoded != b64:
                        nodes.update(extract_and_validate_nodes(decoded)) # [cite: 53]

    return list(nodes), list(new_urls)

def parse_content(content: str, base_url: str, content_type: str) -> Tuple[List[str], List[str]]: # [cite: 54]
    """智能解析内容"""
    nodes = set() # [cite: 54]
    new_urls = set() # [cite: 54]

    if "json" in content_type or content.strip().startswith(("{", "[")): # [cite: 54]
        try:
            parsed = json.loads(content) # [cite: 54]
            logger.info("识别为 JSON 格式。") # [cite: 54]
            nodes.update(extract_nodes_from_json(parsed)) # [cite: 54]
            nodes.update(extract_and_validate_nodes(content)) # [cite: 54]
            return list(nodes), list(new_urls)
        except json.JSONDecodeError: # [cite: 55]
            logger.debug("JSON 解析失败。") # [cite: 55]

    if "yaml" in content_type or content.strip().startswith(("---", "- ", "proxies:", "outbounds:")): # [cite: 55]
        try:
            parsed = yaml.safe_load(content) # [cite: 55]
            if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']): # [cite: 55]
                logger.info("识别为 YAML 格式。") # [cite: 56]
                nodes.update(extract_nodes_from_yaml(parsed)) # [cite: 56]
                nodes.update(extract_and_validate_nodes(content)) # [cite: 56]
                return list(nodes), list(new_urls)
        except yaml.YAMLError: # [cite: 56]
            logger.debug("YAML 解析失败。") # [cite: 56]

    if "html" in content_type or any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html>']): # [cite: 56]
        logger.info("识别为 HTML 格式。") # [cite: 57]
        html_nodes, html_urls = extract_nodes_from_html(content, base_url) # [cite: 57]
        nodes.update(html_nodes) # [cite: 57]
        new_urls.update(html_urls) # [cite: 57]
        nodes.update(extract_and_validate_nodes(content)) # [cite: 57]
        return list(nodes), list(new_urls)

    logger.info("尝试纯文本/Base64 解析。") # [cite: 57]
    decoded = decode_base64_recursive(content) # [cite: 57]
    content_to_scan = decoded if decoded and decoded != content else content # [cite: 57]
    if decoded and decoded != content:
        logger.info("识别为 Base64 编码。") # [cite: 57]
    try:
        parsed = json.loads(content_to_scan) # [cite: 58]
        nodes.update(extract_nodes_from_json(parsed)) # [cite: 58]
    except json.JSONDecodeError:
        pass
    try:
        parsed = yaml.safe_load(content_to_scan) # [cite: 58]
        if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']): # [cite: 58]
            nodes.update(extract_nodes_from_yaml(parsed)) # [cite: 59]
    except yaml.YAMLError:
        pass
    nodes.update(extract_and_validate_nodes(content_to_scan)) # [cite: 59]
    return list(nodes), list(new_urls)

def extract_and_validate_nodes(content: str) -> List[str]: # [cite: 59]
    """提取并验证节点 URL"""
    if not content: # [cite: 59]
        return []
    nodes = set() # [cite: 59]
    for name, pattern in NODE_PATTERNS.items(): # [cite: 59]
        for match in pattern.findall(content): # [cite: 59]
            normalized = standardize_node_url(unquote(match).strip()) # [cite: 59]
            if is_valid_node(normalized): # [cite: 59]
                nodes.add(normalized) # [cite: 60]
    return list(nodes)

async def save_node_counts_to_csv(file_path: str, counts_data: Dict) -> None: # [cite: 60]
    """异步保存节点统计到 CSV"""
    try:
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f: # [cite: 60]
            writer = csv.DictWriter(f, fieldnames=['URL', 'Status', 'Extracted Nodes Count', 'New URLs Found Count', 'Last Updated']) # [cite: 60]
            await f.write(','.join(writer.fieldnames) + '\n') # [cite: 61]
            for url, data in counts_data.items():
                await f.write(f"{url},{data.get('status', 'N/A')},{data.get('extracted_nodes_count', 0)},{data.get('new_urls_found_count', 0)},{data.get('last_updated_timestamp', 'N/A')}\n") # [cite: 61]
        logger.info(f"节点统计保存到 {file_path}。") # [cite: 61]
    except Exception as e:
        logger.error(f"保存统计失败: {e}。") # [cite: 61]

def sanitize_filename(url: str) -> str: # [cite: 62]
    """创建安全的文件名"""
    parsed = urlparse(url) # [cite: 62]
    prefix = parsed.hostname or "link" # [cite: 62]
    if parsed.path: # [cite: 62]
        path = parsed.path.strip('/').replace('/', '_') # [cite: 62]
        if path:
            prefix += f"_{path}" # [cite: 62]
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest() # [cite: 62]
    max_prefix_len = 50
    if len(prefix) > max_prefix_len: # [cite: 62]
        prefix = prefix[:max_prefix_len] # [cite: 62]
    safe_prefix = "".join(c for c in prefix if c.isalnum() or c in ('_', '-')).strip() or "url" # [cite: 62]
    return f"{safe_prefix}_{url_hash[:10]}.txt" # [cite: 62]

async def process_url(url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, 
                     url_cache: Dict, config: CrawlerConfig, depth: int) -> Tuple[str, List[str], List[str]]: # [cite: 63]
    """处理单个 URL"""
    async with semaphore: # [cite: 63]
        logger.info(f"处理 URL: {url} (深度: {depth})。") # [cite: 63]
        cache_data = url_cache.get(url, {}) # [cite: 63]
        content, cache_meta, status = await fetch_content(url, client, config, cache_data) # [cite: 63]

        if cache_meta:
            url_cache[url] = {**cache_data, **cache_meta} # [cite: 64]

        if status == "SKIPPED_UNCHANGED":
            nodes = cache_data.get('extracted_nodes', []) # [cite: 64]
            new_urls = cache_data.get('new_urls_found', []) # [cite: 64]
            logger.info(f"{url} 未变更，节点: {len(nodes)}，新 URL: {len(new_urls)}。") # [cite: 64]
            return status, nodes, new_urls
        elif status.startswith("FETCH_FAILED"): # [cite: 64]
            return status, [], []
        elif content is None: # [cite: 64]
            logger.error(f"{url} 抓取成功但无内容。") # 
            return "FETCH_SUCCESS_NO_CONTENT", [], []

        content_type = cache_meta.get('content_type', 'unknown') if cache_meta else 'unknown' # 
        nodes, new_urls = parse_content(content, url, content_type) # 
        
        # 移除冗余行 url_cache[url] = url_cache.get(url, {})
        url_cache[url].update({
            'extracted_nodes': nodes, # 
            'new_urls_found': new_urls, # [cite: 66]
            'parse_status': "PARSE_SUCCESS", # [cite: 66]
            'last_updated_timestamp': cache_meta.get('last_updated_timestamp', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")) # [cite: 66]
        })

        logger.info(f"{url} 解析完成，节点: {len(nodes)}，新 URL: {len(new_urls)}。") # [cite: 66]
        
        if nodes:
            filename = os.path.join(config.data_dir, sanitize_filename(url)) # [cite: 66]
            try:
                async with aiofiles.open(filename, mode='w', encoding='utf-8') as f: # [cite: 66]
                    for node in nodes:
                        await f.write(f"{node}\n") # [cite: 67]
                logger.info(f"保存 {len(nodes)} 个节点到 {filename}。") # [cite: 67]
            except Exception as e:
                logger.error(f"保存节点失败 {filename}: {e}。") # [cite: 67]

        return "PROCESSED_SUCCESS", nodes, new_urls

# 增强：节点活跃度测试函数 (仅框架，实际测试逻辑复杂)
async def test_and_filter_nodes(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """
    异步测试节点活跃度并进行筛选。
    这是一个框架函数，实际的测试逻辑需要根据不同的协议和测试方式进行实现。
    例如：对 HTTP/SOCKS 代理进行 CONNECT 请求，对 Vmess/Trojan 等使用特定库进行握手。
    """
    if not config.node_test.get('enable', False):
        logger.info("节点活跃度测试未启用，跳过。")
        return nodes

    logger.info(f"开始测试 {len(nodes)} 个节点，并发数: {config.node_test.get('concurrency', 10)}。")
    tested_good_nodes = set()
    semaphore = asyncio.Semaphore(config.node_test.get('concurrency', 10))

    async def _test_single_node(node: str) -> Optional[str]:
        async with semaphore:
            # 这是一个示例测试逻辑，您需要根据实际协议进行替换
            # 例如：使用 httpx 尝试通过代理访问一个测试网站
            try:
                # 假设有一个函数 parse_node_info 可以从 node_url 提取代理信息
                # proxy_info = parse_node_info(node)
                # async with httpx.AsyncClient(proxies={"all": proxy_info}, timeout=config.node_test.get('timeout', 5)) as client:
                #     resp = await client.get("http://www.google.com/generate_204")
                #     resp.raise_for_status()
                # logger.debug(f"节点 {node[:30]}... 测试成功。")
                # return node # 如果测试成功，返回节点
                
                # 暂时直接返回，表示框架
                await asyncio.sleep(0.1) # 模拟测试时间
                if random.random() > 0.1: # 模拟90%成功率
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

# 增强：保存节点为 Clash 配置 (示例框架)
async def save_nodes_as_clash_config(file_path: str, nodes: Set[str]) -> None:
    """异步将节点保存为 Clash YAML 配置格式 (仅框架，需完善)"""
    clash_proxies = []
    for node_url in nodes:
        # 这里需要根据 node_url 解析出 Clash 代理所需的字典格式
        # 例如：
        # if node_url.startswith("ss://"):
        #     proxy_dict = {"name": "ss-node-1", "type": "ss", ...}
        # elif node_url.startswith("vmess://"):
        #     proxy_dict = {"name": "vmess-node-1", "type": "vmess", ...}
        # ...
        # clash_proxies.append(proxy_dict)
        # 目前仅为示例，将节点字符串直接作为名称和类型
        if node_url.startswith("ss://"):
            clash_proxies.append({"name": f"SS-{len(clash_proxies)}", "type": "ss", "server": "example.com", "port": 443, "cipher": "aes-256-gcm", "password": "pass", "udp": True})
        elif node_url.startswith("vmess://"):
            clash_proxies.append({"name": f"VMess-{len(clash_proxies)}", "type": "vmess", "server": "example.com", "port": 443, "uuid": "uuid", "alterId": 0, "cipher": "auto", "tls": True, "network": "ws", "ws-path": "/", "ws-headers": {"Host": "example.com"}})
        # 实际上需要更复杂的解析，这里仅为示意
        else:
            clash_proxies.append({"name": f"Generic-{len(clash_proxies)}", "type": "unknown", "url": node_url})


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
            {"name": "DIRECT", "type": "direct"}
        ],
        "rules": [
            "MATCH,Proxy"
        ]
    }

    try:
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
            await f.write(yaml.dump(clash_config, indent=2, allow_unicode=True))
        logger.info(f"保存 Clash 配置到 {file_path}。")
    except Exception as e:
        logger.error(f"保存 Clash 配置失败: {e}。")


async def main():
    """主函数"""
    start_time = time.time()
    
    # 修正：从文件加载配置
    config = await load_config("config.yaml")
    
    sources_urls = await read_sources(config.sources_file)
    if not sources_urls:
        logger.error("无有效源 URL，退出。")
        return

    url_cache = await load_cache(config.cache_file)
    url_summary = defaultdict(int)
    url_details = {}
    processed_count = 0
    unique_nodes = set()

    # 修正：AsyncClient 不再接受 proxies 参数
    async with httpx.AsyncClient(timeout=config.request_timeout, verify=False) as client: # [cite: 68]
        semaphore = asyncio.Semaphore(config.concurrent_requests_limit) # [cite: 69]
        queue = deque([(url, 0) for url in sources_urls]) # [cite: 69]
        urls_in_queue = set(sources_urls) # [cite: 69]

        while queue:
            url, depth = queue.popleft() # [cite: 69]
            processed_count += 1
            logger.info(f"处理 {processed_count}/{len(urls_in_queue)}: {url} (深度: {depth})。") # [cite: 69]

            try:
                status, nodes, new_urls = await process_url(url, client, semaphore, url_cache, config, depth) # [cite: 70]
                unique_nodes.update(nodes) # [cite: 70]
                
                url_details[url] = {
                    'status': status, # [cite: 71]
                    'extracted_nodes_count': len(nodes), # [cite: 71]
                    'new_urls_found_count': len(new_urls), # [cite: 71]
                    'last_updated_timestamp': url_cache.get(url, {}).get('last_updated_timestamp', 'N/A') # [cite: 71]
                }
                url_summary[status] += 1 # [cite: 71]

                if depth < config.max_recursion_depth: # [cite: 71]
                    for new_url in new_urls: # [cite: 72]
                        if new_url not in urls_in_queue and new_url not in url_details:
                            queue.append((new_url, depth + 1)) # [cite: 72]
                            urls_in_queue.add(new_url) # [cite: 73]

                if processed_count % config.cache_save_interval == 0: # [cite: 73]
                    await save_cache(config.cache_file, url_cache) # [cite: 73]

            except Exception as e:
                logger.error(f"处理 {url} 失败: {e}", exc_info=True) # [cite: 74]
                url_details[url] = { # [cite: 74]
                    'status': "UNEXPECTED_MAIN_ERROR", # [cite: 74]
                    'last_updated_timestamp': url_cache.get(url, {}).get('last_updated_timestamp', 'N/A') # [cite: 74]
                }
                url_summary["UNEXPECTED_MAIN_ERROR"] += 1 # [cite: 74]
                # 修正：传递 config 对象
                await log_failed_url(url, f"主循环错误: {e}", config) # [cite: 75]
                await save_cache(config.cache_file, url_cache) # [cite: 75]

    # 增强：在所有节点收集完毕后进行活跃度测试
    if config.node_test.get('enable', False):
        unique_nodes = await test_and_filter_nodes(unique_nodes, config)

    # 保存所有唯一节点到一个总文件
    total_nodes_file = os.path.join(config.data_dir, "all_nodes.txt")
    try:
        async with aiofiles.open(total_nodes_file, mode='w', encoding='utf-8') as f: # [cite: 75]
            for node in sorted(unique_nodes):
                await f.write(f"{node}\n") # [cite: 76]
        logger.info(f"保存 {len(unique_nodes)} 个唯一节点到 {total_nodes_file}。") # [cite: 76]
    except Exception as e: # [cite: 76]
        logger.error(f"保存总节点文件失败: {e}。")

    # 增强：保存 Clash 配置
    clash_config_file = os.path.join(config.data_dir, "clash_config.yaml")
    await save_nodes_as_clash_config(clash_config_file, unique_nodes)


    await save_cache(config.cache_file, url_cache) # [cite: 76]
    await save_node_counts_to_csv(config.node_counts_file, url_details) # [cite: 76]

    end_time = time.time() # [cite: 76]
    logger.info("\n--- 处理完成报告 ---") #
    logger.info(f"总计处理 {processed_count} 个 URL。") #
    logger.info(f"总计提取唯一节点: {len(unique_nodes)}。") #
    logger.info("状态统计:") #
    for status, count in sorted(url_summary.items()): #
        logger.info(f"  {status}: {count} 个。") #
    logger.info(f"总耗时: {end_time - start_time:.2f} 秒。") #

if __name__ == "__main__":
    asyncio.run(main()) #
