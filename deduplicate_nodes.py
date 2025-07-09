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
from urllib.parse import unquote, urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup
import logging
import httpx
import urllib3
import asyncio
from collections import defaultdict
from typing import List, Dict, Tuple, Set, Optional
from pathlib import Path
import configparser

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("scraper.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 忽略 InsecureRequestWarning 警告
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 加载配置文件 ---
def load_config(config_file: str = "scraper_config.ini") -> configparser.ConfigParser:
    """加载配置文件，设置默认值"""
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'DataDir': 'data',
        'SourcesFile': 'sources.list',
        'NodeOutputPrefix': 'proxy_nodes_',
        'MaxNodesPerSlice': '5000',
        'NodeCountsFile': 'node_counts.csv',
        'CacheFile': 'url_cache.json',
        'FailedUrlsFile': 'failed_urls.log',
        'ConcurrentRequestsLimit': '20',
        'RequestTimeout': '15',
        'RetryAttempts': '2',
        'CacheSaveInterval': '100',
        'MaxRecursionDepth': '2',
        'LogLevel': 'INFO'
    }
    if os.path.exists(config_file):
        config.read(config_file)
        logger.info(f"已加载配置文件: {config_file}")
    else:
        logger.warning(f"配置文件 {config_file} 不存在，使用默认配置")
    return config

CONFIG = load_config()
DATA_DIR = CONFIG['DEFAULT']['DataDir']
SOURCES_FILE = os.path.join(DATA_DIR, CONFIG['DEFAULT']['SourcesFile'])
NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, CONFIG['DEFAULT']['NodeOutputPrefix'])
MAX_NODES_PER_SLICE = int(CONFIG['DEFAULT']['MaxNodesPerSlice'])
NODE_COUNTS_FILE = os.path.join(DATA_DIR, CONFIG['DEFAULT']['NodeCountsFile'])
CACHE_FILE = os.path.join(DATA_DIR, CONFIG['DEFAULT']['CacheFile'])
FAILED_URLS_FILE = os.path.join(DATA_DIR, CONFIG['DEFAULT']['FailedUrlsFile'])
CONCURRENT_REQUESTS_LIMIT = int(CONFIG['DEFAULT']['ConcurrentRequestsLimit'])
REQUEST_TIMEOUT = int(CONFIG['DEFAULT']['RequestTimeout'])
RETRY_ATTEMPTS = int(CONFIG['DEFAULT']['RetryAttempts'])
CACHE_SAVE_INTERVAL = int(CONFIG['DEFAULT']['CacheSaveInterval'])
MAX_RECURSION_DEPTH = int(CONFIG['DEFAULT']['MaxRecursionDepth'])

# 设置日志级别
logging.getLogger().setLevel(getattr(logging, CONFIG['DEFAULT']['LogLevel'].upper(), logging.INFO))

# 确保 data 目录存在
Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

# --- 支持的节点协议正则表达式 ---
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "tuic": re.compile(r"tuic://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# Base64 正则表达式
BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}', re.IGNORECASE)

# User-Agent 池
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.56',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

# --- 辅助函数 ---

def read_sources(file_path: str) -> List[str]:
    """从 sources.list 文件读取所有 URL"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    urls.append(stripped_line)
        logger.info(f"成功读取 {len(urls)} 个源 URL")
        return urls
    except FileNotFoundError:
        logger.error(f"源文件 '{file_path}' 未找到")
        return []
    except Exception as e:
        logger.error(f"读取源文件失败: {e}")
        return []

def load_cache(cache_file: str) -> Dict:
    """加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("缓存文件损坏，将重新生成")
            return {}
    return {}

def save_cache(cache_file: str, cache_data: Dict) -> None:
    """保存 URL 缓存"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2)
        logger.debug(f"缓存已保存到 {cache_file}")
    except IOError as e:
        logger.error(f"保存缓存文件失败: {e}")

def log_failed_url(url: str, reason: str) -> None:
    """记录失败的 URL"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    try:
        with open(FAILED_URLS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {url}: {reason}\n")
    except IOError as e:
        logger.error(f"写入失败 URL 日志失败: {e}")

def decode_base64_recursive(data: str, max_depth: int = 5) -> Optional[str]:
    """递归解码 Base64 字符串"""
    if not isinstance(data, str) or not data.strip() or len(data) < 20:
        return None
    current = data
    for _ in range(max_depth):
        try:
            decoded_bytes = base64.urlsafe_b64decode(current + '==')
            temp = decoded_bytes.decode('utf-8', errors='ignore')
            if not temp or temp == current or not BASE64_REGEX.fullmatch(temp.strip()):
                return temp
            current = temp
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
 prognosis           decoded_bytes = base64.b64decode(current + '==')
                temp = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp or temp == current or not BASE64_REGEX.fullmatch(temp.strip()):
                    return temp
                current = temp
            except (base64.binascii.Error, UnicodeDecodeError):
                return current
        except Exception as e:
            logger.debug(f"Base64 解码错误: {e}")
            return current
    return current

async def fetch_content(url: str, client: httpx.AsyncClient, cache_data: Dict = None) -> Tuple[Optional[str], Optional[Dict], str]:
    """异步获取 URL 内容"""
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection': 'keep-alive'
    }
    if cache_data:
        if cache_data.get('etag'):
            headers['If-None-Match'] = cache_data['etag']
        if cache_data.get('last_modified'):
            headers['If-Modified-Since'] = cache_data['last_modified']

    test_urls = [url]
    if not urlparse(url).scheme:
        test_urls = [f"https://{url}", f"http://{url}"]

    for attempt in range(RETRY_ATTEMPTS):
        for test_url in test_urls:
            try:
                response = await client.get(test_url, headers=headers, follow_redirects=True)
                content_hash = hashlib.sha256(response.content).hexdigest()
                meta = {
                    'etag': response.headers.get('ETag'),
                    'last_modified': response.headers.get('Last-Modified'),
                    'content_hash': content_hash,
                    'content_type': response.headers.get('Content-Type', '').lower(),
                    'last_updated_timestamp': time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                }
                if cache_data and cache_data.get('content_hash') == content_hash:
                    logger.info(f"{url} 内容未更改")
                    meta['last_updated_timestamp'] = cache_data.get('last_updated_timestamp', meta['last_updated_timestamp'])
                    return None, meta, "SKIPPED_UNCHANGED"
                response.raise_for_status()
                return response.text, meta, "FETCH_SUCCESS"
            except httpx.HTTPStatusError as e:
                logger.warning(f"{url} HTTP 错误 ({e.response.status_code})")
                status = f"FETCH_FAILED_HTTP_{e.response.status_code}"
            except httpx.TimeoutException:
                logger.warning(f"{url} 请求超时")
                status = "FETCH_FAILED_TIMEOUT"
            except httpx.ConnectError:
                logger.warning(f"{url} 连接错误")
                status = "FETCH_FAILED_CONNECTION_ERROR"
            except httpx.RequestError as e:
                logger.warning(f"{url} 请求失败: {e}")
                status = "FETCH_FAILED_REQUEST_ERROR"
            except Exception as e:
                logger.error(f"{url} 意外错误: {e}")
                status = "FETCH_FAILED_UNEXPECTED_ERROR"
        if attempt < RETRY_ATTEMPTS - 1:
            await asyncio.sleep(2 ** attempt + random.uniform(0.5, 1.5))
    log_failed_url(url, status)
    return None, None, status

def standardize_node_url(node_url: str) -> str:
    """标准化节点 URL"""
    if not isinstance(node_url, str):
        return ""
    node_url = node_url.replace('\n', '').replace('\r', '')
    try:
        parsed = urlparse(node_url)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
            encoded_query = urlencode(sorted_params, doseq=True)
            parsed = parsed._replace(query=encoded_query)
        if node_url.lower().startswith("vmess://"):
            b64_content = parsed.netloc
            decoded = decode_base64_recursive(b64_content)
            if decoded:
                vmess_json = json.loads(decoded)
                sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}"
        return parsed.geturl()
    except Exception as e:
        logger.debug(f"标准化 URL 失败: {e}, URL: {node_url}")
        return node_url

def is_valid_hysteria2_node(node_link: str) -> bool:
    """校验 Hysteria2 节点"""
    if not node_link.lower().startswith("hysteria2://"):
        return False
    try:
        parsed = urlparse(node_link)
        if '@' not in parsed.netloc:
            return False
        auth, addr_port = parsed.netloc.split('@', 1)
        if not auth or ':' not in addr_port:
            return False
        server, port = addr_port.rsplit(':', 1)
        return bool(server and port.isdigit() and 1 <= int(port) <= 65535)
    except ValueError:
        return False

def is_valid_tuic_node(node_link: str) -> bool:
    """校验 TUIC 节点"""
    if not node_link.lower().startswith("tuic://"):
        return False
    try:
        parsed = urlparse(node_link)
        if '@' not in parsed.netloc:
            return False
        uuid, addr_port = parsed.netloc.split('@', 1)
        if not uuid or ':' not in addr_port:
            return False
        server, port = addr_port.rsplit(':', 1)
        return bool(server and port.isdigit() and 1 <= int(port) <= 65535)
    except ValueError:
        return False

def is_valid_node(node_url: str) -> bool:
    """校验节点有效性"""
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False
    if not any(node_url.lower().startswith(f"{proto}://") for proto in NODE_PATTERNS):
        return False
    parsed = urlparse(node_url)
    if parsed.scheme.lower() == "hysteria2":
        return is_valid_hysteria2_node(node_url)
    if parsed.scheme.lower() == "tuic":
        return is_valid_tuic_node(node_url)
    if parsed.scheme not in ["ss", "ssr", "vmess"]:
        if not parsed.hostname or (parsed.port and not (1 <= parsed.port <= 65535)):
            return False
    elif parsed.scheme == "vmess":
        try:
            decoded = decode_base64_recursive(parsed.netloc)
            if not decoded:
                return False
            vmess = json.loads(decoded)
            return 'add' in vmess and 'port' in vmess and 'id' in vmess and 1 <= int(vmess['port']) <= 65535
        except Exception:
            return False
    return True

def convert_dict_to_node_link(node_dict: Dict) -> Optional[str]:
    """将字典转换为节点链接"""
    if not isinstance(node_dict, dict):
        return None
    node_type = node_dict.get('type', '').lower()
    server = node_dict.get('server') or node_dict.get('add')
    port = node_dict.get('port')
    password = node_dict.get('password')
    uuid = node_dict.get('uuid') or node_dict.get('id')
    name = node_dict.get('name') or node_dict.get('ps', '')
    try:
        port = int(port) if port else None
        if port and not (1 <= port <= 65535):
            return None
    except (ValueError, TypeError):
        return None
    if not (server and port):
        return None

    if node_type == 'vmess':
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
            b64 = base64.b64encode(json.dumps(dict(sorted(vmess_obj.items())), separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f"vmess://{b64.replace('\n', '').replace('\r', '')}"
        except Exception as e:
            logger.debug(f"转换 VMess 失败: {e}")
            return None
    elif node_type == 'vless':
        if not uuid:
            return None
        link = f"vless://{uuid}@{server}:{port}"
        params = {k: v for k, v in {
            'security': node_dict.get('security', 'tls' if node_dict.get('tls') else None),
            'flow': node_dict.get('flow'),
            'type': node_dict.get('network'),
            'path': node_dict.get('path'),
            'host': node_dict.get('host'),
            'sni': node_dict.get('servername'),
            'alpn': node_dict.get('alpn'),
            'pbk': node_dict.get('publicKey'),
            'sid': node_dict.get('shortId'),
            'fp': node_dict.get('fingerprint'),
            'serviceName': node_dict.get('serviceName'),
            'mode': node_dict.get('mode'),
            'remarks': name
        }.items() if v}
        if params:
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'trojan':
        if not password:
            return None
        link = f"trojan://{password}@{server}:{port}"
        params = {k: v for k, v in {
            'security': node_dict.get('security', 'tls' if node_dict.get('tls') else None),
            'type': node_dict.get('network'),
            'path': node_dict.get('path'),
            'host': node_dict.get('host'),
            'sni': node_dict.get('servername'),
            'alpn': node_dict.get('alpn'),
            'fp': node_dict.get('fingerprint'),
            'flow': node_dict.get('flow'),
            'remarks': name
        }.items() if v}
        if params:
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'ss':
        if not password or not node_dict.get('cipher'):
            return None
        method_pwd = f"{node_dict['cipher']}:{password}"
        encoded = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')
        link = f"ss://{encoded}@{server}:{port}"
        if name:
            link += f"#{name}"
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'hysteria2':
        auth = uuid or password
        if not auth:
            return None
        link = f"hysteria2://{auth}@{server}:{port}"
        params = {k: v for k, v in {
            'insecure': int(bool(node_dict.get('insecure'))) if node_dict.get('insecure') is not None else None,
            'obfs': node_dict.get('obfs'),
            'obfs-password': node_dict.get('obfs-password'),
            'sni': node_dict.get('sni'),
            'up': node_dict.get('up'),
            'down': node_dict.get('down'),
            'auth-str': node_dict.get('auth_str'),
            'alpn': node_dict.get('alpn'),
            'peer': node_dict.get('peer'),
            'fast-open': node_dict.get('fast_open'),
            'ca': node_dict.get('ca'),
            'recv-window-conn': node_dict.get('recv_window_conn'),
            'recv-window-client': node_dict.get('recv_window_client'),
            'disable-mtu-discovery': node_dict.get('disable_mtu_discovery')
        }.items() if v is not None}
        if params:
            link += f"?{urlencode(sorted(params.items()), doseq=True)}"
        if name:
            link += f"#{urlparse(name).path.replace(' ', '%20')}"
        return link.replace('\n', '').replace('\r', '')
    elif node_type == 'tuic':
        if not uuid:
            return None
        link = f"tuic://{uuid}@{server}:{port}"
        params = {k: v for k, v in {
            'congestion_control': node_dict.get('congestion_control', 'bbr'),
            'udp_relay_mode': node_dict.get('udp_relay_mode', 'native'),
            'zero_rtt_handshake': node_dict.get('zero_rtt_handshake', '0'),
            'auth_timeout': node_dict.get('auth_timeout'),
            'sni': node_dict.get('sni'),
            'alpn': node_dict.get('alpn'),
            'remarks': name
        }.items() if v is not None}
        if params:
            link += f"?{urlencode(sorted(params.items()), doseq=True)}"
        return link.replace('\n', '').replace('\r', '')
    return None

def extract_nodes_from_json(parsed_json: Dict | List) -> List[str]:
    """从 JSON 数据提取节点"""
    nodes = set()
    if isinstance(parsed_json, dict):
        if 'proxies' in parsed_json:
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
    """从 YAML 数据提取节点"""
    nodes = set()
    if isinstance(parsed_yaml, dict):
        if 'proxies' in parsed_yaml:
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
    """从 HTML 提取节点和订阅 URL"""
    soup = BeautifulSoup(html_content, 'html.parser')
    nodes = set()
    sub_urls = set()
    for a_tag in soup.find_all('a', href=True):
        href = urljoin(base_url, a_tag['href'].strip())
        standardized = standardize_node_url(unquote(href))
        if is_valid_node(standardized):
            nodes.add(standardized)
        elif (href.startswith(('http://', 'https://')) and
              not href.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico')) and
              not href.startswith('mailto:') and
              any(kw in href.lower() for kw in ['sub', 'subscribe', 'clash', 'singbox', 'v2ray', 'trojan', 'ss', 'ssr', 'hysteria', 'tuic'])):
            sub_urls.add(href)
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        text = tag.get_text().strip()
        if text:
            nodes.update(extract_and_validate_nodes(text))
            decoded = decode_base64_recursive(text)
            if decoded and decoded != text:
                nodes.update(extract_and_validate_nodes(decoded))
    for script in soup.find_all('script'):
        if script.string:
            if script.string.strip().startswith(('{', '[')):
                try:
                    js_data = json.loads(script.string)
                    nodes.update(extract_nodes_from_json(js_data))
                except json.JSONDecodeError:
                    pass
            for b64 in BASE64_REGEX.findall(script.string):
                if len(b64) > 30 and '=' in b64:
                    decoded = decode_base64_recursive(b64)
                    if decoded and decoded != b64:
                        nodes.update(extract_and_validate_nodes(decoded))
    return list(nodes), list(sub_urls)

def parse_content(content: str, base_url: str, content_type: str) -> Tuple[List[str], List[str]]:
    """解析内容提取节点和订阅 URL"""
    nodes = set()
    sub_urls = set()
    if "json" in content_type or content.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(content)
            logger.info("内容识别为 JSON")
            nodes.update(extract_nodes_from_json(parsed))
            nodes.update(extract_and_validate_nodes(content))
            return list(nodes), list(sub_urls)
        except json.JSONDecodeError:
            pass
    if "yaml" in content_type or content.strip().startswith(("---", "- ", "proxies:", "outbounds:")):
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict) and any(k in parsed for k in ['proxies', 'proxy-groups', 'outbounds']):
                logger.info("内容识别为 YAML")
                nodes.update(extract_nodes_from_yaml(parsed))
                nodes.update(extract_and_validate_nodes(content))
                return list(nodes), list(sub_urls)
        except yaml.YAMLError:
            pass
    if "html" in content_type or any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html>']):
        logger.info("内容识别为 HTML")
        html_nodes, html_urls = extract_nodes_from_html(content, base_url)
        nodes.update(html_nodes)
        sub_urls.update(html_urls)
        nodes.update(extract_and_validate_nodes(content))
        return list(nodes), list(sub_urls)
    logger.info("内容尝试纯文本/Base64 解析")
    decoded = decode_base64_recursive(content)
    content_to_scan = decoded if decoded and decoded != content else content
    if decoded and decoded != content:
        logger.info("内容已解码为 Base64")
        try:
            parsed_json = json.loads(content_to_scan)
            nodes.update(extract_nodes_from_json(parsed_json))
        except json.JSONDecodeError:
            pass
        try:
            parsed_yaml = yaml.safe_load(content_to_scan)
            if isinstance(parsed_yaml, dict) and any(k in parsed_yaml for k in ['proxies', 'proxy-groups', 'outbounds']):
                nodes.update(extract_nodes_from_yaml(parsed_yaml))
        except yaml.YAMLError:
            pass
    nodes.update(extract_and_validate_nodes(content_to_scan))
    return list(nodes), list(sub_urls)

def extract_and_validate_nodes(content: str) -> List[str]:
    """提取并验证节点 URL"""
    if not content:
        return []
    nodes = set()
    for proto, pattern in NODE_PATTERNS.items():
        for match in pattern.findall(content):
            normalized = standardize_node_url(unquote(match).strip())
            if is_valid_node(normalized):
                nodes.add(normalized)
    return list(nodes)

def load_existing_nodes_from_slices(directory: str, prefix: str) -> Set[str]:
    """加载现有节点"""
    nodes = set()
    for filename in os.listdir(directory):
        if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'):
            try:
                with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
                    for line in f:
                        node = line.strip().split(' = ', 1)[-1].strip()
                        nodes.add(standardize_node_url(node))
            except Exception as e:
                logger.warning(f"加载节点文件失败 ({filename}): {e}")
    logger.info(f"加载 {len(nodes)} 个现有节点")
    return nodes

def save_nodes_to_sliced_files(output_prefix: str, nodes: List[str], max_per_slice: int) -> None:
    """保存节点到切片文件"""
    nodes = sorted(nodes)
    num_slices = (len(nodes) + max_per_slice - 1) // max_per_slice
    for filename in os.listdir(DATA_DIR):
        if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'):
            try:
                os.remove(os.path.join(DATA_DIR, filename))
                logger.info(f"删除旧切片文件: {filename}")
            except OSError as e:
                logger.warning(f"删除旧切片文件失败 ({filename}): {e}")
    for i in range(num_slices):
        slice_nodes = nodes[i * max_per_slice:(i + 1) * max_per_slice]
        file_path = f"{output_prefix}{i+1:03d}.txt"
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for node in slice_nodes:
                    f.write(f"{node.replace('\n', '').replace('\r', '')}\n")
            logger.info(f"保存切片文件: {file_path} ({len(slice_nodes)} 个节点)")
        except IOError as e:
            logger.error(f"保存切片文件失败 ({file_path}): {e}")

def save_node_counts_to_csv(file_path: str, counts_data: Dict) -> None:
    """保存节点统计到 CSV"""
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source URL", "Node Count", "Processing Status", "Last Updated UTC"])
            for url, data in sorted(counts_data.items()):
                writer.writerow([url, data['count'], data['status'], data.get('last_updated_timestamp', 'N/A')])
        logger.info(f"节点统计已保存到 {file_path}")
    except IOError as e:
        logger.error(f"保存节点统计失败: {e}")

async def process_single_url(url: str, depth: int, cache: Dict, client: httpx.AsyncClient) -> Tuple[str, int, Dict, List[str], str, List[str]]:
    """处理单个 URL"""
    logger.info(f"处理 URL: {url} (深度: {depth})")
    cache_data = cache.get(url, {})
    content, meta, status = await fetch_content(url, client, cache_data)
    nodes, sub_urls = [], []
    if meta:
        if status == "FETCH_SUCCESS":
            nodes, sub_urls = parse_content(content, url, meta.get('content_type', 'unknown'))
            meta['node_count'] = len(nodes)
            meta['status'] = "PARSE_SUCCESS" if nodes else "PARSE_NO_NODES"
            logger.info(f"{url} 提取 {len(nodes)} 个节点, {len(sub_urls)} 个新 URL")
        else:
            meta['node_count'] = cache_data.get('node_count', 0)
            meta['status'] = status
    else:
        meta = {
            'node_count': 0,
            'status': status,
            'content_hash': None,
            'etag': None,
            'last_modified': None,
            'content_type': 'unknown',
            'last_updated_timestamp': cache_data.get('last_updated_timestamp', 'N/A')
        }
    return url, meta['node_count'], meta, nodes, meta['status'], sub_urls

async def main():
    start_time = time.time()
    logger.info("脚本开始运行")
    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        logger.error("无源 URL，退出")
        return
    url_cache = load_cache(CACHE_FILE)
    if os.path.exists(FAILED_URLS_FILE):
        try:
            os.remove(FAILED_URLS_FILE)
            logger.info(f"清空旧失败日志: {FAILED_URLS_FILE}")
        except OSError as e:
            logger.warning(f"清空失败日志失败: {e}")
    existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX)
    all_nodes = set(existing_nodes)
    url_info = {}
    url_summary = defaultdict(int)
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS_LIMIT)
    queue = asyncio.Queue()
    visited = set()

    for url in source_urls:
        if url not in visited:
            await queue.put((url, 0))
            visited.add(url)

    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT, http2=True) as client:
        processed = 0
        while not queue.empty():
            async with semaphore:
                url, depth = await queue.get()
                if url in url_info:
                    continue
                try:
                    result = await process_single_url(url, depth, url_cache, client)
                    url, count, meta, nodes, status, new_urls = result
                    url_cache[url] = meta
                    url_info[url] = {'count': count, 'status': status, 'last_updated_timestamp': meta.get('last_updated_timestamp', 'N/A')}
                    url_summary[status] += 1
                    all_nodes.update(nodes)
                    if depth < MAX_RECURSION_DEPTH:
                        for new_url in new_urls:
                            if new_url not in visited:
                                await queue.put((new_url, depth + 1))
                                visited.add(new_url)
                                logger.info(f"发现新 URL: {new_url} (深度: {depth + 1})")
                    processed += 1
                    if processed % CACHE_SAVE_INTERVAL == 0:
                        save_cache(CACHE_FILE, url_cache)
                except Exception as e:
                    logger.error(f"处理 {url} 出错: {e}")
                    url_cache[url] = {
                        'node_count': url_cache.get(url, {}).get('node_count', 0),
                        'status': "UNEXPECTED_MAIN_ERROR",
                        'content_hash': url_cache.get(url, {}).get('content_hash'),
                        'etag': url_cache.get(url, {}).get('etag'),
                        'last_modified': url_cache.get(url, {}).get('last_modified'),
                        'content_type': url_cache.get(url, {}).get('content_type', 'unknown'),
                        'last_updated_timestamp': url_cache.get(url, {}).get('last_updated_timestamp', 'N/A')
                    }
                    url_info[url] = {
                        'count': url_cache[url]['node_count'],
                        'status': "UNEXPECTED_MAIN_ERROR",
                        'last_updated_timestamp': url_cache[url]['last_updated_timestamp']
                    }
                    url_summary["UNEXPECTED_MAIN_ERROR"] += 1
                    log_failed_url(url, f"主循环异常: {e}")
                    save_cache(CACHE_FILE, url_cache)

    save_cache(CACHE_FILE, url_cache)
    save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, list(all_nodes), MAX_NODES_PER_SLICE)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_info)

    logger.info(f"\n处理完成: {processed} 个 URL")
    for status, count in sorted(url_summary.items()):
        logger.info(f"{status}: {count}")
    logger.info(f"总节点数: {len(all_nodes)}")
    logger.info(f"总耗时: {time.time() - start_time:.2f} 秒")
    if any(status.startswith(("FETCH_FAILED", "UNEXPECTED_", "PARSE_NO_NODES")) for status in url_summary):
        logger.info(f"查看失败详情: {FAILED_URLS_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
