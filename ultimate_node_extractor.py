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
from urllib.parse import unquote, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import logging
import httpx
import urllib3

# --- 日志配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 忽略 InsecureRequestWarning 警告
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 配置部分 ---
DATA_DIR = "data"
SOURCES_FILE = "sources.list"
NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, "proxy_nodes_")
MAX_NODES_PER_SLICE = 5000

NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")
FAILED_URLS_FILE = os.path.join(DATA_DIR, "failed_urls.log")

MAX_WORKERS = 25  # 并发量
REQUEST_TIMEOUT = 5  # 单次请求超时时间，单位秒
RETRY_ATTEMPTS = 1  # 请求重试次数
CACHE_SAVE_INTERVAL = 150  # 每处理 N 个 URL 保存一次缓存

# 代理配置 (已移除，设置为 None)
PROXIES = None

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义支持的节点协议正则表达式
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# 匹配 Base64 字符串的正则表达式
BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', re.IGNORECASE)

# 随机 User-Agent 池
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.56',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
]

# --- 辅助函数 ---

def read_sources(file_path: str) -> list[str]:
    """从 sources.list 文件读取所有 URL"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    urls.append(stripped_line)
        logging.info(f"成功读取 {len(urls)} 个源 URL。")
    except FileNotFoundError:
        logging.error(f"错误：源文件 '{file_path}' 未找到。请确保它位于脚本的同级目录。")
    return urls

def load_cache(cache_file: str) -> dict:
    """加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("缓存文件损坏，将重新生成。")
            return {}
    return {}

def save_cache(cache_file: str, cache_data: dict) -> None:
    """保存 URL 缓存"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=4)
    except IOError as e:
        logging.error(f"保存缓存文件失败: {e}")

def log_failed_url(url: str, reason: str) -> None:
    """将失败的URL及其原因记录到文件"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    try:
        with open(FAILED_URLS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {url}: {reason}\n")
    except IOError as e:
        logging.error(f"写入失败URL日志失败: {e}")

def decode_base64_recursive(data: str) -> str | None:
    """尝试递归解码 Base64 字符串，直到无法再解码或内容不再是 Base64。"""
    if not isinstance(data, str) or not data.strip() or len(data) < 20:
        return None

    current_decoded_str = data
    for _ in range(5):  # 最多递归5层
        try:
            decoded_bytes = base64.urlsafe_b64decode(current_decoded_str + '==')
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if not temp_decoded or temp_decoded == current_decoded_str:
                break
            current_decoded_str = temp_decoded
            if not BASE64_REGEX.fullmatch(current_decoded_str):
                break
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
                decoded_bytes = base64.b64decode(current_decoded_str + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded_str:
                    break
                current_decoded_str = temp_decoded
                if not BASE64_REGEX.fullmatch(current_decoded_str):
                    break
            except (base64.binascii.Error, UnicodeDecodeError):
                break
        except Exception as e:
            logging.debug(f"递归Base64解码中发生未知错误: {e}")
            break
    return current_decoded_str

def fetch_content(url: str, retries: int = RETRY_ATTEMPTS, cache_data: dict = None) -> tuple[str | None, dict | None, str]:
    """
    尝试通过 HTTP 或 HTTPS 获取网页内容，并包含重试机制。
    """
    current_user_agent = random.choice(USER_AGENTS)
    current_headers = {
        'User-Agent': current_user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'DNT': '1',
        'Connection': 'keep-alive'
    }

    if cache_data:
        if 'etag' in cache_data and cache_data['etag']:
            current_headers['If-None-Match'] = cache_data['etag']
        if 'last_modified' in cache_data and cache_data['last_modified']:
            current_headers['If-Modified-Since'] = cache_data['last_modified']

    test_urls = []
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        test_urls.append(f"http://{url}")
        test_urls.append(f"https://{url}")
    else:
        test_urls.append(url)

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                with httpx.Client(verify=False, timeout=REQUEST_TIMEOUT, http2=True) as client:
                    response = client.get(current_url_to_test, headers=current_headers, follow_redirects=True)
                
                if response.status_code == 304:
                    logging.info(f"  {url} 内容未修改 (304)。")
                    cached_content_hash = cache_data.get('content_hash')
                    return None, {'etag': cache_data.get('etag'), 'last_modified': cache_data.get('last_modified'), 'content_hash': cached_content_hash, 'content_type': cache_data.get('content_type')}, "SKIPPED_UNCHANGED"

                response.raise_for_status()

                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                content_type = response.headers.get('Content-Type', '').lower()
                content_hash = hashlib.sha256(response.content).hexdigest()

                if cache_data and cache_data.get('content_hash') == content_hash:
                    logging.info(f"  {url} 内容哈希未修改，跳过解析。")
                    return None, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "SKIPPED_UNCHANGED"

                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "FETCH_SUCCESS"

            except httpx.TimeoutException:
                logging.warning(f"  {url} 请求超时 (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_TIMEOUT"
            except httpx.HTTPStatusError as e:
                logging.warning(f"  {url} HTTP错误 ({e.response.status_code} {e.response.reason_phrase}) (尝试 {attempt + 1}/{retries})。")
                status_reason = f"FETCH_FAILED_HTTP_{e.response.status_code}"
            except httpx.ConnectError as e:
                logging.warning(f"  {url} 连接错误 ({e}) (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_CONNECTION_ERROR"
            except httpx.RequestError as e:
                logging.warning(f"  {url} httpx请求失败 ({e}) (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_REQUEST_ERROR"
            except Exception as e:
                logging.error(f"  {url} 意外错误: {e} (尝试 {attempt + 1}/{retries})。", exc_info=True)
                status_reason = "FETCH_FAILED_UNEXPECTED_ERROR"

        if attempt < retries - 1:
            time.sleep(2 ** attempt + 1)

    logging.error(f"  {url} 所有 {retries} 次尝试均失败。")
    log_failed_url(url, status_reason)
    return None, None, status_reason

def standardize_node_url(node_url: str) -> str:
    """
    标准化节点链接的查询参数和部分结构，以便更精确地去重。
    """
    if not isinstance(node_url, str):
        return ""

    parsed = urlparse(node_url)
    if parsed.query:
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
        encoded_query = urlencode(sorted_params, doseq=True)
        parsed = parsed._replace(query=encoded_query)

    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = parsed.netloc
            decoded_b64_content = decode_base64_recursive(b64_content)
            if decoded_b64_content:
                vmess_json = json.loads(decoded_b64_content)
                sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                return f"vmess://{normalized_b64}"
        except Exception as e:
            logging.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
            return node_url

    return parsed.geturl()

def is_valid_hysteria2_node(node_link: str) -> bool:
    """
    校验 Hysteria2 链接是否有效。
    一个有效的 Hysteria2 链接通常至少包含：
    - 协议头: hysteria2://
    - 用户信息 (UUID 或密码) 和服务器地址:port
    这里我们要求链接中必须有 `@` 符号，且 `@` 之前的部分不为空（代表 UUID/密码），
    并且有有效的服务器地址和端口。
    """
    [cite_start]if not node_link.lower().startswith("hysteria2://"): [cite: 94]
        return False
    
    try:
        parsed_url = urlparse(node_link)
    except ValueError:
        return False # 链接格式不正确

    # netloc 包含认证信息和地址:端口，例如：0c4c1a89-5645-4fc2-9e3b-ab09aa44e933@138.2.61.132:13059
    netloc = parsed_url.netloc

    # 检查是否有认证信息（UUID/密码）
    if '@' not in netloc:
        # 如果没有 @ 符号，则认为缺少认证信息，视为无效。
        return False
    
    auth_info, addr_port = netloc.split('@', 1)
    if not auth_info.strip(): # 认证信息为空
        return False

    # 检查服务器地址和端口
    if ':' not in addr_port:
        return False # 缺少端口
    
    server, port_str = addr_port.rsplit(':', 1)
    if not server or not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
        return False # 服务器地址为空或端口不是有效的数字

    return True

def is_valid_node(node_url: str) -> bool:
    """
    检查节点 URL 的基本有效性。
    """
    [cite_start]if not isinstance(node_url, str) or len(node_url) < 10: [cite: 117]
        return False

    found_protocol = False
    [cite_start]for proto in NODE_PATTERNS.keys(): [cite: 117]
        [cite_start]if node_url.lower().startswith(f"{proto}://"): [cite: 117]
            found_protocol = True
            break
    [cite_start]if not found_protocol: [cite: 117]
        return False

    [cite_start]parsed_url = urlparse(node_url) [cite: 117, 118]

    # 特殊处理 Hysteria2 链接的校验
    if parsed_url.scheme.lower() == "hysteria2":
        return is_valid_hysteria2_node(node_url)

    # 其他协议的现有校验逻辑
    [cite_start]if parsed_url.scheme not in ["ss", "ssr", "vmess"]: [cite: 117]
        [cite_start]if not parsed_url.hostname: [cite: 118]
            return False
        [cite_start]if parsed_url.port and not (1 <= parsed_url.port <= 65535): [cite: 118]
            return False
    [cite_start]elif parsed_url.scheme == "vmess": [cite: 118]
        try:
            [cite_start]b64_content = parsed_url.netloc [cite: 118]
            [cite_start]decoded = decode_base64_recursive(b64_content) [cite: 118]
            [cite_start]if not decoded: [cite: 119]
                return False
            [cite_start]vmess_obj = json.loads(decoded) [cite: 119]
            [cite_start]if not ('add' in vmess_obj and 'port' in vmess_obj and 'id' in vmess_obj): [cite: 119]
                return False
            [cite_start]if not (1 <= int(vmess_obj['port']) <= 65535): [cite: 119, 120]
                return False
        except Exception:
            return False

    return True

def convert_dict_to_node_link(node_dict: dict) -> str | None:
    """
    将字典形式的节点数据转换为标准节点链接。
    """
    [cite_start]if not isinstance(node_dict, dict): [cite: 121]
        return None

    [cite_start]node_type = node_dict.get('type', '').lower() [cite: 121]
    [cite_start]server = node_dict.get('server') or node_dict.get('add') [cite: 121]
    [cite_start]port = node_dict.get('port') [cite: 121]
    [cite_start]password = node_dict.get('password') [cite: 121]
    [cite_start]uuid = node_dict.get('uuid') or node_dict.get('id') [cite: 121]
    [cite_start]name = node_dict.get('name') or node_dict.get('ps', '') [cite: 121]

    try:
        [cite_start]port = int(port) if port is not None else None [cite: 122]
        [cite_start]if port and not (1 <= port <= 65535): [cite: 122]
            logging.debug(f"无效端口号: {port} for node {name}")
            return None
    [cite_start]except (ValueError, TypeError): [cite: 122]
        logging.debug(f"端口号非整数: {port} for node {name}")
        return None

    [cite_start]if not (server and port): [cite: 122]
        return None

    [cite_start]if node_type == 'vmess': [cite: 122, 123]
        vmess_obj = {
            [cite_start]"v": node_dict.get('v', '2'), [cite: 123]
            [cite_start]"ps": name, [cite: 123]
            [cite_start]"add": server, [cite: 123]
            [cite_start]"port": port, [cite: 123]
            [cite_start]"id": uuid, [cite: 123]
            [cite_start]"aid": int(node_dict.get('alterId', node_dict.get('aid', 0))), [cite: 123]
            [cite_start]"net": node_dict.get('network', node_dict.get('net', 'tcp')), [cite: 123, 124]
            [cite_start]"type": node_dict.get('type', 'none'), [cite: 124]
            [cite_start]"host": node_dict.get('udp', node_dict.get('host', '')), [cite: 124]
            [cite_start]"path": node_dict.get('path', ''), [cite: 124]
            [cite_start]"tls": "tls" if node_dict.get('tls') else "none", [cite: 124]
            [cite_start]"sni": node_dict.get('servername', node_dict.get('sni', '')), [cite: 124]
            [cite_start]"scy": node_dict.get('cipher', ''), [cite: 124]
            [cite_start]"fp": node_dict.get('fingerprint', '') [cite: 125]
        }
        [cite_start]vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]} [cite: 125]
        try:
            [cite_start]sorted_vmess_obj = dict(sorted(vmess_obj.items())) [cite: 125]
            [cite_start]return f"vmess://{base64.b64encode(json.dumps(sorted_vmess_obj, separators=(',', ':')).encode('utf-8')).decode('utf-8')}" [cite: 125, 126]
        except Exception as e:
            [cite_start]logging.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}") [cite: 126]
            return None

    [cite_start]elif node_type == 'vless': [cite: 126]
        [cite_start]if not uuid: [cite: 126]
            return None
        [cite_start]vless_link = f"vless://{uuid}@{server}:{port}" [cite: 126]
        params = {}
        [cite_start]if node_dict.get('security'): [cite: 126]
            params['security'] = node_dict['security']
        [cite_start]elif node_dict.get('tls'): [cite: 127]
            params['security'] = 'tls'
        [cite_start]if node_dict.get('flow'): [cite: 127]
            params['flow'] = node_dict['flow']
        [cite_start]if node_dict.get('network'): [cite: 127]
            params['type'] = node_dict['network']
        [cite_start]if node_dict.get('path'): [cite: 127]
            params['path'] = node_dict['path']
        [cite_start]if node_dict.get('host'): [cite: 127]
            params['host'] = node_dict['host']
        [cite_start]if node_dict.get('servername'): [cite: 128]
            params['sni'] = node_dict['servername']
        [cite_start]if node_dict.get('alpn'): [cite: 128]
            params['alpn'] = node_dict['alpn']
        [cite_start]if node_dict.get('publicKey'): [cite: 128]
            params['pbk'] = node_dict['publicKey']
        [cite_start]if node_dict.get('shortId'): [cite: 128]
            params['sid'] = node_dict['shortId']
        [cite_start]if node_dict.get('fingerprint'): [cite: 129]
            params['fp'] = node_dict['fingerprint']
        [cite_start]if node_dict.get('serviceName'): [cite: 129]
            params['serviceName'] = node_dict['serviceName']
        [cite_start]if node_dict.get('mode'): [cite: 129]
            params['mode'] = node_dict['mode']
        [cite_start]if name: [cite: 129]
            params['remarks'] = name

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} [cite: 130]
        [cite_start]if params: [cite: 130]
            [cite_start]sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])]) [cite: 130]
            vless_link += "?" + [cite_start]urlencode(sorted_params, doseq=True) [cite: 131]
        return vless_link

    [cite_start]elif node_type == 'trojan': [cite: 131]
        [cite_start]if not password: [cite: 131]
            return None
        [cite_start]trojan_link = f"trojan://{password}@{server}:{port}" [cite: 131]
        params = {}
        [cite_start]if node_dict.get('security'): [cite: 131]
            params['security'] = node_dict['security']
        [cite_start]elif node_dict.get('tls'): [cite: 132]
            params['security'] = 'tls'
        [cite_start]if node_dict.get('network'): [cite: 132]
            params['type'] = node_dict['network']
        [cite_start]if node_dict.get('path'): [cite: 132]
            params['path'] = node_dict['path']
        [cite_start]if node_dict.get('host'): [cite: 132]
            params['host'] = node_dict['host']
        [cite_start]if node_dict.get('servername'): [cite: 132]
            params['sni'] = node_dict['servername']
        [cite_start]if node_dict.get('alpn'): [cite: 133]
            params['alpn'] = node_dict['alpn']
        [cite_start]if node_dict.get('fingerprint'): [cite: 133]
            params['fp'] = node_dict['fingerprint']
        [cite_start]if node_dict.get('flow'): [cite: 133]
            params['flow'] = node_dict['flow']
        [cite_start]if name: [cite: 133]
            params['remarks'] = name

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} [cite: 134]
        [cite_start]if params: [cite: 134]
            [cite_start]sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])]) [cite: 134]
            trojan_link += "?" + [cite_start]urlencode(sorted_params, doseq=True) [cite: 135]
        return trojan_link

    [cite_start]elif node_type == 'ss': [cite: 135]
        [cite_start]if not password or not node_dict.get('cipher'): [cite: 135]
            return None
        [cite_start]method_pwd = f"{node_dict['cipher']}:{password}" [cite: 135]
        [cite_start]encoded_method_pwd = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8') [cite: 135]
        [cite_start]ss_link = f"ss://{encoded_method_pwd}@{server}:{port}" [cite: 135]
        [cite_start]if name: [cite: 136]
            ss_link += f"#{name}"
        return ss_link

    [cite_start]elif node_type == 'hysteria2': [cite: 136]
        # Hysteria2 协议通常需要密码或 UUID，这里统一按密码处理
        [cite_start]if not password: [cite: 136]
            return None
        
        # 修正：Hysteria2 链接的认证信息在 host 部分，而不是 query 参数
        # 例如: hysteria2://uuid@server:port?query_params#name
        # 或者 hysteria2://password@server:port?query_params#name
        # 您的原始代码逻辑似乎尝试将密码放入 query params，这不符合常见格式。
        # 鉴于您的示例是 `hysteria2://0c4c1a89-5645-4fc2-9e3b-ab09aa44e933@138.2.61.132:13059?insecure=0&obfs=salamander&obfs-password=SNLJD19ZejtSdxW4&sni=jp-odhdjfjcj.gzcloud.shop#8|@vpnv2rayNGv`
        # 这表明认证信息 (UUID) 在 `@` 之前。
        # 因此，这里的 `convert_dict_to_node_link` 应该是组装这种格式。

        # 从 node_dict 中获取认证信息，优先 UUID
        auth_info = uuid if uuid else password
        if not auth_info:
            return None

        hysteria2_link_base = f"hysteria2://{auth_info}@{server}:{port}"
        
        params = {}
        # 以下参数应该作为 URL 的 query 部分
        if node_dict.get('insecure') is not None:
            params['insecure'] = int(bool(node_dict['insecure'])) # 0 or 1
        [cite_start]if node_dict.get('obfs'): [cite: 136]
            params['obfs'] = node_dict['obfs']
        [cite_start]if node_dict.get('obfs-password'): [cite: 137]
            params['obfs-password'] = node_dict['obfs-password']
        if node_dict.get('sni'): # sni 字段
            params['sni'] = node_dict['sni']

        # 其他协议特定参数，需要转换为 Hysteria2 的对应名称
        [cite_start]for key in ['up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open', 'ca', 'recv_window_conn', 'recv_window_client', 'disable_mtu_discovery']: [cite: 137]
            if node_dict.get(key) is not None and node_dict.get(key) != '':
                params[key.replace('_', '-')] = node_dict[key]

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} [cite: 137]
        [cite_start]query_string = urlencode(sorted(params.items()), doseq=True) [cite: 137]
        
        final_link = hysteria2_link_base
        if query_string:
            final_link += f"?{query_string}"
        
        [cite_start]if name: [cite: 138]
            # 节点名称通常在 # 之后，且可能需要 URL 编码
            final_link += f"#{urlparse(name).path.replace(' ', '%20')}" 
            
        return final_link

    return None

def parse_content(content: str, content_type_hint: str = "unknown") -> str:
    """
    智能解析内容，尝试通过 Content-Type 提示，然后回退到内容嗅探。
    """
    [cite_start]if not content: [cite: 138]
        return ""

    combined_text_for_regex = []

    [cite_start]if "json" in content_type_hint or content.strip().startswith(("{", "[")): [cite: 139]
        try:
            [cite_start]parsed_json = json.loads(content) [cite: 139]
            [cite_start]logging.info("内容被识别为 JSON 格式。") [cite: 139]
            [cite_start]nodes_from_json = extract_nodes_from_json(parsed_json) [cite: 139]
            [cite_start]if nodes_from_json: [cite: 139]
                [cite_start]combined_text_for_regex.extend(nodes_from_json) [cite: 140]
            [cite_start]combined_text_for_regex.append(content) [cite: 140]
            return "\n".join(list(set(combined_text_for_regex)))
        [cite_start]except json.JSONDecodeError: [cite: 140]
            [cite_start]logging.debug("内容尝试 JSON 解析失败。") [cite: 140]
            pass

    [cite_start]if "yaml" in content_type_hint or content.strip().startswith(("---", "- ", "proxies:")): [cite: 140]
        try:
            [cite_start]parsed_yaml = yaml.safe_load(content) [cite: 141]
            [cite_start]if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml or 'outbounds' in parsed_yaml): [cite: 141]
                [cite_start]logging.info("内容被识别为 YAML 格式。") [cite: 141]
                [cite_start]nodes_from_yaml = extract_nodes_from_yaml(parsed_yaml) [cite: 141]
                [cite_start]if nodes_from_yaml: [cite: 141]
                    [cite_start]combined_text_for_regex.extend(nodes_from_yaml) [cite: 142]
                [cite_start]combined_text_for_regex.append(content) [cite: 142]
                return "\n".join(list(set(combined_text_for_regex)))
        [cite_start]except yaml.YAMLError: [cite: 142]
            [cite_start]logging.debug("内容尝试 YAML 解析失败。") [cite: 142]
            pass

    [cite_start]if "html" in content_type_hint or '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower(): [cite: 142]
        [cite_start]logging.info("内容被识别为 HTML 格式。") [cite: 142]
        [cite_start]nodes_from_html = extract_nodes_from_html(content) [cite: 143]
        [cite_start]if nodes_from_html: [cite: 143]
            [cite_start]combined_text_for_regex.extend(nodes_from_html) [cite: 143]
            return "\n".join(list(set(combined_text_for_regex)))

    [cite_start]logging.info("内容尝试纯文本/Base64 嗅探。") [cite: 143]
    [cite_start]decoded_base64_full = decode_base64_recursive(content) [cite: 143]
    [cite_start]if decoded_base64_full and decoded_base64_full != content: [cite: 143]
        [cite_start]logging.info("内容被识别为 Base64 编码，已递归解码。") [cite: 143]
        [cite_start]combined_text_for_regex.append(decoded_base64_full) [cite: 144]
        try:
            [cite_start]temp_parsed_json = json.loads(decoded_base64_full) [cite: 144]
            [cite_start]combined_text_for_regex.extend(extract_nodes_from_json(temp_parsed_json)) [cite: 144]
        [cite_start]except json.JSONDecodeError: [cite: 144]
            pass
        try:
            [cite_start]temp_parsed_yaml = yaml.safe_load(decoded_base64_full) [cite: 144]
            [cite_start]if isinstance(temp_parsed_yaml, dict) and ('proxies' in temp_parsed_yaml or 'proxy-groups' in temp_parsed_yaml or 'outbounds' in temp_parsed_yaml): [cite: 144, 145]
                [cite_start]combined_text_for_regex.extend(extract_nodes_from_yaml(temp_parsed_yaml)) [cite: 145]
        [cite_start]except yaml.YAMLError: [cite: 145]
            pass

    [cite_start]combined_text_for_regex.append(content) [cite: 145]
    [cite_start]all_text_to_scan = "\n".join(list(set(combined_text_for_regex))) [cite: 145]
    [cite_start]potential_base64_matches = BASE64_REGEX.findall(all_text_to_scan) [cite: 145]
    [cite_start]for b64_match in potential_base64_matches: [cite: 145]
        [cite_start]if len(b64_match) > 30 and '=' in b64_match: [cite: 145]
            [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) [cite: 145]
            [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: [cite: 146]
                [cite_start]combined_text_for_regex.append(decoded_b64_in_text) [cite: 146]

    return "\n".join(list(set(combined_text_for_regex)))

def extract_nodes_from_json(parsed_json: dict | list) -> list[str]:
    """从已解析的 JSON 对象中提取节点链接。"""
    nodes = []
    [cite_start]if isinstance(parsed_json, list): [cite: 147]
        [cite_start]for item in parsed_json: [cite: 147]
            [cite_start]if isinstance(item, str): [cite: 147]
                nodes.append(item)
            [cite_start]elif isinstance(item, dict): [cite: 147]
                [cite_start]node_link = convert_dict_to_node_link(item) [cite: 147]
                [cite_start]if node_link: [cite: 148]
                    nodes.append(node_link)
    [cite_start]elif isinstance(parsed_json, dict): [cite: 148]
        [cite_start]if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list): [cite: 148]
            [cite_start]for proxy in parsed_json['proxies']: [cite: 148]
                [cite_start]if isinstance(proxy, dict): [cite: 149]
                    [cite_start]node_link = convert_dict_to_node_link(proxy) [cite: 149]
                    [cite_start]if node_link: [cite: 149]
                        nodes.append(node_link)
        [cite_start]if 'outbounds' in parsed_json and isinstance(parsed_json['outbounds'], list): [cite: 149]
            [cite_start]for outbound in parsed_json['outbounds']: [cite: 150]
                [cite_start]if isinstance(outbound, dict): [cite: 150]
                    [cite_start]node_link = convert_dict_to_node_link(outbound) [cite: 150]
                    [cite_start]if node_link: [cite: 150]
                        nodes.append(node_link)
        [cite_start]for key, value in parsed_json.items(): [cite: 150]
            [cite_start]if isinstance(value, str): [cite: 151]
                nodes.append(value)
                [cite_start]decoded_value = decode_base64_recursive(value) [cite: 151]
                [cite_start]if decoded_value and decoded_value != value: [cite: 151]
                    nodes.append(decoded_value)
            [cite_start]elif isinstance(value, list): [cite: 151]
                [cite_start]for list_item in value: [cite: 152]
                    [cite_start]if isinstance(list_item, str): [cite: 152]
                        nodes.append(list_item)
                        [cite_start]decoded_list_item = decode_base64_recursive(list_item) [cite: 152]
                        [cite_start]if decoded_list_item and decoded_list_item != list_item: [cite: 153]
                            nodes.append(decoded_list_item)
                    [cite_start]elif isinstance(list_item, dict): [cite: 153]
                        [cite_start]node_link = convert_dict_to_node_link(list_item) [cite: 153]
                        [cite_start]if node_link: [cite: 154]
                            nodes.append(node_link)
    return nodes

def extract_nodes_from_yaml(parsed_yaml: dict) -> list[str]:
    """从已解析的 YAML 对象中提取节点链接。"""
    nodes = []
    [cite_start]if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list): [cite: 154]
        [cite_start]for proxy in parsed_yaml['proxies']: [cite: 155]
            [cite_start]if isinstance(proxy, dict) and 'type' in proxy: [cite: 155]
                [cite_start]node_link = convert_dict_to_node_link(proxy) [cite: 155]
                [cite_start]if node_link: [cite: 155]
                    nodes.append(node_link)
    [cite_start]if 'outbounds' in parsed_yaml and isinstance(parsed_yaml['outbounds'], list): [cite: 155]
        [cite_start]for outbound in parsed_yaml['outbounds']: [cite: 155]
            [cite_start]if isinstance(outbound, dict) and 'type' in outbound: [cite: 156]
                [cite_start]node_link = convert_dict_to_node_link(outbound) [cite: 156]
                [cite_start]if node_link: [cite: 156]
                    nodes.append(node_link)

    def search_for_b64_in_yaml_values(obj):
        [cite_start]if isinstance(obj, dict): [cite: 156]
            [cite_start]for k, v in obj.items(): [cite: 157]
                [cite_start]if isinstance(v, str): [cite: 157]
                    [cite_start]decoded_value = decode_base64_recursive(v) [cite: 157]
                    [cite_start]if decoded_value and decoded_value != v: [cite: 157]
                        nodes.append(decoded_value)
                [cite_start]elif isinstance(v, (dict, list)): [cite: 157]
                    search_for_b64_in_yaml_values(v)
    [cite_start]elif isinstance(obj, list): [cite: 158]
        [cite_start]for item in obj: [cite: 158]
            [cite_start]if isinstance(item, str): [cite: 158]
                [cite_start]decoded_value = decode_base64_recursive(item) [cite: 158]
                [cite_start]if decoded_value and decoded_value != item: [cite: 159]
                    nodes.append(decoded_value)
            [cite_start]elif isinstance(item, (dict, list)): [cite: 159]
                search_for_b64_in_yaml_values(item)
    [cite_start]search_for_b64_in_yaml_values(parsed_yaml) [cite: 159]

    return nodes

def extract_nodes_from_html(html_content: str) -> list[str]:
    """从 HTML 内容中提取节点链接。"""
    nodes = []
    [cite_start]soup = BeautifulSoup(html_content, 'html.parser') [cite: 159]
    [cite_start]potential_node_containers = soup.find_all(['pre', 'code', 'textarea', 'script', 'style']) [cite: 159, 160]
    [cite_start]for tag in potential_node_containers: [cite: 160]
        [cite_start]extracted_text = tag.get_text(separator="\n", strip=True) [cite: 160]
        [cite_start]if extracted_text: [cite: 160]
            nodes.append(extracted_text)
            [cite_start]if tag.name in ['script', 'style']: [cite: 160]
                [cite_start]potential_base64_matches = BASE64_REGEX.findall(extracted_text) [cite: 160]
                [cite_start]for b64_match in potential_base64_matches: [cite: 161]
                    [cite_start]if len(b64_match) > 30 and '=' in b64_match: [cite: 161]
                        [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) [cite: 161]
                        [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: [cite: 161]
                            nodes.append(decoded_b64_in_text)

    [cite_start]if soup.body: [cite: 161, 162]
        [cite_start]body_text = soup.body.get_text(separator="\n", strip=True) [cite: 162]
        [cite_start]if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()): [cite: 162]
            [cite_start]if body_text: [cite: 162]
                nodes.append(body_text)
                [cite_start]potential_base64_matches = BASE64_REGEX.findall(body_text) [cite: 162]
                [cite_start]for b64_match in potential_base64_matches: [cite: 163]
                    [cite_start]if len(b64_match) > 30 and '=' in b64_match: [cite: 163]
                        [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) [cite: 163]
                        [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: [cite: 164]
                            nodes.append(decoded_b64_in_text)
    return nodes

def extract_and_validate_nodes(content: str) -> list[str]:
    """
    从解析后的内容中提取并验证所有支持格式的节点 URL。
    """
    [cite_start]if not content: [cite: 164]
        return []

    found_nodes = set()
    [cite_start]for pattern_name, pattern_regex in NODE_PATTERNS.items(): [cite: 165]
        [cite_start]matches = pattern_regex.findall(content) [cite: 165]
        for match in matches:
            [cite_start]decoded_match = unquote(match).strip() [cite: 165]
            [cite_start]normalized_node = standardize_node_url(decoded_match) [cite: 165]
            # 这里统一调用 is_valid_node，它内部会判断 Hysteria2 的有效性
            if is_valid_node(normalized_node):
                found_nodes.add(normalized_node)

    return list(found_nodes)

def load_existing_nodes_from_slices(directory: str, prefix: str) -> set[str]:
    """从多个切片文件中加载已存在的节点列表，并进行标准化处理。"""
    existing_nodes = set()
    loaded_count = 0
    [cite_start]for filename in os.listdir(directory): [cite: 165]
        [cite_start]if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'): [cite: 165]
            [cite_start]file_path = os.path.join(directory, filename) [cite: 166]
            try:
                [cite_start]with open(file_path, 'r', encoding='utf-8') as f: [cite: 166]
                    for line in f:
                        # 适应旧格式（Proxy-0000X = 链接）和新格式（纯链接）
                        [cite_start]parts = line.strip().split(' = ', 1) [cite: 167]
                        node_url = parts[1].strip() if len(parts) == 2 else line.strip()
                        [cite_start]standardized_node = standardize_node_url(node_url) [cite: 167]
                        [cite_start]existing_nodes.add(standardized_node) [cite: 167]
                        [cite_start]loaded_count += 1 [cite: 168]
            except Exception as e:
                [cite_start]logging.warning(f"加载现有节点文件失败 ({file_path}): {e}") [cite: 168]
    [cite_start]logging.info(f"已从 {len([f for f in os.listdir(directory) if f.startswith(os.path.basename(prefix)) and f.endswith('.txt')])} 个切片文件中加载 {loaded_count} 个现有节点。") [cite: 168]
    return existing_nodes

def save_nodes_to_sliced_files(output_prefix: str, nodes: list[str], max_nodes_per_slice: int) -> None:
    """将处理后的节点切片保存到多个文本文件，不再带 'Proxy-0000X = ' 前缀。"""
    total_nodes = len(nodes)
    [cite_start]num_slices = (total_nodes + max_nodes_per_slice - 1) // max_nodes_per_slice [cite: 169]

    # 清理旧的切片文件
    [cite_start]for filename in os.listdir(DATA_DIR): [cite: 169]
        [cite_start]if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'): [cite: 169]
            try:
                [cite_start]os.remove(os.path.join(DATA_DIR, filename)) [cite: 170]
                [cite_start]logging.info(f"已删除旧切片文件: {filename}") [cite: 170]
            except OSError as e:
                [cite_start]logging.warning(f"删除旧切片文件失败 ({filename}): {e}") [cite: 170]

    saved_files_count = 0
    [cite_start]nodes.sort() # 排序确保输出一致性 [cite: 170]
    [cite_start]for i in range(num_slices): [cite: 170]
        [cite_start]start_index = i * max_nodes_per_slice [cite: 171]
        [cite_start]end_index = min((i + 1) * max_nodes_per_slice, total_nodes) [cite: 171]
        [cite_start]slice_nodes = nodes[start_index:end_index] [cite: 171]
        [cite_start]slice_file_name = f"{output_prefix}{i+1:03d}.txt" [cite: 171]

        try:
            [cite_start]with open(slice_file_name, 'w', encoding='utf-8') as f: [cite: 171]
                for node in slice_nodes: # 直接写入节点，不带前缀
                    f.write(f"{node}\n")
            [cite_start]logging.info(f"已保存切片文件: {slice_file_name} (包含 {len(slice_nodes)} 个节点)") [cite: 171]
            saved_files_count += 1
        except IOError as e:
            [cite_start]logging.error(f"保存切片文件失败 ({slice_file_name} {e})") [cite: 172]

    [cite_start]logging.info(f"最终节点列表已切片保存到 {saved_files_count} 个文件。") [cite: 172]

def save_node_counts_to_csv(file_path: str, counts_data: dict) -> None:
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    try:
        [cite_start]with open(file_path, 'w', encoding='utf-8', newline='') as f: [cite: 172]
            [cite_start]writer = csv.writer(f) [cite: 173]
            [cite_start]writer.writerow(["Source URL", "Node Count", "Processing Status"]) [cite: 173]
            [cite_start]for url in sorted(counts_data.keys()): [cite: 173]
                [cite_start]item = counts_data[url] [cite: 173]
                [cite_start]writer.writerow([url, item['count'], item['status']]) [cite: 173]
        [cite_start]logging.info(f"节点数量统计已保存到 {file_path}") [cite: 173]
    except IOError as e:
        [cite_start]logging.error(f"保存节点数量统计CSV失败: {e}") [cite: 173]

# --- 主逻辑 ---

def process_single_url(url: str, url_cache_data: dict) -> tuple[str, int, dict, list[str], str]:
    """处理单个URL的逻辑"""
    logging.info(f"开始处理 URL: {url}")
    [cite_start]content, new_cache_meta, fetch_status = fetch_content(url, cache_data=url_cache_data.get(url, {}).copy()) [cite: 174]

    [cite_start]if fetch_status == "SKIPPED_UNCHANGED": [cite: 174]
        [cite_start]cached_info = url_cache_data.get(url, {'node_count': 0, 'status': 'UNKNOWN'}) [cite: 174]
        return url, cached_info.get('node_count', 0), new_cache_meta, [], fetch_status

    [cite_start]if fetch_status != "FETCH_SUCCESS": [cite: 174]
        return url, 0, None, [], fetch_status

    [cite_start]parsed_content_text = parse_content(content, new_cache_meta.get('content_type', 'unknown')) [cite: 174]
    [cite_start]nodes_from_url = extract_and_validate_nodes(parsed_content_text) [cite: 175]

    [cite_start]logging.info(f"从 {url} 提取到 {len(nodes_from_url)} 个有效节点。") [cite: 175]

    [cite_start]if new_cache_meta: [cite: 175]
        [cite_start]new_cache_meta['node_count'] = len(nodes_from_url) [cite: 175]
        [cite_start]new_cache_meta['status'] = "PARSE_NO_NODES" if len(nodes_from_url) == 0 else "PARSE_SUCCESS" [cite: 175]
    else:
        [cite_start]new_cache_meta = url_cache_data.get(url, {}) [cite: 175]
        [cite_start]new_cache_meta['node_count'] = len(nodes_from_url) [cite: 175]
        [cite_start]new_cache_meta['status'] = "PARSE_NO_NODES" if len(nodes_from_url) == 0 else "PARSE_SUCCESS" [cite: 175]

    return url, len(nodes_from_url), new_cache_meta, nodes_from_url, new_cache_meta['status']

def main():
    start_time = time.time()
    logging.info("脚本开始运行。")

    [cite_start]source_urls = read_sources(SOURCES_FILE) [cite: 176]
    [cite_start]if not source_urls: [cite: 176]
        [cite_start]logging.error("未找到任何源 URL，脚本终止。") [cite: 176]
        return

    [cite_start]url_cache = load_cache(CACHE_FILE) [cite: 176]
    [cite_start]if os.path.exists(FAILED_URLS_FILE): [cite: 176]
        try:
            [cite_start]os.remove(FAILED_URLS_FILE) [cite: 176]
            [cite_start]logging.info(f"已清空旧的失败URL日志文件: {FAILED_URLS_FILE}") [cite: 176]
        except OSError as e:
            [cite_start]logging.warning(f"清空失败URL日志文件失败: {e}") [cite: 176]

    [cite_start]existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX) [cite: 177]
    all_new_and_existing_nodes = set(existing_nodes)

    url_processing_detailed_info = {}
    url_processing_summary = defaultdict(int)

    [cite_start]with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor: [cite: 177]
        [cite_start]future_to_url = {executor.submit(process_single_url, url, url_cache): url for url in source_urls} [cite: 177]

        [cite_start]for i, future in enumerate(as_completed(future_to_url)): [cite: 177]
            [cite_start]url = future_to_url[future] [cite: 177]
            try:
                [cite_start]processed_url, node_count, updated_cache_meta, extracted_nodes_list, status = future.result() [cite: 177]
                [cite_start]url_processing_detailed_info[processed_url] = {'count': node_count, 'status': status} [cite: 178]
                [cite_start]url_processing_summary[status] += 1 [cite: 178]

                [cite_start]if extracted_nodes_list: [cite: 178]
                    [cite_start]all_new_and_existing_nodes.update(extracted_nodes_list) [cite: 178]

                [cite_start]if updated_cache_meta: [cite: 178]
                    url_cache[processed_url] = updated_cache_meta
                [cite_start]elif status == "SKIPPED_UNCHANGED": [cite: 179]
                    [cite_start]if processed_url not in url_cache: [cite: 179]
                        [cite_start]url_cache[processed_url] = {'node_count': node_count, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'} [cite: 179]
                    else:
                        [cite_start]url_cache[processed_url]['node_count'] = node_count [cite: 180]
                        url_cache[processed_url]['status'] = status
                else:
                    [cite_start]if processed_url not in url_cache: [cite: 180, 181]
                        [cite_start]url_cache[processed_url] = {'node_count': 0, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'} [cite: 181]
                    else:
                        [cite_start]url_cache[processed_url]['status'] = status [cite: 181]
                        [cite_start]url_cache[processed_url]['node_count'] = 0 [cite: 181]

                [cite_start]if (i + 1) % CACHE_SAVE_INTERVAL == 0: [cite: 182]
                    [cite_start]save_cache(CACHE_FILE, url_cache) [cite: 182]
                    [cite_start]logging.info(f"已处理 {i + 1} 个URL，阶段性保存缓存。") [cite: 182]

            except Exception as exc:
                [cite_start]logging.error(f'{url} 生成了一个意外异常 (主循环): {exc}', exc_info=True) [cite: 182, 183]
                [cite_start]url_processing_detailed_info[url] = {'count': url_cache.get(url, {}).get('node_count', 0), 'status': "UNEXPECTED_MAIN_ERROR"} [cite: 183]
                [cite_start]url_processing_summary["UNEXPECTED_MAIN_ERROR"] += 1 [cite: 183]
                [cite_start]log_failed_url(url, f"意外主循环异常: {exc}") [cite: 183]
                [cite_start]save_cache(CACHE_FILE, url_cache) [cite: 183]

    [cite_start]logging.info("\n--- 处理完成报告 ---") [cite: 184]
    [cite_start]logging.info(f"总共尝试处理 {len(source_urls)} 个源URL。") [cite: 184]
    [cite_start]logging.info(f"状态统计:") [cite: 184]
    [cite_start]for status, count in sorted(url_processing_summary.items()): [cite: 184]
        logging.info(f"  {status}: {count} 个")

    [cite_start]final_nodes_list = sorted(list(all_new_and_existing_nodes)) [cite: 184]
    [cite_start]logging.info(f"总共收集到 {len(final_nodes_list)} 个去重后的节点 (含原有节点)。") [cite: 184]

    [cite_start]save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE) [cite: 184]
    [cite_start]save_node_counts_to_csv(NODE_COUNTS_FILE, url_processing_detailed_info) [cite: 184]
    [cite_start]save_cache(CACHE_FILE, url_cache) [cite: 184]

    end_time = time.time()
    [cite_start]logging.info(f"\n总耗时: {end_time - start_time:.2f} 秒。") [cite: 184]
    if any(status.startswith("FETCH_FAILED") or status.startswith("UNEXPECTED_") or status.startswith("PARSE_NO_NODES") for status in url_processing_summary.keys()):
        logging.info(f"\n请检查 {FAILED_URLS_FILE} 文件查看失败的URL详情。")

if __name__ == "__main__":
    main()
