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
import logging
import httpx
import urllib3
import asyncio
from collections import defaultdict

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

CONCURRENT_REQUESTS_LIMIT = 30 # 建议降低并发量以提高稳定性
REQUEST_TIMEOUT = 15 # 增加超时时间
RETRY_ATTEMPTS = 2
CACHE_SAVE_INTERVAL = 100
MAX_RECURSION_DEPTH = 2 # 最大递归抓取深度，0表示只抓取sources.list中的URL，1表示抓取sources.list和它们直接指向的URL，以此类推

PROXIES = None #

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
BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}', re.IGNORECASE) # 至少20个字符，减少误判

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
            # 尝试 urlsafe 解码
            decoded_bytes = base64.urlsafe_b64decode(current_decoded_str + '==')
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if not temp_decoded or temp_decoded == current_decoded_str:
                break
            # 检查解码后的字符串是否仍然是 Base64 格式，如果是则继续解码
            # 否则，停止递归，认为已经到达最终内容
            if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                current_decoded_str = temp_decoded
                break
            current_decoded_str = temp_decoded
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
                # 尝试标准 Base64 解码
                decoded_bytes = base64.b64decode(current_decoded_str + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded_str:
                    break
                if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                    current_decoded_str = temp_decoded
                    break
                current_decoded_str = temp_decoded
            except (base64.binascii.Error, UnicodeDecodeError):
                break
        except Exception as e:
            logging.debug(f"递归Base64解码中发生未知错误: {e}")
            break
    return current_decoded_str

async def fetch_content(url: str, client: httpx.AsyncClient, retries: int = RETRY_ATTEMPTS, cache_data: dict = None) -> tuple[str | None, dict | None, str]:
    """
    异步尝试通过 HTTP 或 HTTPS 获取指定 URL 的内容，并包含重试机制。
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
    # 确保 URL 总是带上协议头，避免 httpx 内部解析问题
    parsed_input_url = urlparse(url)
    if not parsed_input_url.scheme:
        # 如果原始URL没有协议头，尝试 HTTPS 和 HTTP
        test_urls.append(f"https://{url}")
        test_urls.append(f"http://{url}")
    else:
        # 如果原始URL已有协议头，直接使用
        test_urls.append(url)

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                response = await client.get(current_url_to_test, headers=current_headers, follow_redirects=True)

                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                content_type = response.headers.get('Content-Type', '').lower()
                content_hash = hashlib.sha256(response.content).hexdigest()

                # If content hash is the same, regardless of 304 or 200, it's unchanged.
                if cache_data and cache_data.get('content_hash') == content_hash:
                    logging.info(f"  {url} 内容哈希未修改，跳过解析。")
                    # Update cache meta with latest headers even if content didn't change
                    return None, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type, 'last_updated_timestamp': cache_data.get('last_updated_timestamp', 'N/A')}, "SKIPPED_UNCHANGED"

                response.raise_for_status()

                # Content has changed or is new, so update last_updated_timestamp
                current_time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type, 'last_updated_timestamp': current_time_str}, "FETCH_SUCCESS"

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
            await asyncio.sleep(2 ** attempt + 1)

    logging.error(f"  {url} 所有 {retries} 次尝试均失败。")
    log_failed_url(url, status_reason)
    return None, None, status_reason

def standardize_node_url(node_url: str) -> str:
    """
    标准化节点链接的查询参数和部分结构，以便更精确地去重。
    并确保返回的 URL 不包含内部换行符。
    """
    if not isinstance(node_url, str):
        return ""

    try:
        parsed = urlparse(node_url)
    except ValueError as e:
        logging.warning(f"标准化节点URL时遇到无效格式错误: {e} - URL: {node_url}")
        # 尝试清理，但返回原始URL，不进行标准化
        return node_url.replace('\n', '').replace('\r', '')

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
                # 对 VMess 字段进行排序，保证一致性，同时考虑不同键的类型（字符串化）
                sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                # 确保 base64 内容不包含换行符
                normalized_b64 = normalized_b64.replace('\n', '').replace('\r', '')
                return f"vmess://{normalized_b64}"
        except Exception as e:
            logging.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
            return node_url.replace('\n', '').replace('\r', '') # 失败时也清理

    final_url = parsed.geturl()
    # 显式地从最终的 URL 字符串中移除任何换行符
    final_url = final_url.replace('\n', '').replace('\r', '')
    return final_url

def is_valid_hysteria2_node(node_link: str) -> bool:
    """
    校验 Hysteria2 链接是否有效。
    一个有效的 Hysteria2 链接通常至少包含：
    - 协议头: hysteria2://
    - 用户信息 (UUID 或密码) 和服务器地址:port
    这里我们要求链接中必须有 `@` 符号，且 `@` 之前的部分不为空（代表 UUID/密码），
    并且有有效的服务器地址和端口。
    """
    if not node_link.lower().startswith("hysteria2://"):
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
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False

    found_protocol = False
    for proto in NODE_PATTERNS.keys():
        if node_url.lower().startswith(f"{proto}://"):
            found_protocol = True
            break
    if not found_protocol:
        return False

    parsed_url = urlparse(node_url)

    # 特殊处理 Hysteria2 链接的校验
    if parsed_url.scheme.lower() == "hysteria2":
        return is_valid_hysteria2_node(node_url)

    # 其他协议的现有校验逻辑
    if parsed_url.scheme not in ["ss", "ssr", "vmess"]:
        if not parsed_url.hostname:
            return False
        if parsed_url.port and not (1 <= parsed_url.port <= 65535):
                return False
    elif parsed_url.scheme == "vmess":
        try:
            b64_content = parsed_url.netloc
            decoded = decode_base64_recursive(b64_content)
            if not decoded:
                return False
            vmess_obj = json.loads(decoded)
            if not ('add' in vmess_obj and 'port' in vmess_obj and 'id' in vmess_obj):
                return False
            if not (1 <= int(vmess_obj['port']) <= 65535):
                return False
        except Exception:
            return False

    return True

def convert_dict_to_node_link(node_dict: dict) -> str | None:
    """
    将字典形式的节点数据转换为标准节点链接。
    """
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
            logging.debug(f"无效端口号: {port} for node {name}")
            return None
    except (ValueError, TypeError):
        logging.debug(f"端口号非整数: {port} for node {name}")
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
            sorted_vmess_obj = dict(sorted(vmess_obj.items()))
            b64_encoded = base64.b64encode(json.dumps(sorted_vmess_obj, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return b64_encoded.replace('\n', '').replace('\r', '') # 确保不含换行符
        except Exception as e:
            logging.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}")
            return None

    elif node_type == 'vless':
        if not uuid:
            return None
        vless_link = f"vless://{uuid}@{server}:{port}"
        params = {}
        if node_dict.get('security'):
            params['security'] = node_dict['security']
        elif node_dict.get('tls'):
            params['security'] = 'tls'
        if node_dict.get('flow'):
            params['flow'] = node_dict['flow']
        if node_dict.get('network'):
            params['type'] = node_dict['network']
        if node_dict.get('path'):
            params['path'] = node_dict['path']
        if node_dict.get('host'):
            params['host'] = node_dict['host']
        if node_dict.get('servername'):
            params['sni'] = node_dict['servername']
        if node_dict.get('alpn'):
            params['alpn'] = node_dict['alpn']
        if node_dict.get('publicKey'):
            params['pbk'] = node_dict['publicKey']
        if node_dict.get('shortId'):
            params['sid'] = node_dict['shortId']
        if node_dict.get('fingerprint'):
            params['fp'] = node_dict['fingerprint']
        if node_dict.get('serviceName'):
            params['serviceName'] = node_dict['serviceName']
        if node_dict.get('mode'):
            params['mode'] = node_dict['mode']
        if name:
            params['remarks'] = name

        params = {k: v for k, v in params.items() if v not in ['', None]}
        if params:
            sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
            vless_link += "?" + urlencode(sorted_params, doseq=True)
        return vless_link.replace('\n', '').replace('\r', '') # 确保不含换行符

    elif node_type == 'trojan':
        if not password:
            return None
        trojan_link = f"trojan://{password}@{server}:{port}"
        params = {}
        if node_dict.get('security'):
            params['security'] = node_dict['security']
        elif node_dict.get('tls'):
            params['security'] = 'tls'
        if node_dict.get('network'):
            params['type'] = node_dict['network']
        if node_dict.get('path'):
            params['path'] = node_dict['path']
        if node_dict.get('host'):
            params['host'] = node_dict['host']
        if node_dict.get('servername'):
            params['sni'] = node_dict['servername']
        if node_dict.get('alpn'):
            params['alpn'] = node_dict['alpn']
        if node_dict.get('fingerprint'):
            params['fp'] = node_dict['fingerprint']
        if node_dict.get('flow'):
            params['flow'] = node_dict['flow']
        if name:
            params['remarks'] = name

        params = {k: v for k, v in params.items() if v not in ['', None]}
        if params:
            sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
            trojan_link += "?" + urlencode(sorted_params, doseq=True)
        return trojan_link.replace('\n', '').replace('\r', '') # 确保不含换行符

    elif node_type == 'ss':
        if not password or not node_dict.get('cipher'):
            return None
        method_pwd = f"{node_dict['cipher']}:{password}"
        encoded_method_pwd = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')
        ss_link = f"ss://{encoded_method_pwd}@{server}:{port}"
        if name:
            ss_link += f"#{name}"
        return ss_link.replace('\n', '').replace('\r', '') # 确保不含换行符

    elif node_type == 'hysteria2':
        # Hysteria2 协议认证信息在 host 部分
        auth_info = uuid if uuid else password
        if not auth_info:
            return None

        hysteria2_link_base = f"hysteria2://{auth_info}@{server}:{port}"

        params = {}
        # 以下参数应该作为 URL 的 query 部分
        if node_dict.get('insecure') is not None:
            params['insecure'] = int(bool(node_dict['insecure'])) # 0 or 1
        if node_dict.get('obfs'):
            params['obfs'] = node_dict['obfs']
        if node_dict.get('obfs-password'):
            params['obfs-password'] = node_dict['obfs-password']
        if node_dict.get('sni'): # sni 字段
            params['sni'] = node_dict['sni']

        # 其他协议特定参数，需要转换为 Hysteria2 的对应名称
        for key in ['up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open', 'ca', 'recv_window_conn', 'recv_window_client', 'disable_mtu_discovery']:
            if node_dict.get(key) is not None and node_dict.get(key) != '':
                params[key.replace('_', '-')] = node_dict[key]

        params = {k: v for k, v in params.items() if v not in ['', None]}
        query_string = urlencode(sorted(params.items()), doseq=True)

        final_link = hysteria2_link_base
        if query_string:
            final_link += f"?{query_string}"

        if name:
            # 节点名称通常在 # 之后，且可能需要 URL 编码
            final_link += f"#{urlparse(name).path.replace(' ', '%20')}"
            
        return final_link.replace('\n', '').replace('\r', '') # 确保不含换行符

    return None

def extract_nodes_from_json(parsed_json: dict | list) -> list[str]:
    """从解析后的JSON数据中提取节点链接。"""
    nodes = set()
    if isinstance(parsed_json, dict):
        if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list):
            for proxy_obj in parsed_json['proxies']:
                if isinstance(proxy_obj, dict):
                    node_link = convert_dict_to_node_link(proxy_obj)
                    if node_link and is_valid_node(node_link):
                        nodes.add(node_link)
        # 兼容其他可能包含节点列表的 JSON 结构
        for key, value in parsed_json.items():
            if isinstance(value, str):
                extracted_from_str = extract_and_validate_nodes(value)
                nodes.update(extracted_from_str)
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_json(value)) # 递归查找
    elif isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, str):
                extracted_from_str = extract_and_validate_nodes(item)
                nodes.update(extracted_from_str)
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_json(item)) # 递归查找
    return list(nodes)

def extract_nodes_from_yaml(parsed_yaml: dict | list) -> list[str]:
    """从解析后的YAML数据中提取节点链接。"""
    nodes = set()
    if isinstance(parsed_yaml, dict):
        if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
            for proxy_obj in parsed_yaml['proxies']:
                if isinstance(proxy_obj, dict):
                    node_link = convert_dict_to_node_link(proxy_obj)
                    if node_link and is_valid_node(node_link):
                        nodes.add(node_link)
        # 兼容其他可能包含节点列表的 YAML 结构
        for key, value in parsed_yaml.items():
            if isinstance(value, str):
                extracted_from_str = extract_and_validate_nodes(value)
                nodes.update(extracted_from_str)
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_yaml(value)) # 递归查找
    elif isinstance(parsed_yaml, list):
        for item in parsed_yaml:
            if isinstance(item, str):
                extracted_from_str = extract_and_validate_nodes(item)
                nodes.update(extracted_from_str)
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_yaml(item)) # 递归查找
    return list(nodes)

def extract_nodes_from_html(html_content: str, base_url: str) -> tuple[list[str], list[str]]:
    """
    从HTML内容中提取节点链接，并识别可能指向其他订阅源的URL。
    返回 (extracted_node_links, potential_subscription_urls)
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_nodes_from_html_set = set()
    potential_subscription_urls_set = set()

    # 1. 查找所有链接
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        
        # 将相对路径转换为绝对路径
        absolute_href = urljoin(base_url, href)
        
        # 尝试将href作为节点链接处理
        standardized_href = standardize_node_url(unquote(absolute_href).strip())
        if is_valid_node(standardized_href):
            extracted_nodes_from_html_set.add(standardized_href)
        else:
            # 如果不是直接节点，检查是否为订阅链接
            # 过滤掉常见的图片、JS、CSS、邮件等链接，只关注可能的订阅链接
            if (absolute_href.startswith(('http://', 'https://')) and
                not absolute_href.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico')) and
                not absolute_href.startswith('mailto:') and
                (absolute_href.endswith(('.txt', '.yaml', '.yml', '.json')) or
                 'sub' in absolute_href.lower() or 'subscribe' in absolute_href.lower() or
                 'clash' in absolute_href.lower() or 'singbox' in absolute_href.lower() or
                 'v2ray' in absolute_href.lower() or 'trojan' in absolute_href.lower() or
                 'ss' in absolute_href.lower() or 'ssr' in absolute_href.lower() or
                 'hysteria' in absolute_href.lower())):
                potential_subscription_urls_set.add(absolute_href)

    # 2. 查找 <pre>, <code>, <textarea> 中的文本内容，这些可能包含原始节点列表或Base64编码
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        text_content = tag.get_text().strip()
        if text_content:
            # 尝试直接解析其中的节点
            nodes_from_text = extract_and_validate_nodes(text_content)
            extracted_nodes_from_html_set.update(nodes_from_text)
            # 尝试 Base64 解码并提取节点
            decoded_b64 = decode_base64_recursive(text_content)
            if decoded_b64 and decoded_b64 != text_content:
                nodes_from_decoded_b64 = extract_and_validate_nodes(decoded_b64)
                extracted_nodes_from_html_set.update(nodes_from_decoded_b64)

    # 3. 查找 <script> 标签中的内容，可能包含 JSON 或 Base64 编码的节点
    for script_tag in soup.find_all('script'):
        script_content = script_tag.string
        if script_content:
            # 尝试解析 JSON
            if script_content.strip().startswith(('{', '[')):
                try:
                    js_data = json.loads(script_content)
                    # 递归从JS数据中提取节点
                    extracted_from_json_in_script = extract_nodes_from_json(js_data)
                    extracted_nodes_from_html_set.update(extracted_from_json_in_script)
                except json.JSONDecodeError:
                    pass
            
            # 提取脚本内容中的所有类似 Base64 的字符串并尝试解码
            potential_base64_matches = BASE64_REGEX.findall(script_content)
            for b64_match in potential_base64_matches:
                if len(b64_match) > 30 and '=' in b64_match: # 简单过滤短的或非Base64的匹配
                    decoded_b64_in_script = decode_base64_recursive(b64_match)
                    if decoded_b64_in_script and decoded_b64_in_script != b64_match:
                        # 从解码后的内容中提取节点
                        nodes_from_decoded_b64 = extract_and_validate_nodes(decoded_b64_in_script)
                        extracted_nodes_from_html_set.update(nodes_from_decoded_b64)

    return list(extracted_nodes_from_html_set), list(potential_subscription_urls_set)

def urljoin(base: str, url: str) -> str:
    """
    一个更健壮的URL拼接函数，处理相对路径。
    """
    if urlparse(url).scheme: # 如果是绝对URL，直接返回
        return url
    
    parsed_base = urlparse(base)
    # 对于相对URL，处理好路径，避免 /a/b + ../c 变成 /a/../c
    if not parsed_base.path.endswith('/'):
        base = base.rsplit('/', 1)[0] + '/'
    
    return urlparse(base)._replace(path=os.path.normpath(os.path.join(parsed_base.path, urlparse(url).path))).geturl()


def parse_content(content: str, base_url: str, content_type_hint: str = "unknown") -> tuple[list[str], list[str]]:
    """
    智能解析内容，尝试通过 Content-Type 提示，然后回退到内容嗅探。
    返回 (extracted_node_links, new_urls_to_follow)
    """
    extracted_nodes = set()
    new_urls_to_follow = set()

    # 1. 尝试 JSON 解析 (基于 Content-Type 或内容前缀)
    if "json" in content_type_hint or content.strip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(content)
            logging.info("内容被识别为 JSON 格式。")
            nodes_from_json = extract_nodes_from_json(parsed_json)
            extracted_nodes.update(nodes_from_json)
            # JSON 内容中可能也直接包含 Base64 编码的节点列表
            nodes_from_text = extract_and_validate_nodes(content)
            extracted_nodes.update(nodes_from_text)
            return list(extracted_nodes), list(new_urls_to_follow)
        except json.JSONDecodeError:
            logging.debug("内容尝试 JSON 解析失败。")
            pass

    # 2. 尝试 YAML 解析 (基于 Content-Type 或内容前缀)
    if "yaml" in content_type_hint or content.strip().startswith(("---", "- ", "proxies:", "outbounds:")):
        try:
            parsed_yaml = yaml.safe_load(content)
            if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml or 'outbounds' in parsed_yaml):
                logging.info("内容被识别为 YAML 格式。")
                nodes_from_yaml = extract_nodes_from_yaml(parsed_yaml)
                extracted_nodes.update(nodes_from_yaml)
                # YAML 内容中可能也直接包含 Base64 编码的节点列表
                nodes_from_text = extract_and_validate_nodes(content)
                extracted_nodes.update(nodes_from_text)
                return list(extracted_nodes), list(new_urls_to_follow)
        except yaml.YAMLError:
            logging.debug("内容尝试 YAML 解析失败。")
            pass

    # 3. 尝试 HTML 解析 (基于 Content-Type 或内容前缀)
    if "html" in content_type_hint or '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower():
        logging.info("内容被识别为 HTML 格式。")
        nodes_from_html, urls_from_html = extract_nodes_from_html(content, base_url)
        extracted_nodes.update(nodes_from_html)
        new_urls_to_follow.update(urls_from_html)
        
        # HTML 页面中的文本部分也可能直接包含 Base64 编码的节点列表
        nodes_from_text = extract_and_validate_nodes(content)
        extracted_nodes.update(nodes_from_text)
        
        return list(extracted_nodes), list(new_urls_to_follow)

    # 4. 尝试纯文本/Base64 嗅探 (作为最后的回退)
    logging.info("内容尝试纯文本/Base64 嗅探。")
    decoded_base64_full = decode_base64_recursive(content)
    
    content_to_scan = content # 默认扫描原始内容
    if decoded_base64_full and decoded_base64_full != content:
        logging.info("内容被识别为 Base64 编码，已递归解码。")
        content_to_scan = decoded_base64_full # 如果成功解码，则扫描解码后的内容

        # 解码后尝试再次进行 JSON/YAML 解析
        try:
            temp_parsed_json = json.loads(content_to_scan)
            extracted_nodes.update(extract_nodes_from_json(temp_parsed_json))
        except json.JSONDecodeError:
            pass
        try:
            temp_parsed_yaml = yaml.safe_load(content_to_scan)
            if isinstance(temp_parsed_yaml, dict) and ('proxies' in temp_parsed_yaml or 'proxy-groups' in temp_parsed_yaml or 'outbounds' in temp_parsed_yaml):
                extracted_nodes.update(extract_nodes_from_yaml(temp_parsed_yaml))
        except yaml.YAMLError:
            pass
    
    # 最后，对所有潜在文本片段进行通用正则匹配提取
    nodes_from_final_scan = extract_and_validate_nodes(content_to_scan)
    extracted_nodes.update(nodes_from_final_scan)

    return list(extracted_nodes), list(new_urls_to_follow)

def extract_and_validate_nodes(content: str) -> list[str]:
    """
    从解析后的内容中提取并验证所有支持格式的节点 URL。
    """
    if not content:
        return []

    found_nodes = set()
    for pattern_name, pattern_regex in NODE_PATTERNS.items():
        matches = pattern_regex.findall(content)
        for match in matches:
            decoded_match = unquote(match).strip()
            normalized_node = standardize_node_url(decoded_match) # standardize_node_url 内部会处理换行符
            # 这里统一调用 is_valid_node，它内部会判断 Hysteria2 的有效性
            if is_valid_node(normalized_node):
                found_nodes.add(normalized_node)

    return list(found_nodes)

def load_existing_nodes_from_slices(directory: str, prefix: str) -> set[str]:
    """从多个切片文件中加载已存在的节点列表，并进行标准化处理。"""
    existing_nodes = set()
    loaded_count = 0
    for filename in os.listdir(directory):
        if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        # 适应旧格式（Proxy-0000X = 链接）和新格式（纯链接）
                        parts = line.strip().split(' = ', 1)
                        node_url = parts[1].strip() if len(parts) == 2 else line.strip()
                        standardized_node = standardize_node_url(node_url) # 加载时也确保移除换行符
                        existing_nodes.add(standardized_node)
                        loaded_count += 1
            except Exception as e:
                logging.warning(f"加载现有节点文件失败 ({file_path}): {e}")
    logging.info(f"已从 {len([f for f in os.listdir(directory) if f.startswith(os.path.basename(prefix)) and f.endswith('.txt')])} 个切片文件中加载 {loaded_count} 个现有节点。")
    return existing_nodes

def save_nodes_to_sliced_files(output_prefix: str, nodes: list[str], max_nodes_per_slice: int) -> None:
    """将处理后的节点切片保存到多个文本文件，不再带 'Proxy-0000X = ' 前缀。"""
    total_nodes = len(nodes)
    num_slices = (total_nodes + max_nodes_per_slice - 1) // max_nodes_per_slice

    # 清理旧的切片文件
    for filename in os.listdir(DATA_DIR):
        if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'):
            try:
                os.remove(os.path.join(DATA_DIR, filename))
                logging.info(f"已删除旧切片文件: {filename}")
            except OSError as e:
                logging.warning(f"删除旧切片文件失败 ({filename}): {e}")

    saved_files_count = 0
    nodes.sort() # 排序确保输出一致性
    for i in range(num_slices):
        start_index = i * max_nodes_per_slice
        end_index = min((i + 1) * max_nodes_per_slice, total_nodes)
        slice_nodes = nodes[start_index:end_index]
        slice_file_name = f"{output_prefix}{i+1:03d}.txt"

        try:
            with open(slice_file_name, 'w', encoding='utf-8') as f:
                for node in slice_nodes: # 直接写入节点，不带前缀
                    # 再次确保写入的每个节点都是单行，避免任何意外的换行符
                    f.write(f"{node.replace('\n', '').replace('\r', '')}\n")
            logging.info(f"已保存切片文件: {slice_file_name} (包含 {len(slice_nodes)} 个节点)")
            saved_files_count += 1
        except IOError as e:
                logging.error(f"保存切片文件失败 ({slice_file_name} {e})")

    logging.info(f"最终节点列表已切片保存到 {saved_files_count} 个文件。")

def save_node_counts_to_csv(file_path: str, counts_data: dict) -> None:
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source URL", "Node Count", "Processing Status", "Last Updated UTC"])
            for url in sorted(counts_data.keys()):
                item = counts_data[url]
                writer.writerow([url, item['count'], item['status'], item.get('last_updated_timestamp', 'N/A')])
        logging.info(f"节点数量统计已保存到 {file_path}")
    except IOError as e:
        logging.error(f"保存节点数量统计CSV失败: {e}")

# --- 主逻辑 ---

async def process_single_url(url: str, current_depth: int, url_cache_data: dict, client: httpx.AsyncClient) -> tuple[str, int, dict, list[str], str, list[str]]:
    """处理单个URL的异步逻辑"""
    logging.info(f"开始处理 URL: {url} (深度: {current_depth})")
    
    # Get previous cache data for comparison
    previous_cache_meta = url_cache_data.get(url, {}).copy()
    
    content, new_cache_meta, fetch_status = await fetch_content(url, client, cache_data=previous_cache_meta)

    extracted_nodes_list = []
    new_urls_to_follow = []

    # If new_cache_meta is None, it means fetching failed
    if new_cache_meta is None:
        logging.error(f"无法获取或处理 {url} 的内容。")
        # Return a placeholder cache meta to avoid None issues downstream
        return url, 0, {
            'node_count': 0, 
            'status': fetch_status, 
            'content_hash': None, 
            'etag': None, 
            'last_modified': None, 
            'content_type': 'unknown',
            'last_updated_timestamp': previous_cache_meta.get('last_updated_timestamp', 'N/A')
        }, extracted_nodes_list, fetch_status, new_urls_to_follow

    # Determine if content was effectively updated based on fetch_status or content_hash comparison
    content_was_updated = (fetch_status == "FETCH_SUCCESS")
    if not content_was_updated and previous_cache_meta.get('content_hash') != new_cache_meta.get('content_hash'):
        content_was_updated = True
        logging.warning(f"  {url} 即使状态为 {fetch_status}，但内容哈希仍不同，将其视为已更新。")


    if content_was_updated:
        # Pass the original URL as base_url for relative link resolution in HTML parsing
        extracted_nodes_list, new_urls_to_follow = parse_content(content, url, new_cache_meta.get('content_type', 'unknown'))
        logging.info(f"从 {url} 提取到 {len(extracted_nodes_list)} 个有效节点，发现 {len(new_urls_to_follow)} 个新URL。")
        
        # Update node count and status based on current parsing
        new_cache_meta['node_count'] = len(extracted_nodes_list)
        new_cache_meta['status'] = "PARSE_NO_NODES" if len(extracted_nodes_list) == 0 else "PARSE_SUCCESS"
        # Update last_updated_timestamp only if content actually changed or it's a new entry
        new_cache_meta['last_updated_timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        logging.info(f"  {url} 内容已更新，上次更新时间: {new_cache_meta['last_updated_timestamp']}")
    else: # Content was skipped as unchanged
        # Preserve previous node count and status if unchanged, or initialize if new
        # nodes_from_url will be empty if skipped, so we don't add to all_new_and_existing_nodes
        new_cache_meta['node_count'] = previous_cache_meta.get('node_count', 0)
        new_cache_meta['status'] = fetch_status # Use SKIPPED_UNCHANGED status
        new_cache_meta['last_updated_timestamp'] = previous_cache_meta.get('last_updated_timestamp', 'N/A')
        logging.info(f"  {url} 内容未更新。") # Log explicitly that it was unchanged.

    return url, new_cache_meta.get('node_count', 0), new_cache_meta, extracted_nodes_list, new_cache_meta['status'], new_urls_to_follow


async def main():
    start_time = time.time()
    logging.info("脚本开始运行。")

    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        logging.error("未找到任何源 URL，脚本终止。")
        return

    url_cache = load_cache(CACHE_FILE)
    if os.path.exists(FAILED_URLS_FILE):
        try:
            os.remove(FAILED_URLS_FILE)
            logging.info(f"已清空旧的失败URL日志文件: {FAILED_URLS_FILE}")
        except OSError as e:
            logging.warning(f"清空失败URL日志文件失败: {e}")

    existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX)
    all_new_and_existing_nodes = set(existing_nodes)

    url_processing_detailed_info = {}
    url_processing_summary = defaultdict(int)

    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS_LIMIT)
    url_queue = asyncio.Queue()
    visited_urls = set() # Keep track of all URLs that have been added to the queue or processed

    # Initialize queue with source URLs
    for url in source_urls:
        if url not in visited_urls:
            await url_queue.put((url, 0)) # (url, depth)
            visited_urls.add(url)


    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT, http2=True) as client:
        processed_tasks_count = 0
        while not url_queue.empty():
            current_url, current_depth = await url_queue.get()

            # Skip if already processed in this run (can happen if added multiple times from different sources)
            # This check is less critical now due to `visited_urls` but good for robustness
            if current_url in url_processing_detailed_info: # If already processed in this main run
                 logging.debug(f"跳过已在当前运行中处理的URL: {current_url}")
                 continue

            try:
                processed_url, node_count, updated_cache_meta, extracted_nodes_list, status, new_urls_to_follow = \
                    await process_single_url(current_url, current_depth, url_cache, client)
                
                # Update url_cache with the meta-data returned, even if fetch failed or skipped
                if updated_cache_meta:
                    url_cache[processed_url] = updated_cache_meta
                    url_processing_detailed_info[processed_url] = {
                        'count': node_count, 
                        'status': status, 
                        'last_updated_timestamp': updated_cache_meta.get('last_updated_timestamp', 'N/A')
                    }
                else: # Fallback for cases where updated_cache_meta is None (e.g., fetch failed completely)
                    url_cache[processed_url] = {
                        'node_count': 0, 
                        'status': status, 
                        'content_hash': None, 
                        'etag': None, 
                        'last_modified': None, 
                        'content_type': 'unknown',
                        'last_updated_timestamp': url_cache.get(processed_url, {}).get('last_updated_timestamp', 'N/A') # Keep previous timestamp if available
                    }
                    url_processing_detailed_info[processed_url] = {
                        'count': 0, 
                        'status': status, 
                        'last_updated_timestamp': url_cache.get(processed_url, {}).get('last_updated_timestamp', 'N/A')
                    }

                url_processing_summary[status] += 1

                if extracted_nodes_list:
                    all_new_and_existing_nodes.update(extracted_nodes_list)

                # Add new URLs found to the queue for further processing if within depth limit
                if new_urls_to_follow and current_depth < MAX_RECURSION_DEPTH:
                    for new_url in new_urls_to_follow:
                        if new_url not in visited_urls:
                            await url_queue.put((new_url, current_depth + 1))
                            visited_urls.add(new_url) # Mark as visited/queued
                            logging.info(f"发现新URL加入队列: {new_url} (深度: {current_depth + 1})")

                processed_tasks_count += 1
                if processed_tasks_count % CACHE_SAVE_INTERVAL == 0:
                    save_cache(CACHE_FILE, url_cache)
                    logging.info(f"已处理 {processed_tasks_count} 个URL，阶段性保存缓存。")

            except Exception as exc: # 捕获单个任务中的所有意外异常
                logging.error(f'处理 {current_url} 时发生意外异常 (主循环): {exc}', exc_info=True)
                # 即使发生异常，也尝试更新或记录该URL的状态
                url_cache[current_url] = { # 更新缓存，标记为异常状态
                    'node_count': url_cache.get(current_url, {}).get('node_count', 0), # 保持之前的节点数量
                    'status': "UNEXPECTED_MAIN_ERROR",
                    'content_hash': url_cache.get(current_url, {}).get('content_hash'),
                    'etag': url_cache.get(current_url, {}).get('etag'),
                    'last_modified': url_cache.get(current_url, {}).get('last_modified'),
                    'content_type': url_cache.get(current_url, {}).get('content_type', 'unknown'),
                    'last_updated_timestamp': url_cache.get(current_url, {}).get('last_updated_timestamp', 'N/A')
                }
                url_processing_detailed_info[current_url] = {
                    'count': url_cache.get(current_url, {}).get('node_count', 0), 
                    'status': "UNEXPECTED_MAIN_ERROR",
                    'last_updated_timestamp': url_cache.get(current_url, {}).get('last_updated_timestamp', 'N/A')
                }
                url_processing_summary["UNEXPECTED_MAIN_ERROR"] += 1
                log_failed_url(current_url, f"意外主循环异常: {exc}")
                # Save cache immediately on error for robustness
                save_cache(CACHE_FILE, url_cache) 

    # 脚本结束时，保存最终缓存和统计信息
    save_cache(CACHE_FILE, url_cache) # 确保所有任务完成后保存一次缓存

    logging.info("\n--- 处理完成报告 ---")
    logging.info(f"总共尝试处理 {processed_tasks_count} 个URL (包含递归抓取)。")
    logging.info(f"状态统计:")
    for status, count in sorted(url_processing_summary.items()):
        logging.info(f"  {status}: {count} 个")

    final_nodes_list = sorted(list(all_new_and_existing_nodes))
    logging.info(f"总共收集到 {len(final_nodes_list)} 个去重后的节点 (含原有节点)。")

    save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_processing_detailed_info)
    save_cache(CACHE_FILE, url_cache)

    end_time = time.time()
    logging.info(f"\n总耗时: {end_time - start_time:.2f} 秒。")
    if any(status.startswith("FETCH_FAILED") or status.startswith("UNEXPECTED_") or status.startswith("PARSE_NO_NODES") for status in url_processing_summary.keys()):
        logging.info(f"\n请检查 {FAILED_URLS_FILE} 文件查看失败的URL详情。")

if __name__ == "__main__":
    asyncio.run(main())
