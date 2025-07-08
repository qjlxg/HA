import requests
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

# --- 日志配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 忽略 InsecureRequestWarning 警告
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- 配置部分 ---
DATA_DIR = "data"
SOURCES_FILE = "sources.list"
NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, "proxy_nodes_")
MAX_NODES_PER_SLICE = 2000

NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")
FAILED_URLS_FILE = os.path.join(DATA_DIR, "failed_urls.log")

MAX_WORKERS = 25 # 进一步增加并发量，考虑系统资源
REQUEST_TIMEOUT = 15 # 单次请求超时时间，单位秒，可适当延长
RETRY_ATTEMPTS = 5 # 请求重试次数
CACHE_SAVE_INTERVAL = 20 # 每处理 N 个 URL 保存一次缓存

# 代理配置 (可选)
PROXIES = None # 默认不使用代理
# PROXIES = {
#     "http://": "http://user:pass@host:port",
#     "https://": "http://user:pass@host:port",
# }

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义支持的节点协议正则表达式
# 注意：这些正则主要用于从原始文本中“抓取”，而不是结构化解析后的生成
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# 匹配 Base64 字符串的正则表达式 (至少 20 个字符，排除常见URL字符，提高准确性)
# 后面可能跟 '=' 填充，或者在 Base64 URL Safe 中没有 '='
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
    if not isinstance(data, str) or not data.strip():
        return None

    current_decoded_str = data
    for _ in range(5): # 最多递归5层，防止无限循环
        try:
            # 尝试 Base64 URL Safe 解码
            decoded_bytes = base64.urlsafe_b64decode(current_decoded_str + '==')
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')

            # 如果解码后内容与原内容相同或为空，停止
            if not temp_decoded or temp_decoded == current_decoded_str:
                break
            current_decoded_str = temp_decoded

            # 快速检查解码后内容是否仍像 Base64
            if not BASE64_REGEX.fullmatch(current_decoded_str):
                break # 如果解码后不再是纯粹的Base64，则停止递归
        except (base64.binascii.Error, UnicodeDecodeError):
            # 尝试标准 Base64 解码
            try:
                decoded_bytes = base64.b64decode(current_decoded_str + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded_str:
                    break
                current_decoded_str = temp_decoded
                if not BASE64_REGEX.fullmatch(current_decoded_str):
                    break
            except (base64.binascii.Error, UnicodeDecodeError):
                break # 无法解码，停止
        except Exception as e:
            logging.debug(f"递归Base64解码中发生未知错误: {e}")
            break
    return current_decoded_str

def fetch_content(url: str, retries: int = RETRY_ATTEMPTS, cache_data: dict = None) -> tuple[str | None, dict | None, str]:
    """
    尝试通过 HTTP 或 HTTPS 获取网页内容，并包含重试机制。
    返回 content, new_cache_meta, 和一个指示成功或失败原因的状态字符串。
    使用 httpx 库以支持 HTTP/2。
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
        # 对于裸域名或IP地址，尝试HTTP和HTTPS
        test_urls.append(f"http://{url}")
        test_urls.append(f"https://{url}")
    else:
        test_urls.append(url)

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                with httpx.Client(proxies=PROXIES, verify=False, timeout=REQUEST_TIMEOUT, http2=True) as client:
                    response = client.get(current_url_to_test, headers=current_headers, follow_redirects=True)

                if response.status_code == 304:
                    logging.info(f"  {url} 内容未修改 (304)。")
                    # 返回缓存中的 content_hash 以便在 parse_content 中进行二次检查
                    cached_content_hash = cache_data.get('content_hash')
                    return None, {'etag': cache_data.get('etag'), 'last_modified': cache_data.get('last_modified'), 'content_hash': cached_content_hash, 'content_type': cache_data.get('content_type')}, "SKIPPED_UNCHANGED"

                response.raise_for_status() # 对 4xx/5xx 状态码抛出异常

                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                content_type = response.headers.get('Content-Type', '').lower()

                # 为了更精确的去重，也保存内容的 SHA256 哈希
                content_hash = hashlib.sha256(response.content).hexdigest()

                # 如果内容哈希与缓存中的哈希一致，也视为未修改，避免重复解析
                if cache_data and cache_data.get('content_hash') == content_hash:
                    logging.info(f"  {url} 内容哈希未修改，跳过解析。")
                    return None, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "SKIPPED_UNCHANGED"

                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "FETCH_SUCCESS"

            except httpx.TimeoutException:
                logging.warning(f"  {url} 请求超时 (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_TIMEOUT"
            except httpx.HTTPStatusError as e:
                logging.warning(f"  {url} HTTP错误 ({e.response.status_code} {e.response.reason}) (尝试 {attempt + 1}/{retries})。")
                status_reason = f"FETCH_FAILED_HTTP_{e.response.status_code}"
            except httpx.ConnectError as e:
                logging.warning(f"  {url} 连接错误 ({e}) (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_CONNECTION_ERROR"
            except httpx.RequestError as e: # 捕获更通用的 httpx 请求错误
                logging.warning(f"  {url} httpx请求失败 ({e}) (尝试 {attempt + 1}/{retries})。")
                status_reason = "FETCH_FAILED_REQUEST_ERROR"
            except Exception as e:
                logging.error(f"  {url} 意外错误: {e} (尝试 {attempt + 1}/{retries})。", exc_info=True) # 打印详细栈追踪
                status_reason = "FETCH_FAILED_UNEXPECTED_ERROR"

        if attempt < retries - 1:
            time.sleep(2 ** attempt + 1) # 指数退避

    logging.error(f"  {url} 所有 {retries} 次尝试均失败。")
    log_failed_url(url, status_reason)
    return None, None, status_reason

def standardize_node_url(node_url: str) -> str:
    """
    标准化节点链接的查询参数和部分结构，以便更精确地去重。
    返回一个规范化的字符串表示。
    """
    if not isinstance(node_url, str):
        return ""

    parsed = urlparse(node_url)

    # 1. 对查询参数进行排序
    if parsed.query:
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        # 将字典转换为有序的列表，然后重新编码
        sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
        encoded_query = urlencode(sorted_params, doseq=True)
        parsed = parsed._replace(query=encoded_query)

    # 2. 对部分协议的特定字段进行规范化 (例如 vmess 的 JSON 结构)
    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = parsed.netloc # 对于 vmess:// 协议， netloc 部分就是 Base64 编码
            decoded_b64_content = decode_base64_recursive(b64_content) # 确保解码
            if decoded_b64_content:
                vmess_json = json.loads(decoded_b64_content)
                # 对 VMess JSON 字段进行排序，保证哈希一致性
                # 确保所有 key 都是字符串，防止非字符串 key 导致排序失败
                sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                # 重新编码以获取规范化 Base64
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                return f"vmess://{normalized_b64}"
        except Exception as e:
            logging.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
            # 如果标准化失败，返回原始 URL，但会影响去重效果
            return node_url

    return parsed.geturl()

def is_valid_node(node_url: str) -> bool:
    """
    检查节点 URL 的基本有效性。
    此函数现在只检查协议和基本结构，具体内容交由 convert_dict_to_node_link 或后续连接测试。
    """
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False

    # 检查是否包含任何已知协议前缀
    found_protocol = False
    for proto in NODE_PATTERNS.keys():
        if node_url.lower().startswith(f"{proto}://"):
            found_protocol = True
            break
    if not found_protocol:
        return False

    # 进一步检查 URL 的结构，排除明显无效的链接
    # 对于 ss/ssr/vmess，host和port可能在base64中，但trojan/vless/hysteria2通常需要明确的host
    parsed_url = urlparse(node_url)
    if parsed_url.scheme not in ["ss", "ssr", "vmess"]: # 这些协议的host可能被编码
        if not parsed_url.hostname:
            return False
        if parsed_url.port and not (1 <= parsed_url.port <= 65535):
            return False
    elif parsed_url.scheme == "vmess":
        try:
            # 尝试解码并解析VMess，确保其内部结构基本完整
            b64_content = parsed_url.netloc
            decoded = decode_base64_recursive(b64_content)
            if not decoded: return False
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
    尝试将字典形式的节点数据转换为标准节点链接。
    用于处理从 JSON 或 YAML 中解析出的结构化节点数据。
    """
    node_type = node_dict.get('type', '').lower()

    # 统一字段名，优先 Clash 或通用，然后 V2RayN
    server = node_dict.get('server') or node_dict.get('add')
    port = node_dict.get('port')
    password = node_dict.get('password')
    uuid = node_dict.get('uuid') or node_dict.get('id')
    name = node_dict.get('name') or node_dict.get('ps', '') # 节点名称/备注

    # 端口号必须是整数且在有效范围内
    try:
        port = int(port) if port is not None else None
        if port and not (1 <= port <= 65535):
            logging.debug(f"无效端口号: {port} for node {name}")
            return None
    except (ValueError, TypeError):
        logging.debug(f"端口号非整数: {port} for node {name}")
        return None

    if not (server and port):
        return None # 缺少基本信息

    if node_type == 'vmess':
        vmess_obj = {
            "v": node_dict.get('v', '2'),
            "ps": name,
            "add": server,
            "port": port,
            "id": uuid,
            "aid": int(node_dict.get('alterId', node_dict.get('aid', 0))),
            "net": node_dict.get('network', node_dict.get('net', 'tcp')),
            "type": node_dict.get('type', 'none'), # http, none, srtp, quic, ....
            "host": node_dict.get('udp', node_dict.get('host', '')),
            "path": node_dict.get('path', ''),
            "tls": "tls" if node_dict.get('tls') else "none",
            "sni": node_dict.get('servername', node_dict.get('sni', '')),
            "scy": node_dict.get('cipher', ''), # security
            "fp": node_dict.get('fingerprint', '') # fingerprint
        }
        # 移除空值或默认值，使JSON更紧凑
        vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]}
        try:
            # 使用 separators=(',', ':') 移除空格，使 JSON 更紧凑，便于标准化 Base64
            # 排序键以确保一致性
            sorted_vmess_obj = dict(sorted(vmess_obj.items()))
            return f"vmess://{base64.b64encode(json.dumps(sorted_vmess_obj, separators=(',', ':')).encode('utf-8')).decode('utf-8')}"
        except Exception as e:
            logging.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}")
            return None

    elif node_type == 'vless':
        if not uuid: return None
        vless_link = f"vless://{uuid}@{server}:{port}"
        params = {}
        if node_dict.get('security'): params['security'] = node_dict['security'] # tls/reality
        elif node_dict.get('tls'): params['security'] = 'tls'

        if node_dict.get('flow'): params['flow'] = node_dict['flow']
        if node_dict.get('network'): params['type'] = node_dict['network'] # ws, grpc
        if node_dict.get('path'): params['path'] = node_dict['path']
        if node_dict.get('host'): params['host'] = node_dict['host']
        if node_dict.get('servername'): params['sni'] = node_dict['servername']
        if node_dict.get('alpn'): params['alpn'] = node_dict['alpn']
        if node_dict.get('publicKey'): params['pbk'] = node_dict['publicKey'] # XTLS-reality
        if node_dict.get('shortId'): params['sid'] = node_dict['shortId']
        if node_dict.get('fingerprint'): params['fp'] = node_dict['fingerprint']
        if node_dict.get('serviceName'): params['serviceName'] = node_dict['serviceName'] # grpc
        if node_dict.get('mode'): params['mode'] = node_dict['mode'] # grpc

        if name: params['remarks'] = name # VLESS 名称通常作为 remarks

        # 移除空值或默认值
        params = {k: v for k, v in params.items() if v not in ['', None]}

        if params:
            # doseq=True 处理列表参数 (如 alpn)，排序以规范化
            sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
            vless_link += "?" + urlencode(sorted_params, doseq=True)
        return vless_link

    elif node_type == 'trojan':
        if not password: return None
        trojan_link = f"trojan://{password}@{server}:{port}"
        params = {}
        if node_dict.get('security'): params['security'] = node_dict['security'] # tls
        elif node_dict.get('tls'): params['security'] = 'tls'

        if node_dict.get('network'): params['type'] = node_dict['network']
        if node_dict.get('path'): params['path'] = node_dict['path']
        if node_dict.get('host'): params['host'] = node_dict['host']
        if node_dict.get('servername'): params['sni'] = node_dict['servername']
        if node_dict.get('alpn'): params['alpn'] = node_dict['alpn']
        if node_dict.get('fingerprint'): params['fp'] = node_dict['fingerprint']
        if node_dict.get('flow'): params['flow'] = node_dict['flow']

        if name: params['remarks'] = name

        params = {k: v for k, v in params.items() if v not in ['', None]}

        if params:
            sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
            trojan_link += "?" + urlencode(sorted_params, doseq=True)
        return trojan_link

    elif node_type == 'ss':
        if not password or not node_dict.get('cipher'): return None
        method_pwd = f"{node_dict['cipher']}:{password}"
        encoded_method_pwd = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')

        ss_link = f"ss://{encoded_method_pwd}@{server}:{port}"
        if name:
            ss_link += f"#{name}" # Shadowsocks 名称通常在 # 之后
        return ss_link

    elif node_type == 'hysteria2':
        if not password: return None
        params = {'password': password}
        if node_dict.get('obfs'): params['obfs'] = node_dict['obfs']
        if node_dict.get('obfs-password'): params['obfs-password'] = node_dict['obfs-password']

        # 常见 Hysteria2 参数
        for key in ['up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open', 'ca', 'recv_window_conn', 'recv_window_client', 'disable_mtu_discovery']:
            if node_dict.get(key) is not None and node_dict.get(key) != '': # 检查是否存在且不为 None 或空字符串
                params[key.replace('_', '-')] = node_dict[key] # 替换 '_' 为 '-'

        params = {k: v for k, v in params.items() if v not in ['', None]}

        query_string = urlencode(sorted(params.items()), doseq=True) # 排序参数以规范化

        hysteria2_link = f"hysteria2://{server}:{port}"
        if name:
             hysteria2_link += f"/{name}" # Hysteria2 名称通常在端口后
        if query_string:
            hysteria2_link += f"?{query_string}"

        return hysteria2_link

    return None

def parse_content(content: str, content_type_hint: str = "unknown") -> str:
    """
    智能解析内容，尝试通过 Content-Type 提示，然后回退到内容嗅探。
    返回一个包含所有可能节点链接的拼接文本字符串。
    """
    if not content:
        return ""

    combined_text_for_regex = []

    # --- 1. Content-Type 驱动的解析 ---
    # 尝试 JSON
    if "json" in content_type_hint or content.strip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(content)
            logging.info("内容被识别为 JSON 格式。")
            nodes_from_json = extract_nodes_from_json(parsed_json)
            if nodes_from_json: # 如果成功从JSON中提取
                # 将结构化提取的节点直接添加，无需再进行正则匹配
                combined_text_for_regex.extend(nodes_from_json)
                # 同时也把原始JSON内容作为文本，以防有内嵌的未结构化节点
                combined_text_for_regex.append(content)
                # 跳过后续的内容嗅探，因为已经有了强力的结构化解析
                return "\n".join(list(set(combined_text_for_regex)))
        except json.JSONDecodeError:
            logging.debug("内容尝试 JSON 解析失败。")
            pass

    # 尝试 YAML
    if "yaml" in content_type_hint or content.strip().startswith(("---", "- ", "proxies:")):
        try:
            parsed_yaml = yaml.safe_load(content)
            if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml or 'outbounds' in parsed_yaml): # Sing-box outbounds
                logging.info("内容被识别为 YAML 格式。")
                nodes_from_yaml = extract_nodes_from_yaml(parsed_yaml)
                if nodes_from_yaml:
                    combined_text_for_regex.extend(nodes_from_yaml)
                    combined_text_for_regex.append(content)
                    return "\n".join(list(set(combined_text_for_regex)))
        except yaml.YAMLError:
            logging.debug("内容尝试 YAML 解析失败。")
            pass

    # 尝试 HTML
    if "html" in content_type_hint or '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower():
        logging.info("内容被识别为 HTML 格式。")
        nodes_from_html = extract_nodes_from_html(content)
        if nodes_from_html:
             combined_text_for_regex.extend(nodes_from_html)
             # HTML 中提取的通常是文本内容，所以可以直接添加到 combined_text_for_regex
             return "\n".join(list(set(combined_text_for_regex)))

    # --- 2. 回退到通用文本/Base64 嗅探 ---
    logging.info("内容尝试纯文本/Base64 嗅探。")
    # 首先尝试对整个内容进行递归 Base64 解码
    decoded_base64_full = decode_base64_recursive(content)
    if decoded_base64_full and decoded_base64_full != content:
        logging.info("内容被识别为 Base64 编码，已递归解码。")
        combined_text_for_regex.append(decoded_base64_full)

        # 尝试将解码后的内容作为 JSON/YAML 再解析一次
        try:
            temp_parsed_json = json.loads(decoded_base64_full)
            combined_text_for_regex.extend(extract_nodes_from_json(temp_parsed_json))
        except json.JSONDecodeError:
            pass

        try:
            temp_parsed_yaml = yaml.safe_load(decoded_base64_full)
            if isinstance(temp_parsed_yaml, dict) and ('proxies' in temp_parsed_yaml or 'proxy-groups' in temp_parsed_yaml or 'outbounds' in temp_parsed_yaml):
                combined_text_for_regex.extend(extract_nodes_from_yaml(temp_parsed_yaml))
        except yaml.YAMLError:
            pass

    # 最后，将原始内容（如果没被完全解码）或解码后的内容作为纯文本加入，并尝试从其中提取 Base64 字符串
    combined_text_for_regex.append(content)

    # 从所有收集到的文本中，用正则匹配潜在的 Base64 块并解码
    all_text_to_scan = "\n".join(combined_text_for_regex) # 聚合所有文本
    potential_base64_matches = BASE64_REGEX.findall(all_text_to_scan)
    for b64_match in potential_base64_matches:
        if len(b64_match) > 30 and '=' in b64_match: # 避免解码太短的随机字符串和非Base64字符串
            decoded_b64_in_text = decode_base64_recursive(b64_match)
            if decoded_b64_in_text and decoded_b64_in_text != b64_match:
                combined_text_for_regex.append(decoded_b64_in_text)

    # 去重并返回
    return "\n".join(list(set(combined_text_for_regex)))

def extract_nodes_from_json(parsed_json: dict | list) -> list[str]:
    """从已解析的 JSON 对象中提取节点链接。"""
    nodes = []
    if isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, str):
                nodes.append(item)
            elif isinstance(item, dict):
                node_link = convert_dict_to_node_link(item)
                if node_link:
                    nodes.append(node_link)
    elif isinstance(parsed_json, dict):
        # 优先处理Clash/Sing-box风格的 proxies/outbounds 列表
        if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list):
            for proxy in parsed_json['proxies']:
                if isinstance(proxy, dict):
                    node_link = convert_dict_to_node_link(proxy)
                    if node_link: nodes.append(node_link)
        if 'outbounds' in parsed_json and isinstance(parsed_json['outbounds'], list): # Sing-box
             for outbound in parsed_json['outbounds']:
                if isinstance(outbound, dict):
                    node_link = convert_dict_to_node_link(outbound)
                    if node_link: nodes.append(node_link)

        # 遍历字典中的所有字符串值和列表值，深度搜索
        for key, value in parsed_json.items():
            if isinstance(value, str):
                nodes.append(value)
                # 尝试递归解码字段值中的 Base64 字符串
                decoded_value = decode_base64_recursive(value)
                if decoded_value and decoded_value != value:
                    nodes.append(decoded_value)
            elif isinstance(value, list):
                for list_item in value:
                    if isinstance(list_item, str):
                        nodes.append(list_item)
                        decoded_list_item = decode_base64_recursive(list_item)
                        if decoded_list_item and decoded_list_item != list_item:
                            nodes.append(decoded_list_item)
                    elif isinstance(list_item, dict):
                        node_link = convert_dict_to_node_link(list_item)
                        if node_link:
                            nodes.append(node_link)
    return nodes

def extract_nodes_from_yaml(parsed_yaml: dict) -> list[str]:
    """从已解析的 YAML 对象中提取节点链接。"""
    nodes = []
    # Clash/Sing-box style proxies
    if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
        for proxy in parsed_yaml['proxies']:
            if isinstance(proxy, dict) and 'type' in proxy:
                node_link = convert_dict_to_node_link(proxy)
                if node_link:
                    nodes.append(node_link)
    # Sing-box style outbounds
    if 'outbounds' in parsed_yaml and isinstance(parsed_yaml['outbounds'], list):
        for outbound in parsed_yaml['outbounds']:
            if isinstance(outbound, dict) and 'type' in outbound:
                node_link = convert_dict_to_node_link(outbound)
                if node_link:
                    nodes.append(node_link)

    # 递归搜索所有字符串，以防有未在代理列表中但被编码的节点
    def search_for_b64_in_yaml_values(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    decoded_value = decode_base64_recursive(v)
                    if decoded_value and decoded_value != v:
                        nodes.append(decoded_value)
                elif isinstance(v, (dict, list)):
                    search_for_b64_in_yaml_values(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    decoded_value = decode_base64_recursive(item)
                    if decoded_value and decoded_value != item:
                        nodes.append(decoded_value)
                elif isinstance(item, (dict, list)):
                    search_for_b64_in_yaml_values(item)
    search_for_b64_in_yaml_values(parsed_yaml)

    return nodes

def extract_nodes_from_html(html_content: str) -> list[str]:
    """从 HTML 内容中提取节点链接。"""
    nodes = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # 优先从 pre, code, textarea, script 标签中提取文本或可能的节点
    # 增加对 style 标签的考虑，有时会有内联的 base64
    potential_node_containers = soup.find_all(['pre', 'code', 'textarea', 'script', 'style'])
    for tag in potential_node_containers:
        extracted_text = tag.get_text(separator="\n", strip=True)
        if extracted_text:
            nodes.append(extracted_text)
            # 尝试从 script 或 style 标签中提取 Base64 字符串
            if tag.name in ['script', 'style']:
                potential_base64_matches = BASE64_REGEX.findall(extracted_text)
                for b64_match in potential_base64_matches:
                    if len(b64_match) > 30 and '=' in b64_match:
                        decoded_b64_in_text = decode_base64_recursive(b64_match)
                        if decoded_b64_in_text and decoded_b64_in_text != b64_match:
                            nodes.append(decoded_b64_in_text)

    # 其次，提取整个 body 的文本内容，并检查是否可能包含节点
    if soup.body:
        body_text = soup.body.get_text(separator="\n", strip=True)
        # 只有当文本内容足够长或者已经包含某种节点模式时才添加，避免大量无用文本
        if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()):
            if body_text:
                nodes.append(body_text)
                # 尝试从 body 文本中提取 Base64 字符串
                potential_base64_matches = BASE64_REGEX.findall(body_text)
                for b64_match in potential_base64_matches:
                    if len(b64_match) > 30 and '=' in b64_match:
                        decoded_b64_in_text = decode_base64_recursive(b64_match)
                        if decoded_b64_in_text and decoded_b64_in_text != b64_match:
                            nodes.append(decoded_b64_in_text)
    return nodes


def extract_and_validate_nodes(content: str) -> list[str]:
    """
    从解析后的内容中提取并验证所有支持格式的节点 URL。
    会进行最终的节点 URL 规范化。
    """
    if not content:
        return []

    found_nodes = set()

    for pattern_name, pattern_regex in NODE_PATTERNS.items():
        matches = pattern_regex.findall(content)
        for match in matches:
            decoded_match = unquote(match).strip()

            # 对节点链接进行标准化
            normalized_node = standardize_node_url(decoded_match)

            if is_valid_node(normalized_node):
                found_nodes.add(normalized_node)

    return list(found_nodes)

def load_existing_nodes_from_slices(directory: str, prefix: str) -> set[str]:
    """从多个切片文件中加载已存在的节点列表，并进行标准化处理。"""
    existing_nodes = set()
    loaded_count = 0
    # 确保只加载符合命名规则的文件
    for filename in os.listdir(directory):
        if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(' = ', 1)
                        if len(parts) == 2:
                            node_url = parts[1].strip()
                            # 对加载的现有节点进行标准化，以匹配新的去重逻辑
                            standardized_node = standardize_node_url(node_url)
                            existing_nodes.add(standardized_node)
                            loaded_count += 1
            except Exception as e:
                logging.warning(f"加载现有节点文件失败 ({file_path}): {e}")
    logging.info(f"已从 {len([f for f in os.listdir(directory) if f.startswith(os.path.basename(prefix)) and f.endswith('.txt')])} 个切片文件中加载 {loaded_count} 个现有节点。")
    return existing_nodes

def save_nodes_to_sliced_files(output_prefix: str, nodes: list[str], max_nodes_per_slice: int) -> None:
    """将处理后的节点切片保存到多个文本文件，并进行升序自定义命名"""
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
    nodes.sort() # 确保 nodes 是排序的，以保证切片文件的内容一致性
    for i in range(num_slices):
        start_index = i * max_nodes_per_slice
        end_index = min((i + 1) * max_nodes_per_slice, total_nodes)

        slice_nodes = nodes[start_index:end_index]
        slice_file_name = f"{output_prefix}{i+1:03d}.txt"

        try:
            with open(slice_file_name, 'w', encoding='utf-8') as f:
                for j, node in enumerate(slice_nodes):
                    global_index = start_index + j
                    f.write(f"Proxy-{global_index+1:05d} = {node}\n")
            logging.info(f"已保存切片文件: {slice_file_name} (包含 {len(slice_nodes)} 个节点)")
            saved_files_count += 1
        except IOError as e:
            logging.error(f"保存切片文件失败 ({slice_file_name}): {e}")

    logging.info(f"最终节点列表已切片保存到 {saved_files_count} 个文件。")

def save_node_counts_to_csv(file_path: str, counts_data: dict) -> None:
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source URL", "Node Count", "Processing Status"])
            for url in sorted(counts_data.keys()):
                item = counts_data[url]
                writer.writerow([url, item['count'], item['status']])
        logging.info(f"节点数量统计已保存到 {file_path}")
    except IOError as e:
        logging.error(f"保存节点数量统计CSV失败: {e}")

# --- 主逻辑 ---

def process_single_url(url: str, url_cache_data: dict) -> tuple[str, int, dict, list[str], str]:
    """处理单个URL的逻辑，返回 URL, 节点数量, 更新的缓存元数据, 提取到的节点列表, 处理状态。"""
    logging.info(f"开始处理 URL: {url}")
    # 传递 cache_data[url] 的副本给 fetch_content，防止并发修改
    content, new_cache_meta, fetch_status = fetch_content(url, cache_data=url_cache_data.get(url, {}).copy())

    if fetch_status == "SKIPPED_UNCHANGED":
        # 对于未更改的 URL，从缓存中获取之前的节点数量和状态
        cached_info = url_cache_data.get(url, {'node_count': 0, 'status': 'UNKNOWN'})
        # 返回缓存中的节点数量，但实际节点列表为空，因为没有重新解析
        return url, cached_info.get('node_count', 0), new_cache_meta, [], fetch_status

    if fetch_status != "FETCH_SUCCESS":
        # 对于抓取失败的 URL，节点数量为 0，并返回具体失败状态
        return url, 0, None, [], fetch_status

    parsed_content_text = parse_content(content, new_cache_meta.get('content_type', 'unknown'))
    nodes_from_url = extract_and_validate_nodes(parsed_content_text)

    logging.info(f"从 {url} 提取到 {len(nodes_from_url)} 个有效节点。")

    # 更新缓存元数据
    if new_cache_meta:
        new_cache_meta['node_count'] = len(nodes_from_url)
        # 如果是成功抓取但无节点，也更新状态
        if len(nodes_from_url) == 0:
            new_cache_meta['status'] = "PARSE_NO_NODES"
        else:
            new_cache_meta['status'] = "PARSE_SUCCESS"
    else: # 理论上不会发生，因为 fetch_content 成功会返回 meta
        new_cache_meta = url_cache_data.get(url, {}) # 获取旧的，然后更新
        new_cache_meta['node_count'] = len(nodes_from_url)
        new_cache_meta['status'] = "PARSE_NO_NODES" if len(nodes_from_url) == 0 else "PARSE_SUCCESS"

    return url, len(nodes_from_url), new_cache_meta, nodes_from_url, new_cache_meta['status']


def main():
    start_time = time.time()
    logging.info("脚本开始运行。")

    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        logging.error("未找到任何源 URL，脚本终止。")
        return

    url_cache = load_cache(CACHE_FILE)
    # 清理旧的失败URL日志
    if os.path.exists(FAILED_URLS_FILE):
        try:
            os.remove(FAILED_URLS_FILE)
            logging.info(f"已清空旧的失败URL日志文件: {FAILED_URLS_FILE}")
        except OSError as e:
            logging.warning(f"清空失败URL日志文件失败: {e}")

    # 加载现有节点时就进行标准化，保证去重逻辑一致
    existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX)
    all_new_and_existing_nodes = set(existing_nodes) # 使用 set 进行去重

    url_processing_detailed_info = {} # 存储 {url: {'count': N, 'status': '...'}, ...}
    url_processing_summary = defaultdict(int) # 统计状态

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(process_single_url, url, url_cache): url for url in source_urls}

        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                processed_url, node_count, updated_cache_meta, extracted_nodes_list, status = future.result()

                url_processing_detailed_info[processed_url] = {'count': node_count, 'status': status}
                url_processing_summary[status] += 1

                if extracted_nodes_list:
                    all_new_and_existing_nodes.update(extracted_nodes_list)

                # 更新缓存
                if updated_cache_meta:
                    url_cache[processed_url] = updated_cache_meta
                elif status == "SKIPPED_UNCHANGED":
                    # 对于跳过的URL，确保缓存中的节点计数和状态正确
                    if processed_url not in url_cache: # 理论上不会发生，但以防万一
                        url_cache[processed_url] = {'node_count': node_count, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'}
                    else:
                        url_cache[processed_url]['node_count'] = node_count
                        url_cache[processed_url]['status'] = status
                else: # 抓取失败，但不是跳过未修改的情况，需要更新状态
                     if processed_url not in url_cache:
                         url_cache[processed_url] = {'node_count': 0, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'}
                     else:
                         url_cache[processed_url]['status'] = status
                         url_cache[processed_url]['node_count'] = 0 # 失败的节点计数为0

                if (i + 1) % CACHE_SAVE_INTERVAL == 0:
                    save_cache(CACHE_FILE, url_cache)
                    logging.info(f"已处理 {i + 1} 个URL，阶段性保存缓存。")

            except Exception as exc:
                logging.error(f'{url} 生成了一个意外异常 (主循环): {exc}', exc_info=True)
                url_processing_detailed_info[url] = {'count': url_cache.get(url, {}).get('node_count', 0), 'status': "UNEXPECTED_MAIN_ERROR"}
                url_processing_summary["UNEXPECTED_MAIN_ERROR"] += 1
                log_failed_url(url, f"意外主循环异常: {exc}")
                save_cache(CACHE_FILE, url_cache) # 即使出错也尝试保存缓存

    logging.info("\n--- 处理完成报告 ---")
    logging.info(f"总共尝试处理 {len(source_urls)} 个源URL。")
    logging.info(f"状态统计:")
    for status, count in sorted(url_processing_summary.items()):
        logging.info(f"  {status}: {count} 个")

    final_nodes_list = sorted(list(all_new_and_existing_nodes))
    logging.info(f"总共收集到 {len(final_nodes_list)} 个去重后的节点 (含原有节点)。")

    save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_processing_detailed_info) # 传入详细信息
    save_cache(CACHE_FILE, url_cache) # 最终保存一次缓存，确保所有更新都写入

    end_time = time.time()
    logging.info(f"\n总耗时: {end_time - start_time:.2f} 秒。")

    if any(status.startswith("FETCH_FAILED") or status.startswith("UNEXPECTED_") or status.startswith("PARSE_NO_NODES") for status in url_processing_summary.keys()):
        logging.info(f"\n请检查 {FAILED_URLS_FILE} 文件查看失败的URL详情。")

if __name__ == "__main__":
    main()
