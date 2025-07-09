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
import asyncio # 引入 asyncio
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

[cite_start]CONCURRENT_REQUESTS_LIMIT = 50 # 并发量，从 MAX_WORKERS 改为更适合异步的命名 [cite: 97]
[cite_start]REQUEST_TIMEOUT = 10  # 单次请求超时时间，单位秒 (适当增加，避免过多超时) [cite: 97]
[cite_start]RETRY_ATTEMPTS = 2  # 请求重试次数 [cite: 97]
[cite_start]CACHE_SAVE_INTERVAL = 100  # 每处理 N 个 URL 保存一次缓存 [cite: 97]

# 代理配置 (已移除，设置为 None)
[cite_start]PROXIES = None # [cite: 97]

# 确保 data 目录存在
[cite_start]os.makedirs(DATA_DIR, exist_ok=True) # [cite: 97]

# 定义支持的节点协议正则表达式
NODE_PATTERNS = {
    [cite_start]"hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE), # [cite: 98]
    [cite_start]"vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE), # [cite: 98]
    [cite_start]"trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE), # [cite: 98]
    [cite_start]"ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE), # [cite: 98]
    [cite_start]"ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE), # [cite: 98]
    [cite_start]"vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE) # [cite: 98]
}

# 匹配 Base64 字符串的正则表达式
# [cite_start]更加宽松的Base64匹配，允许更长的非标准Base64片段，因为有些内容可能只是一部分Base64编码 [cite: 98]
BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}', re.IGNORECASE) # 至少20个字符的Base64-like字符串

# 随机 User-Agent 池
USER_AGENTS = [
    [cite_start]'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', # [cite: 99]
    [cite_start]'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0', # [cite: 99]
    [cite_start]'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15', # [cite: 99]
    [cite_start]'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.56', # [cite: 99]
    [cite_start]'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36', # [cite: 99]
    [cite_start]'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1', # [cite: 99]
    [cite_start]'Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1', # [cite: 100]
    [cite_start]'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36', # [cite: 100]
]

# --- 辅助函数 ---

def read_sources(file_path: str) -> list[str]:
    """从 sources.list 文件读取所有 URL"""
    urls = []
    try:
        [cite_start]with open(file_path, 'r', encoding='utf-8') as f: # [cite: 101]
            [cite_start]for line in f: # [cite: 101]
                [cite_start]stripped_line = line.strip() # [cite: 101]
                [cite_start]if stripped_line and not stripped_line.startswith('#'): # [cite: 101]
                    [cite_start]urls.append(stripped_line) # [cite: 101]
        [cite_start]logging.info(f"成功读取 {len(urls)} 个源 URL。") # [cite: 101]
    except FileNotFoundError:
        [cite_start]logging.error(f"错误：源文件 '{file_path}' 未找到。请确保它位于脚本的同级目录。") # [cite: 101]
    [cite_start]return urls # [cite: 101]

def load_cache(cache_file: str) -> dict:
    """加载 URL 缓存"""
    [cite_start]if os.path.exists(cache_file): # [cite: 102]
        try:
            [cite_start]with open(cache_file, 'r', encoding='utf-8') as f: # [cite: 102]
                [cite_start]return json.load(f) # [cite: 102]
        except json.JSONDecodeError:
            [cite_start]logging.warning("缓存文件损坏，将重新生成。") # [cite: 102]
            return {}
    [cite_start]return {} # [cite: 102]

def save_cache(cache_file: str, cache_data: dict) -> None:
    """保存 URL 缓存"""
    try:
        [cite_start]with open(cache_file, 'w', encoding='utf-8') as f: # [cite: 103]
            [cite_start]json.dump(cache_data, f, indent=4) # [cite: 103]
    except IOError as e:
        [cite_start]logging.error(f"保存缓存文件失败: {e}") # [cite: 103]

def log_failed_url(url: str, reason: str) -> None:
    """将失败的URL及其原因记录到文件"""
    [cite_start]timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) # [cite: 103]
    try:
        [cite_start]with open(FAILED_URLS_FILE, 'a', encoding='utf-8') as f: # [cite: 103]
            [cite_start]f.write(f"[{timestamp}] {url}: {reason}\n") # [cite: 103]
    except IOError as e:
        [cite_start]logging.error(f"写入失败URL日志失败: {e}") # [cite: 103]

def decode_base64_recursive(data: str) -> str | None:
    """尝试递归解码 Base64 字符串，直到无法再解码或内容不再是 Base64。"""
    [cite_start]if not isinstance(data, str) or not data.strip() or len(data) < 20: # [cite: 104]
        [cite_start]return None # [cite: 104]

    [cite_start]current_decoded_str = data # [cite: 104]
    [cite_start]for _ in range(5):  # 最多递归5层 [cite: 104]
        try:
            # [cite_start]尝试 urlsafe 解码 [cite: 104]
            [cite_start]decoded_bytes = base64.urlsafe_b64decode(current_decoded_str + '==') # [cite: 104]
            [cite_start]temp_decoded = decoded_bytes.decode('utf-8', errors='ignore') # [cite: 104]
            [cite_start]if not temp_decoded or temp_decoded == current_decoded_str: # [cite: 105]
                break
            [cite_start]current_decoded_str = temp_decoded # [cite: 105]
            [cite_start]if not BASE64_REGEX.fullmatch(current_decoded_str): # 如果解码后不再是Base64格式，停止 [cite: 105]
                break
        [cite_start]except (base64.binascii.Error, UnicodeDecodeError): # [cite: 105]
            try:
                # [cite_start]尝试标准 Base64 解码 [cite: 106]
                [cite_start]decoded_bytes = base64.b64decode(current_decoded_str + '==') # [cite: 106]
                [cite_start]temp_decoded = decoded_bytes.decode('utf-8', errors='ignore') # [cite: 106]
                [cite_start]if not temp_decoded or temp_decoded == current_decoded_str: # [cite: 106]
                    break
                [cite_start]current_decoded_str = temp_decoded # [cite: 107]
                [cite_start]if not BASE64_REGEX.fullmatch(current_decoded_str): # [cite: 107]
                    break
            [cite_start]except (base64.binascii.Error, UnicodeDecodeError): # [cite: 107]
                break
        except Exception as e:
            [cite_start]logging.debug(f"递归Base64解码中发生未知错误: {e}") # [cite: 107]
            break
    [cite_start]return current_decoded_str # [cite: 107]

async def fetch_content(url: str, client: httpx.AsyncClient, retries: int = RETRY_ATTEMPTS, cache_data: dict = None) -> tuple[str | None, dict | None, str]:
    """
    异步尝试通过 HTTP 或 HTTPS 获取指定 URL 的内容，并包含重试机制。
    """
    [cite_start]current_user_agent = random.choice(USER_AGENTS) # [cite: 109]
    current_headers = {
        [cite_start]'User-Agent': current_user_agent, # [cite: 109]
        [cite_start]'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', # [cite: 109]
        [cite_start]'Accept-Encoding': 'gzip, deflate, br', # [cite: 109]
        [cite_start]'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7', # [cite: 109]
        [cite_start]'DNT': '1', # [cite: 109]
        [cite_start]'Connection': 'keep-alive' # [cite: 109]
    }

    [cite_start]if cache_data: # [cite: 110]
        [cite_start]if 'etag' in cache_data and cache_data['etag']: # [cite: 110]
            [cite_start]current_headers['If-None-Match'] = cache_data['etag'] # [cite: 110]
        [cite_start]if 'last_modified' in cache_data and cache_data['last_modified']: # [cite: 110]
            [cite_start]current_headers['If-Modified-Since'] = cache_data['last_modified'] # [cite: 110]

    [cite_start]test_urls = [] # [cite: 110]
    [cite_start]parsed_url = urlparse(url) # [cite: 110]
    [cite_start]if not parsed_url.scheme: # [cite: 110]
        [cite_start]test_urls.append(f"http://{url}") # [cite: 110]
        [cite_start]test_urls.append(f"https://{url}") # [cite: 110]
    else:
        [cite_start]test_urls.append(url) # [cite: 110]

    [cite_start]for attempt in range(retries): # [cite: 111]
        [cite_start]for current_url_to_test in test_urls: # [cite: 111]
            try:
                response = await client.get(current_url_to_test, headers=current_headers, follow_redirects=True) # 使用 await

                [cite_start]if response.status_code == 304: # [cite: 112]
                    [cite_start]logging.info(f"  {url} 内容未修改 (304)。") # [cite: 112]
                    [cite_start]cached_content_hash = cache_data.get('content_hash') # [cite: 112]
                    [cite_start]return None, {'etag': cache_data.get('etag'), 'last_modified': cache_data.get('last_modified'), 'content_hash': cached_content_hash, 'content_type': cache_data.get('content_type')}, "SKIPPED_UNCHANGED" # [cite: 112]

                [cite_start]response.raise_for_status() # [cite: 112]

                [cite_start]new_etag = response.headers.get('ETag') # [cite: 113]
                [cite_start]new_last_modified = response.headers.get('Last-Modified') # [cite: 113]
                [cite_start]content_type = response.headers.get('Content-Type', '').lower() # [cite: 113]
                [cite_start]content_hash = hashlib.sha256(response.content).hexdigest() # [cite: 113]

                [cite_start]if cache_data and cache_data.get('content_hash') == content_hash: # [cite: 113]
                    [cite_start]logging.info(f"  {url} 内容哈希未修改，跳过解析。") # [cite: 114]
                    [cite_start]return None, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "SKIPPED_UNCHANGED" # [cite: 114]

                [cite_start]return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': content_hash, 'content_type': content_type}, "FETCH_SUCCESS" # [cite: 114]

            except httpx.TimeoutException:
                [cite_start]logging.warning(f"  {url} 请求超时 (尝试 {attempt + 1}/{retries})。") # [cite: 115]
                [cite_start]status_reason = "FETCH_FAILED_TIMEOUT" # [cite: 115]
            except httpx.HTTPStatusError as e:
                [cite_start]logging.warning(f"  {url} HTTP错误 ({e.response.status_code} {e.response.reason_phrase}) (尝试 {attempt + 1}/{retries})。") # [cite: 115]
                [cite_start]status_reason = f"FETCH_FAILED_HTTP_{e.response.status_code}" # [cite: 115]
            except httpx.ConnectError as e:
                [cite_start]logging.warning(f"  {url} 连接错误 ({e}) (尝试 {attempt + 1}/{retries})。") # [cite: 116]
                [cite_start]status_reason = "FETCH_FAILED_CONNECTION_ERROR" # [cite: 116]
            except httpx.RequestError as e:
                [cite_start]logging.warning(f"  {url} httpx请求失败 ({e}) (尝试 {attempt + 1}/{retries})。") # [cite: 116]
                [cite_start]status_reason = "FETCH_FAILED_REQUEST_ERROR" # [cite: 116]
            except Exception as e:
                [cite_start]logging.error(f"  {url} 意外错误: {e} (尝试 {attempt + 1}/{retries})。", exc_info=True) # [cite: 117]
                [cite_start]status_reason = "FETCH_FAILED_UNEXPECTED_ERROR" # [cite: 117]

        [cite_start]if attempt < retries - 1: # [cite: 117]
            await asyncio.sleep(2 ** attempt + 1) # 使用 asyncio.sleep 进行异步等待

    [cite_start]logging.error(f"  {url} 所有 {retries} 次尝试均失败。") # [cite: 117]
    [cite_start]log_failed_url(url, status_reason) # [cite: 117]
    [cite_start]return None, None, status_reason # [cite: 118]

def standardize_node_url(node_url: str) -> str:
    """
    标准化节点链接的查询参数和部分结构，以便更精确地去重。
    """
    [cite_start]if not isinstance(node_url, str): # [cite: 118]
        [cite_start]return "" # [cite: 118]

    [cite_start]parsed = urlparse(node_url) # [cite: 118]
    [cite_start]if parsed.query: # [cite: 118]
        [cite_start]query_params = parse_qs(parsed.query, keep_blank_values=True) # [cite: 119]
        [cite_start]sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values]) # [cite: 119]
        [cite_start]encoded_query = urlencode(sorted_params, doseq=True) # [cite: 119]
        [cite_start]parsed = parsed._replace(query=encoded_query) # [cite: 119]

    [cite_start]if node_url.lower().startswith("vmess://"): # [cite: 119]
        try:
            [cite_start]b64_content = parsed.netloc # [cite: 119]
            [cite_start]decoded_b64_content = decode_base64_recursive(b64_content) # [cite: 119]
            [cite_start]if decoded_b64_content: # [cite: 119]
                [cite_start]vmess_json = json.loads(decoded_b64_content) # [cite: 119]
                # 对 VMess 字段进行排序，保证一致性，同时考虑不同键的类型（字符串化）
                [cite_start]sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0]))) # [cite: 120]
                [cite_start]normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8') # [cite: 120]
                [cite_start]return f"vmess://{normalized_b64}" # [cite: 120]
        except Exception as e:
            [cite_start]logging.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}") # [cite: 120]
            [cite_start]return node_url # [cite: 120]

    [cite_start]return parsed.geturl() # [cite: 120]

def is_valid_hysteria2_node(node_link: str) -> bool:
    """
    校验 Hysteria2 链接是否有效。
    一个有效的 Hysteria2 链接通常至少包含：
    - 协议头: hysteria2://
    - 用户信息 (UUID 或密码) 和服务器地址:port
    这里我们要求链接中必须有 `@` 符号，且 `@` 之前的部分不为空（代表 UUID/密码），
    并且有有效的服务器地址和端口。
    """
    [cite_start]if not node_link.lower().startswith("hysteria2://"): # [cite: 121]
        [cite_start]return False # [cite: 121]

    try:
        [cite_start]parsed_url = urlparse(node_link) # [cite: 121]
    except ValueError:
        [cite_start]return False # 链接格式不正确 [cite: 121]

    # [cite_start]netloc 包含认证信息和地址:端口，例如：0c4c1a89-5645-4fc2-9e3b-ab09aa44e933@138.2.61.132:13059 [cite: 121]
    [cite_start]netloc = parsed_url.netloc # [cite: 122]

    # [cite_start]检查是否有认证信息（UUID/密码） [cite: 122]
    [cite_start]if '@' not in netloc: # [cite: 122]
        # 如果没有 @ 符号，则认为缺少认证信息，视为无效。
        [cite_start]return False # [cite: 122]

    [cite_start]auth_info, addr_port = netloc.split('@', 1) # [cite: 122]
    [cite_start]if not auth_info.strip(): # 认证信息为空 [cite: 122]
        [cite_start]return False # [cite: 122]

    # [cite_start]检查服务器地址和端口 [cite: 122]
    [cite_start]if ':' not in addr_port: # [cite: 122]
        [cite_start]return False # 缺少端口 [cite: 122]

    [cite_start]server, port_str = addr_port.rsplit(':', 1) # [cite: 122]
    [cite_start]if not server or not port_str.isdigit() or not (1 <= int(port_str) <= 65535): # [cite: 123]
        [cite_start]return False # 服务器地址为空或端口不是有效的数字 [cite: 123]

    [cite_start]return True # [cite: 123]

def is_valid_node(node_url: str) -> bool:
    """
    检查节点 URL 的基本有效性。
    """
    [cite_start]if not isinstance(node_url, str) or len(node_url) < 10: # [cite: 123]
        [cite_start]return False # [cite: 123]

    [cite_start]found_protocol = False # [cite: 123]
    [cite_start]for proto in NODE_PATTERNS.keys(): # [cite: 123]
        [cite_start]if node_url.lower().startswith(f"{proto}://"): # [cite: 123]
            [cite_start]found_protocol = True # [cite: 124]
            break
    [cite_start]if not found_protocol: # [cite: 124]
        [cite_start]return False # [cite: 124]

    [cite_start]parsed_url = urlparse(node_url) # [cite: 124]

    # [cite_start]特殊处理 Hysteria2 链接的校验 [cite: 124]
    [cite_start]if parsed_url.scheme.lower() == "hysteria2": # [cite: 124]
        [cite_start]return is_valid_hysteria2_node(node_url) # [cite: 124]

    # [cite_start]其他协议的现有校验逻辑 [cite: 124]
    [cite_start]if parsed_url.scheme not in ["ss", "ssr", "vmess"]: # [cite: 124]
        [cite_start]if not parsed_url.hostname: # [cite: 124]
            [cite_start]return False # [cite: 124]
        [cite_start]if parsed_url.port and not (1 <= parsed_url.port <= 65535): # [cite: 125]
                return False
    [cite_start]elif parsed_url.scheme == "vmess": # [cite: 125]
        try:
            [cite_start]b64_content = parsed_url.netloc # [cite: 125]
            [cite_start]decoded = decode_base64_recursive(b64_content) # [cite: 125]
            [cite_start]if not decoded: # [cite: 125]
                [cite_start]return False # [cite: 125]
            [cite_start]vmess_obj = json.loads(decoded) # [cite: 126]
            [cite_start]if not ('add' in vmess_obj and 'port' in vmess_obj and 'id' in vmess_obj): # [cite: 126]
                return False
            [cite_start]if not (1 <= int(vmess_obj['port']) <= 65535): # [cite: 126]
                return False
        except Exception:
            [cite_start]return False # [cite: 127]

    [cite_start]return True # [cite: 127]

def convert_dict_to_node_link(node_dict: dict) -> str | None:
    """
    将字典形式的节点数据转换为标准节点链接。
    """
    [cite_start]if not isinstance(node_dict, dict): # [cite: 128]
        [cite_start]return None # [cite: 128]

    [cite_start]node_type = node_dict.get('type', '').lower() # [cite: 128]
    [cite_start]server = node_dict.get('server') or node_dict.get('add') # [cite: 128]
    [cite_start]port = node_dict.get('port') # [cite: 128]
    [cite_start]password = node_dict.get('password') # [cite: 128]
    [cite_start]uuid = node_dict.get('uuid') or node_dict.get('id') # [cite: 128]
    [cite_start]name = node_dict.get('name') or node_dict.get('ps', '') # [cite: 128]

    try:
        [cite_start]port = int(port) if port is not None else None # [cite: 129]
        [cite_start]if port and not (1 <= port <= 65535): # [cite: 129]
            [cite_start]logging.debug(f"无效端口号: {port} for node {name}") # [cite: 129]
            return None
    except (ValueError, TypeError):
        [cite_start]logging.debug(f"端口号非整数: {port} for node {name}") # [cite: 129]
        return None

    [cite_start]if not (server and port): # [cite: 129]
        return None

    [cite_start]if node_type == 'vmess': # [cite: 129]
        vmess_obj = {
            [cite_start]"v": node_dict.get('v', '2'), # [cite: 130]
            [cite_start]"ps": name, # [cite: 130]
            [cite_start]"add": server, # [cite: 130]
            [cite_start]"port": port, # [cite: 130]
            [cite_start]"id": uuid, # [cite: 130]
            [cite_start]"aid": int(node_dict.get('alterId', node_dict.get('aid', 0))), # [cite: 130]
            [cite_start]"net": node_dict.get('network', node_dict.get('net', 'tcp')), # [cite: 130]
            [cite_start]"type": node_dict.get('type', 'none'), # [cite: 131]
            [cite_start]"host": node_dict.get('udp', node_dict.get('host', '')), # [cite: 131]
            [cite_start]"path": node_dict.get('path', ''), # [cite: 131]
            [cite_start]"tls": "tls" if node_dict.get('tls') else "none", # [cite: 131]
            [cite_start]"sni": node_dict.get('servername', node_dict.get('sni', '')), # [cite: 131]
            [cite_start]"scy": node_dict.get('cipher', ''), # [cite: 131]
            [cite_start]"fp": node_dict.get('fingerprint', '') # [cite: 131]
        }
        [cite_start]vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]} # [cite: 132]
        try:
            [cite_start]sorted_vmess_obj = dict(sorted(vmess_obj.items())) # [cite: 132]
            [cite_start]return f"vmess://{base64.b64encode(json.dumps(sorted_vmess_obj, separators=(',', ':')).encode('utf-8')).decode('utf-8')}" # [cite: 132]
        except Exception as e:
            [cite_start]logging.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}") # [cite: 132]
            [cite_start]return None # [cite: 133]

    [cite_start]elif node_type == 'vless': # [cite: 133]
        [cite_start]if not uuid: # [cite: 133]
            return None
        [cite_start]vless_link = f"vless://{uuid}@{server}:{port}" # [cite: 133]
        [cite_start]params = {} # [cite: 133]
        [cite_start]if node_dict.get('security'): # [cite: 133]
            [cite_start]params['security'] = node_dict['security'] # [cite: 134]
        [cite_start]elif node_dict.get('tls'): # [cite: 134]
            [cite_start]params['security'] = 'tls' # [cite: 134]
        [cite_start]if node_dict.get('flow'): # [cite: 134]
            [cite_start]params['flow'] = node_dict['flow'] # [cite: 134]
        [cite_start]if node_dict.get('network'): # [cite: 134]
            [cite_start]params['type'] = node_dict['network'] # [cite: 134]
        [cite_start]if node_dict.get('path'): # [cite: 134]
            [cite_start]params['path'] = node_dict['path'] # [cite: 134]
        [cite_start]if node_dict.get('host'): # [cite: 134]
            [cite_start]params['host'] = node_dict['host'] # [cite: 135]
        [cite_start]if node_dict.get('servername'): # [cite: 135]
            [cite_start]params['sni'] = node_dict['servername'] # [cite: 135]
        [cite_start]if node_dict.get('alpn'): # [cite: 135]
            [cite_start]params['alpn'] = node_dict['alpn'] # [cite: 135]
        [cite_start]if node_dict.get('publicKey'): # [cite: 135]
            [cite_start]params['pbk'] = node_dict['publicKey'] # [cite: 135]
        [cite_start]if node_dict.get('shortId'): # [cite: 135]
            [cite_start]params['sid'] = node_dict['shortId'] # [cite: 135]
        [cite_start]if node_dict.get('fingerprint'): # [cite: 135]
            [cite_start]params['fp'] = node_dict['fingerprint'] # [cite: 136]
        [cite_start]if node_dict.get('serviceName'): # [cite: 136]
            [cite_start]params['serviceName'] = node_dict['serviceName'] # [cite: 136]
        [cite_start]if node_dict.get('mode'): # [cite: 136]
            [cite_start]params['mode'] = node_dict['mode'] # [cite: 136]
        [cite_start]if name: # [cite: 136]
            [cite_start]params['remarks'] = name # [cite: 136]

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} # [cite: 137]
        [cite_start]if params: # [cite: 137]
            [cite_start]sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])]) # [cite: 137]
            vless_link += "?" + [cite_start]urlencode(sorted_params, doseq=True) # [cite: 138]
        [cite_start]return vless_link # [cite: 138]

    [cite_start]elif node_type == 'trojan': # [cite: 138]
        [cite_start]if not password: # [cite: 138]
            return None
        [cite_start]trojan_link = f"trojan://{password}@{server}:{port}" # [cite: 138]
        [cite_start]params = {} # [cite: 138]
        [cite_start]if node_dict.get('security'): # [cite: 138]
            [cite_start]params['security'] = node_dict['security'] # [cite: 139]
        [cite_start]elif node_dict.get('tls'): # [cite: 139]
            [cite_start]params['security'] = 'tls' # [cite: 139]
        [cite_start]if node_dict.get('network'): # [cite: 139]
            [cite_start]params['type'] = node_dict['network'] # [cite: 139]
        [cite_start]if node_dict.get('path'): # [cite: 139]
            [cite_start]params['path'] = node_dict['path'] # [cite: 139]
        [cite_start]if node_dict.get('host'): # [cite: 139]
            [cite_start]params['host'] = node_dict['host'] # [cite: 139]
        [cite_start]if node_dict.get('servername'): # [cite: 139]
            [cite_start]params['sni'] = node_dict['servername'] # [cite: 139]
        [cite_start]if node_dict.get('alpn'): # [cite: 140]
            [cite_start]params['alpn'] = node_dict['alpn'] # [cite: 140]
        [cite_start]if node_dict.get('fingerprint'): # [cite: 140]
            [cite_start]params['fp'] = node_dict['fingerprint'] # [cite: 140]
        [cite_start]if node_dict.get('flow'): # [cite: 140]
            [cite_start]params['flow'] = node_dict['flow'] # [cite: 140]
        [cite_start]if name: # [cite: 140]
            [cite_start]params['remarks'] = name # [cite: 140]

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} # [cite: 141]
        [cite_start]if params: # [cite: 141]
            [cite_start]sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])]) # [cite: 141]
            trojan_link += "?" + [cite_start]urlencode(sorted_params, doseq=True) # [cite: 142]
        [cite_start]return trojan_link # [cite: 142]

    [cite_start]elif node_type == 'ss': # [cite: 142]
        [cite_start]if not password or not node_dict.get('cipher'): # [cite: 142]
            return None
        [cite_start]method_pwd = f"{node_dict['cipher']}:{password}" # [cite: 142]
        [cite_start]encoded_method_pwd = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8') # [cite: 142]
        [cite_start]ss_link = f"ss://{encoded_method_pwd}@{server}:{port}" # [cite: 142]
        [cite_start]if name: # [cite: 143]
            [cite_start]ss_link += f"#{name}" # [cite: 143]
        [cite_start]return ss_link # [cite: 143]

    [cite_start]elif node_type == 'hysteria2': # [cite: 143]
        # [cite_start]Hysteria2 协议认证信息在 host 部分 [cite: 143]
        [cite_start]auth_info = uuid if uuid else password # [cite: 143]
        [cite_start]if not auth_info: # [cite: 143]
            return None

        [cite_start]hysteria2_link_base = f"hysteria2://{auth_info}@{server}:{port}" # [cite: 144]

        [cite_start]params = {} # [cite: 144]
        # [cite_start]以下参数应该作为 URL 的 query 部分 [cite: 144]
        [cite_start]if node_dict.get('insecure') is not None: # [cite: 144]
            [cite_start]params['insecure'] = int(bool(node_dict['insecure'])) # 0 or 1 [cite: 144]
        [cite_start]if node_dict.get('obfs'): # [cite: 144]
            [cite_start]params['obfs'] = node_dict['obfs'] # [cite: 144]
        [cite_start]if node_dict.get('obfs-password'): # [cite: 144]
            [cite_start]params['obfs-password'] = node_dict['obfs-password'] # [cite: 144]
        [cite_start]if node_dict.get('sni'): # sni 字段 [cite: 144]
            [cite_start]params['sni'] = node_dict['sni'] # [cite: 145]

        # [cite_start]其他协议特定参数，需要转换为 Hysteria2 的对应名称 [cite: 145]
        [cite_start]for key in ['up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open', 'ca', 'recv_window_conn', 'recv_window_client', 'disable_mtu_discovery']: # [cite: 145]
            [cite_start]if node_dict.get(key) is not None and node_dict.get(key) != '': # [cite: 145]
                [cite_start]params[key.replace('_', '-')] = node_dict[key] # [cite: 145]

        [cite_start]params = {k: v for k, v in params.items() if v not in ['', None]} # [cite: 145]
        [cite_start]query_string = urlencode(sorted(params.items()), doseq=True) # [cite: 146]

        [cite_start]final_link = hysteria2_link_base # [cite: 146]
        [cite_start]if query_string: # [cite: 146]
            [cite_start]final_link += f"?{query_string}" # [cite: 146]

        [cite_start]if name: # [cite: 146]
            # [cite_start]节点名称通常在 # 之后，且可能需要 URL 编码 [cite: 146]
            [cite_start]final_link += f"#{urlparse(name).path.replace(' ', '%20')}" # [cite: 147]
            
        [cite_start]return final_link # [cite: 147]

    [cite_start]return None # [cite: 147]


def parse_content(content: str, content_type_hint: str = "unknown") -> str:
    """
    智能解析内容，尝试通过 Content-Type 提示，然后回退到内容嗅探。
    增加对各种潜在文本的解析尝试。
    """
    [cite_start]if not content: # [cite: 147]
        [cite_start]return "" # [cite: 147]

    [cite_start]combined_text_for_regex = [] # [cite: 147]

    # 1. 尝试 JSON 解析 (基于 Content-Type 或内容前缀)
    [cite_start]if "json" in content_type_hint or content.strip().startswith(("{", "[")): # [cite: 147]
        try:
            [cite_start]parsed_json = json.loads(content) # [cite: 148]
            [cite_start]logging.info("内容被识别为 JSON 格式。") # [cite: 148]
            [cite_start]nodes_from_json = extract_nodes_from_json(parsed_json) # [cite: 148]
            [cite_start]if nodes_from_json: # [cite: 148]
                [cite_start]combined_text_for_regex.extend(nodes_from_json) # [cite: 148]
            [cite_start]combined_text_for_regex.append(content) # 也保留原始内容以供后续正则匹配 [cite: 148]
            [cite_start]return "\n".join(list(set(combined_text_for_regex))) # [cite: 148]
        except json.JSONDecodeError:
            [cite_start]logging.debug("内容尝试 JSON 解析失败。") # [cite: 149]
            pass

    # 2. 尝试 YAML 解析 (基于 Content-Type 或内容前缀)
    [cite_start]if "yaml" in content_type_hint or content.strip().startswith(("---", "- ", "proxies:")): # [cite: 149]
        try:
            [cite_start]parsed_yaml = yaml.safe_load(content) # [cite: 149]
            [cite_start]if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml or 'outbounds' in parsed_yaml): # [cite: 150]
                [cite_start]logging.info("内容被识别为 YAML 格式。") # [cite: 150]
                [cite_start]nodes_from_yaml = extract_nodes_from_yaml(parsed_yaml) # [cite: 150]
                [cite_start]if nodes_from_yaml: # [cite: 150]
                    [cite_start]combined_text_for_regex.extend(nodes_from_yaml) # [cite: 150]
                [cite_start]combined_text_for_regex.append(content) # 也保留原始内容以供后续正则匹配 [cite: 150]
                [cite_start]return "\n".join(list(set(combined_text_for_regex))) # [cite: 150]
        except yaml.YAMLError:
            [cite_start]logging.debug("内容尝试 YAML 解析失败。") # [cite: 151]
            pass

    # 3. 尝试 HTML 解析 (基于 Content-Type 或内容前缀)
    [cite_start]if "html" in content_type_hint or '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower(): # [cite: 151]
        [cite_start]logging.info("内容被识别为 HTML 格式。") # [cite: 151]
        [cite_start]nodes_from_html = extract_nodes_from_html(content) # [cite: 151]
        [cite_start]if nodes_from_html: # [cite: 152]
            [cite_start]combined_text_for_regex.extend(nodes_from_html) # [cite: 152]
            # [cite_start]HTML 内容中可能直接包含 Base64 编码的订阅链接，需要进一步处理 [cite: 168, 169, 170, 171, 172]
            text_from_html = "\n".join(list(set(combined_text_for_regex)))
            decoded_html_base64 = decode_base64_recursive(text_from_html)
            if decoded_html_base64 and decoded_html_base64 != text_from_html:
                combined_text_for_regex.append(decoded_html_base64)
            # 在提取的文本中再次查找 Base64
            potential_base64_matches = BASE64_REGEX.findall(text_from_html)
            [cite_start]for b64_match in potential_base64_matches: # [cite: 170]
                [cite_start]if len(b64_match) > 30 and '=' in b64_match: # [cite: 171]
                    [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) # [cite: 171]
                    [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: # [cite: 171]
                        [cite_start]combined_text_for_regex.append(decoded_b64_in_text) # [cite: 172]

            return "\n".join(list(set(combined_text_for_regex)))


    # 4. 尝试纯文本/Base64 嗅探 (作为最后的回退)
    [cite_start]logging.info("内容尝试纯文本/Base64 嗅探。") # [cite: 151]
    [cite_start]decoded_base64_full = decode_base64_recursive(content) # [cite: 152]
    [cite_start]if decoded_base64_full and decoded_base64_full != content: # [cite: 152]
        [cite_start]logging.info("内容被识别为 Base64 编码，已递归解码。") # [cite: 152]
        [cite_start]combined_text_for_regex.append(decoded_base64_full) # [cite: 152]
        # 解码后尝试再次进行 JSON/YAML 解析
        try:
            [cite_start]temp_parsed_json = json.loads(decoded_base64_full) # [cite: 152]
            [cite_start]combined_text_for_regex.extend(extract_nodes_from_json(temp_parsed_json)) # [cite: 152]
        except json.JSONDecodeError:
            pass
        try:
            [cite_start]temp_parsed_yaml = yaml.safe_load(decoded_base64_full) # [cite: 153]
            [cite_start]if isinstance(temp_parsed_yaml, dict) and ('proxies' in temp_parsed_yaml or 'proxy-groups' in temp_parsed_yaml or 'outbounds' in temp_parsed_yaml): # [cite: 153]
                [cite_start]combined_text_for_regex.extend(extract_nodes_from_yaml(temp_parsed_yaml)) # [cite: 153]
        except yaml.YAMLError:
            pass

    # 遍历所有可能的文本片段，查找 Base64 编码的节点信息
    [cite_start]combined_text_for_regex.append(content) # [cite: 153]
    [cite_start]all_text_to_scan = "\n".join(list(set(combined_text_for_regex))) # [cite: 153]
    [cite_start]potential_base64_matches = BASE64_REGEX.findall(all_text_to_scan) # [cite: 153]
    [cite_start]for b64_match in potential_base64_matches: # [cite: 154]
        # [cite_start]增加对 Base64 长度和 `=` 结束符的判断，减少误判 [cite: 154]
        [cite_start]if len(b64_match) > 30 and '=' in b64_match: # [cite: 154]
            [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) # [cite: 154]
            [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: # [cite: 154]
                [cite_start]combined_text_for_regex.append(decoded_b64_in_text) # [cite: 154]

    [cite_start]return "\n".join(list(set(combined_text_for_regex))) # [cite: 154]

def extract_nodes_from_json(parsed_json: dict | list) -> list[str]:
    """从已解析的 JSON 对象中提取节点链接。"""
    [cite_start]nodes = [] # [cite: 155]
    [cite_start]if isinstance(parsed_json, list): # [cite: 155]
        [cite_start]for item in parsed_json: # [cite: 155]
            [cite_start]if isinstance(item, str): # [cite: 155]
                [cite_start]nodes.append(item) # [cite: 155]
            [cite_start]elif isinstance(item, dict): # [cite: 155]
                [cite_start]node_link = convert_dict_to_node_link(item) # [cite: 155]
                [cite_start]if node_link: # [cite: 156]
                    [cite_start]nodes.append(node_link) # [cite: 156]
    [cite_start]elif isinstance(parsed_json, dict): # [cite: 156]
        [cite_start]if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list): # [cite: 156]
            [cite_start]for proxy in parsed_json['proxies']: # [cite: 156]
                [cite_start]if isinstance(proxy, dict): # [cite: 157]
                    [cite_start]node_link = convert_dict_to_node_link(proxy) # [cite: 157]
                    [cite_start]if node_link: # [cite: 157]
                        [cite_start]nodes.append(node_link) # [cite: 157]
        [cite_start]if 'outbounds' in parsed_json and isinstance(parsed_json['outbounds'], list): # [cite: 157]
            [cite_start]for outbound in parsed_json['outbounds']: # [cite: 157]
                [cite_start]if isinstance(outbound, dict): # [cite: 158]
                    [cite_start]node_link = convert_dict_to_node_link(outbound) # [cite: 158]
                    [cite_start]if node_link: # [cite: 158]
                        [cite_start]nodes.append(node_link) # [cite: 158]
        # [cite_start]递归查找所有字符串值，尝试解码 Base64 [cite: 158]
        [cite_start]for key, value in parsed_json.items(): # [cite: 158]
            [cite_start]if isinstance(value, str): # [cite: 159]
                [cite_start]nodes.append(value) # [cite: 159]
                [cite_start]decoded_value = decode_base64_recursive(value) # [cite: 159]
                [cite_start]if decoded_value and decoded_value != value: # [cite: 159]
                    [cite_start]nodes.append(decoded_value) # [cite: 159]
            [cite_start]elif isinstance(value, list): # [cite: 159]
                [cite_start]for list_item in value: # [cite: 160]
                    [cite_start]if isinstance(list_item, str): # [cite: 160]
                        [cite_start]nodes.append(list_item) # [cite: 160]
                        [cite_start]decoded_list_item = decode_base64_recursive(list_item) # [cite: 160]
                        [cite_start]if decoded_list_item and decoded_list_item != list_item: # [cite: 161]
                            [cite_start]nodes.append(decoded_list_item) # [cite: 161]
                    [cite_start]elif isinstance(list_item, dict): # [cite: 161]
                        [cite_start]node_link = convert_dict_to_node_link(list_item) # [cite: 162]
                        [cite_start]if node_link: # [cite: 162]
                            [cite_start]nodes.append(node_link) # [cite: 162]
    [cite_start]return nodes # [cite: 162]

def extract_nodes_from_yaml(parsed_yaml: dict) -> list[str]:
    """从已解析的 YAML 对象中提取节点链接。"""
    [cite_start]nodes = [] # [cite: 162]
    [cite_start]if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list): # [cite: 162]
        [cite_start]for proxy in parsed_yaml['proxies']: # [cite: 163]
            [cite_start]if isinstance(proxy, dict) and 'type' in proxy: # [cite: 163]
                [cite_start]node_link = convert_dict_to_node_link(proxy) # [cite: 163]
                [cite_start]if node_link: # [cite: 163]
                    [cite_start]nodes.append(node_link) # [cite: 163]
    [cite_start]if 'outbounds' in parsed_yaml and isinstance(parsed_yaml['outbounds'], list): # [cite: 163]
        [cite_start]for outbound in parsed_yaml['outbounds']: # [cite: 163]
            [cite_start]if isinstance(outbound, dict) and 'type' in outbound: # [cite: 163]
                [cite_start]node_link = convert_dict_to_node_link(outbound) # [cite: 164]
                [cite_start]if node_link: # [cite: 164]
                    [cite_start]nodes.append(node_link) # [cite: 164]

    # [cite_start]递归查找所有字符串值，尝试解码 Base64 [cite: 164]
    def search_for_b64_in_yaml_values(obj):
        [cite_start]if isinstance(obj, dict): # [cite: 164]
            [cite_start]for k, v in obj.items(): # [cite: 165]
                [cite_start]if isinstance(v, str): # [cite: 165]
                    [cite_start]decoded_value = decode_base64_recursive(v) # [cite: 165]
                    [cite_start]if decoded_value and decoded_value != v: # [cite: 165]
                        [cite_start]nodes.append(decoded_value) # [cite: 165]
                [cite_start]elif isinstance(v, (dict, list)): # [cite: 165]
                    [cite_start]search_for_b64_in_yaml_values(v) # [cite: 165]
        [cite_start]elif isinstance(obj, list): # [cite: 166]
            [cite_start]for item in obj: # [cite: 166]
                [cite_start]if isinstance(item, str): # [cite: 166]
                    [cite_start]decoded_value = decode_base64_recursive(item) # [cite: 166]
                    [cite_start]if decoded_value and decoded_value != item: # [cite: 166]
                        [cite_start]nodes.append(decoded_value) # [cite: 167]
                [cite_start]elif isinstance(item, (dict, list)): # [cite: 167]
                    [cite_start]search_for_b64_in_yaml_values(item) # [cite: 167]
    [cite_start]search_for_b64_in_yaml_values(parsed_yaml) # [cite: 167]

    [cite_start]return nodes # [cite: 167]

def extract_nodes_from_html(html_content: str) -> list[str]:
    """从 HTML 内容中提取节点链接。"""
    [cite_start]nodes = [] # [cite: 167]
    [cite_start]soup = BeautifulSoup(html_content, 'html.parser') # [cite: 168]

    # 查找可能包含节点信息的特定标签
    [cite_start]potential_node_containers = soup.find_all(['pre', 'code', 'textarea', 'script', 'style']) # [cite: 168]
    [cite_start]for tag in potential_node_containers: # [cite: 168]
        [cite_start]extracted_text = tag.get_text(separator="\n", strip=True) # [cite: 168]
        [cite_start]if extracted_text: # [cite: 168]
            [cite_start]nodes.append(extracted_text) # [cite: 168]
            # [cite_start]对这些标签内的文本也尝试进行 Base64 解码 [cite: 168]
            if tag.name in ['script', 'style', 'textarea', 'pre', 'code']:
                [cite_start]potential_base64_matches = BASE64_REGEX.findall(extracted_text) # [cite: 168]
                [cite_start]for b64_match in potential_base64_matches: # [cite: 169]
                    [cite_start]if len(b64_match) > 30 and '=' in b64_match: # [cite: 169]
                        [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) # [cite: 169]
                        [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: # [cite: 169]
                            [cite_start]nodes.append(decoded_b64_in_text) # [cite: 169]

    # [cite_start]也检查 body 中的直接文本内容，特别是当页面没有明确的容器标签时 [cite: 170]
    if soup.body:
        [cite_start]body_text = soup.body.get_text(separator="\n", strip=True) # [cite: 170]
        # [cite_start]只有当body文本长度较大或包含已知协议模式时才处理，避免无关的短文本 [cite: 170]
        [cite_start]if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()): # [cite: 170]
            [cite_start]if body_text: # [cite: 170]
                [cite_start]nodes.append(body_text) # [cite: 170]
                [cite_start]potential_base64_matches = BASE64_REGEX.findall(body_text) # [cite: 170]
                [cite_start]for b64_match in potential_base64_matches: # [cite: 171]
                    [cite_start]if len(b64_match) > 30 and '=' in b64_match: # [cite: 171]
                        [cite_start]decoded_b64_in_text = decode_base64_recursive(b64_match) # [cite: 171]
                        [cite_start]if decoded_b64_in_text and decoded_b64_in_text != b64_match: # [cite: 171]
                            [cite_start]nodes.append(decoded_b64_in_text) # [cite: 172]
    [cite_start]return nodes # [cite: 172]

def extract_and_validate_nodes(content: str) -> list[str]:
    """
    从解析后的内容中提取并验证所有支持格式的节点 URL。
    """
    [cite_start]if not content: # [cite: 172]
        return []

    [cite_start]found_nodes = set() # [cite: 173]
    [cite_start]for pattern_name, pattern_regex in NODE_PATTERNS.items(): # [cite: 173]
        [cite_start]matches = pattern_regex.findall(content) # [cite: 173]
        [cite_start]for match in matches: # [cite: 173]
            [cite_start]decoded_match = unquote(match).strip() # [cite: 173]
            [cite_start]normalized_node = standardize_node_url(decoded_match) # [cite: 173]
            # [cite_start]这里统一调用 is_valid_node，它内部会判断 Hysteria2 的有效性 [cite: 173]
            [cite_start]if is_valid_node(normalized_node): # [cite: 173]
                [cite_start]found_nodes.add(normalized_node) # [cite: 173]

    [cite_start]return list(found_nodes) # [cite: 173]

def load_existing_nodes_from_slices(directory: str, prefix: str) -> set[str]:
    """从多个切片文件中加载已存在的节点列表，并进行标准化处理。"""
    [cite_start]existing_nodes = set() # [cite: 174]
    [cite_start]loaded_count = 0 # [cite: 174]
    [cite_start]for filename in os.listdir(directory): # [cite: 174]
        [cite_start]if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'): # [cite: 174]
            [cite_start]file_path = os.path.join(directory, filename) # [cite: 174]
            try:
                [cite_start]with open(file_path, 'r', encoding='utf-8') as f: # [cite: 174]
                    [cite_start]for line in f: # [cite: 174]
                        # [cite_start]适应旧格式（Proxy-0000X = 链接）和新格式（纯链接） [cite: 175]
                        [cite_start]parts = line.strip().split(' = ', 1) # [cite: 175]
                        [cite_start]node_url = parts[1].strip() if len(parts) == 2 else line.strip() # [cite: 175]
                        [cite_start]standardized_node = standardize_node_url(node_url) # [cite: 175]
                        [cite_start]existing_nodes.add(standardized_node) # [cite: 176]
                        [cite_start]loaded_count += 1 # [cite: 176]
            except Exception as e:
                [cite_start]logging.warning(f"加载现有节点文件失败 ({file_path}): {e}") # [cite: 176]
    [cite_start]logging.info(f"已从 {len([f for f in os.listdir(directory) if f.startswith(os.path.basename(prefix)) and f.endswith('.txt')])} 个切片文件中加载 {loaded_count} 个现有节点。") # [cite: 176]
    [cite_start]return existing_nodes # [cite: 176]

def save_nodes_to_sliced_files(output_prefix: str, nodes: list[str], max_nodes_per_slice: int) -> None:
    """将处理后的节点切片保存到多个文本文件，不再带 'Proxy-0000X = ' 前缀。"""
    [cite_start]total_nodes = len(nodes) # [cite: 177]
    [cite_start]num_slices = (total_nodes + max_nodes_per_slice - 1) // max_nodes_per_slice # [cite: 177]

    # [cite_start]清理旧的切片文件 [cite: 177]
    [cite_start]for filename in os.listdir(DATA_DIR): # [cite: 177]
        [cite_start]if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'): # [cite: 177]
            try:
                [cite_start]os.remove(os.path.join(DATA_DIR, filename)) # [cite: 177]
                [cite_start]logging.info(f"已删除旧切片文件: {filename}") # [cite: 177]
            except OSError as e:
                [cite_start]logging.warning(f"删除旧切片文件失败 ({filename}): {e}") # [cite: 178]

    [cite_start]saved_files_count = 0 # [cite: 178]
    [cite_start]nodes.sort() # 排序确保输出一致性 [cite: 178]
    [cite_start]for i in range(num_slices): # [cite: 178]
        [cite_start]start_index = i * max_nodes_per_slice # [cite: 178]
        [cite_start]end_index = min((i + 1) * max_nodes_per_slice, total_nodes) # [cite: 178]
        [cite_start]slice_nodes = nodes[start_index:end_index] # [cite: 178]
        [cite_start]slice_file_name = f"{output_prefix}{i+1:03d}.txt" # [cite: 179]

        try:
            [cite_start]with open(slice_file_name, 'w', encoding='utf-8') as f: # [cite: 179]
                [cite_start]for node in slice_nodes: # 直接写入节点，不带前缀 [cite: 179]
                    [cite_start]f.write(f"{node}\n") # [cite: 179]
            [cite_start]logging.info(f"已保存切片文件: {slice_file_name} (包含 {len(slice_nodes)} 个节点)") # [cite: 179]
            [cite_start]saved_files_count += 1 # [cite: 179]
        except IOError as e:
            [cite_start]logging.error(f"保存切片文件失败 ({slice_file_name} {e})") # [cite: 180]

    [cite_start]logging.info(f"最终节点列表已切片保存到 {saved_files_count} 个文件。") # [cite: 180]

def save_node_counts_to_csv(file_path: str, counts_data: dict) -> None:
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    try:
        [cite_start]with open(file_path, 'w', encoding='utf-8', newline='') as f: # [cite: 180]
            [cite_start]writer = csv.writer(f) # [cite: 181]
            [cite_start]writer.writerow(["Source URL", "Node Count", "Processing Status"]) # [cite: 181]
            [cite_start]for url in sorted(counts_data.keys()): # [cite: 181]
                [cite_start]item = counts_data[url] # [cite: 181]
                [cite_start]writer.writerow([url, item['count'], item['status']]) # [cite: 181]
        [cite_start]logging.info(f"节点数量统计已保存到 {file_path}") # [cite: 181]
    except IOError as e:
        [cite_start]logging.error(f"保存节点数量统计CSV失败: {e}") # [cite: 181]

# --- 主逻辑 ---

async def process_single_url(url: str, url_cache_data: dict, client: httpx.AsyncClient) -> tuple[str, int, dict, list[str], str]:
    """处理单个URL的异步逻辑"""
    [cite_start]logging.info(f"开始处理 URL: {url}") # [cite: 182]
    [cite_start]content, new_cache_meta, fetch_status = await fetch_content(url, client, cache_data=url_cache_data.get(url, {}).copy()) # [cite: 182]

    [cite_start]if fetch_status == "SKIPPED_UNCHANGED": # [cite: 182]
        [cite_start]cached_info = url_cache_data.get(url, {'node_count': 0, 'status': 'UNKNOWN'}) # [cite: 182]
        [cite_start]return url, cached_info.get('node_count', 0), new_cache_meta, [], fetch_status # [cite: 182]

    [cite_start]if fetch_status != "FETCH_SUCCESS": # [cite: 183]
        [cite_start]return url, 0, None, [], fetch_status # [cite: 183]

    [cite_start]parsed_content_text = parse_content(content, new_cache_meta.get('content_type', 'unknown')) # [cite: 183]
    [cite_start]nodes_from_url = extract_and_validate_nodes(parsed_content_text) # [cite: 183]

    [cite_start]logging.info(f"从 {url} 提取到 {len(nodes_from_url)} 个有效节点。") # [cite: 183]

    [cite_start]if new_cache_meta: # [cite: 183]
        [cite_start]new_cache_meta['node_count'] = len(nodes_from_url) # [cite: 183]
        [cite_start]new_cache_meta['status'] = "PARSE_NO_NODES" if len(nodes_from_url) == 0 else "PARSE_SUCCESS" # [cite: 183]
    else:
        [cite_start]new_cache_meta = url_cache_data.get(url, {}) # [cite: 183]
        [cite_start]new_cache_meta['node_count'] = len(nodes_from_url) # [cite: 183]
        [cite_start]new_cache_meta['status'] = "PARSE_NO_NODES" if len(nodes_from_url) == 0 else "PARSE_SUCCESS" # [cite: 183]

    [cite_start]return url, len(nodes_from_url), new_cache_meta, nodes_from_url, new_cache_meta['status'] # [cite: 184]


async def main():
    [cite_start]start_time = time.time() # [cite: 184]
    [cite_start]logging.info("脚本开始运行。") # [cite: 184]

    [cite_start]source_urls = read_sources(SOURCES_FILE) # [cite: 184]
    [cite_start]if not source_urls: # [cite: 184]
        [cite_start]logging.error("未找到任何源 URL，脚本终止。") # [cite: 184]
        return

    [cite_start]url_cache = load_cache(CACHE_FILE) # [cite: 184]
    [cite_start]if os.path.exists(FAILED_URLS_FILE): # [cite: 184]
        try:
            [cite_start]os.remove(FAILED_URLS_FILE) # [cite: 184]
            [cite_start]logging.info(f"已清空旧的失败URL日志文件: {FAILED_URLS_FILE}") # [cite: 184]
        except OSError as e:
            [cite_start]logging.warning(f"清空失败URL日志文件失败: {e}") # [cite: 185]

    [cite_start]existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX) # [cite: 185]
    [cite_start]all_new_and_existing_nodes = set(existing_nodes) # [cite: 185]

    [cite_start]url_processing_detailed_info = {} # [cite: 185]
    [cite_start]url_processing_summary = defaultdict(int) # [cite: 185]

    # 使用 asyncio.Semaphore 控制并发量
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS_LIMIT)

    async def throttled_process_url(url, cache, client):
        async with semaphore:
            return await process_single_url(url, cache, client)

    # 使用 httpx.AsyncClient 替代同步客户端，并开启 http2
    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT, http2=True) as client:
        tasks = [throttled_process_url(url, url_cache, client) for url in source_urls]
        
        # 使用 asyncio.gather 来并发执行所有任务
        for i, future in enumerate(asyncio.as_completed(tasks)):
            processed_url, node_count, updated_cache_meta, extracted_nodes_list, status = await future
            [cite_start]url_processing_detailed_info[processed_url] = {'count': node_count, 'status': status} # [cite: 185]
            [cite_start]url_processing_summary[status] += 1 # [cite: 185]

            [cite_start]if extracted_nodes_list: # [cite: 186]
                [cite_start]all_new_and_existing_nodes.update(extracted_nodes_list) # [cite: 186]

            [cite_start]if updated_cache_meta: # [cite: 186]
                [cite_start]url_cache[processed_url] = updated_cache_meta # [cite: 186]
            [cite_start]elif status == "SKIPPED_UNCHANGED": # [cite: 186]
                [cite_start]if processed_url not in url_cache: # [cite: 187]
                    [cite_start]url_cache[processed_url] = {'node_count': node_count, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'} # [cite: 187]
                else:
                    [cite_start]url_cache[processed_url]['node_count'] = node_count # [cite: 187]
                    [cite_start]url_cache[processed_url]['status'] = status # [cite: 188]
            else:
                [cite_start]if processed_url not in url_cache: # [cite: 188]
                    [cite_start]url_cache[processed_url] = {'node_count': 0, 'status': status, 'content_hash': None, 'etag': None, 'last_modified': None, 'content_type': 'unknown'} # [cite: 189]
                else:
                    [cite_start]url_cache[processed_url]['status'] = status # [cite: 189]
                    [cite_start]url_cache[processed_url]['node_count'] = 0 # [cite: 189]

            [cite_start]if (i + 1) % CACHE_SAVE_INTERVAL == 0: # [cite: 189]
                [cite_start]save_cache(CACHE_FILE, url_cache) # [cite: 190]
                [cite_start]logging.info(f"已处理 {i + 1} 个URL，阶段性保存缓存。") # [cite: 190]

    # 脚本结束时，保存最终缓存和统计信息
    save_cache(CACHE_FILE, url_cache) # 确保所有任务完成后保存一次缓存

    [cite_start]logging.info("\n--- 处理完成报告 ---") # [cite: 191]
    [cite_start]logging.info(f"总共尝试处理 {len(source_urls)} 个源URL。") # [cite: 191]
    [cite_start]logging.info(f"状态统计:") # [cite: 191]
    [cite_start]for status, count in sorted(url_processing_summary.items()): # [cite: 191]
        [cite_start]logging.info(f"  {status}: {count} 个") # [cite: 191]

    [cite_start]final_nodes_list = sorted(list(all_new_and_existing_nodes)) # [cite: 191]
    [cite_start]logging.info(f"总共收集到 {len(final_nodes_list)} 个去重后的节点 (含原有节点)。") # [cite: 192]

    [cite_start]save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE) # [cite: 192]
    [cite_start]save_node_counts_to_csv(NODE_COUNTS_FILE, url_processing_detailed_info) # [cite: 192]
    [cite_start]save_cache(CACHE_FILE, url_cache) # [cite: 192]

    [cite_start]end_time = time.time() # [cite: 192]
    logging.info(f"\n总耗时: {end_time - start_time:.2f} 秒。") #
    if any(status.startswith("FETCH_FAILED") or status.startswith("UNEXPECTED_") or status.startswith("PARSE_NO_NODES") for status in url_processing_summary.keys()): #
        logging.info(f"\n请检查 {FAILED_URLS_FILE} 文件查看失败的URL详情。") #

if __name__ == "__main__":
    asyncio.run(main()) # 运行异步主函数
