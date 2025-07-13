import httpx
import asyncio
import re
import os
import aiofiles
import aiofiles.threadpool.text
import json
import yaml
import base64
from collections import defaultdict
import datetime
import hashlib
from bs4 import BeautifulSoup
import logging
import typing
import uuid
# import httpcore # 不再直接导入，因为其SSLError属性可能不存在

# 配置日志，同时输出到控制台和文件
logging.basicConfig(
    level=logging.INFO, # 可以根据需要调整为 DEBUG, INFO, WARNING, ERROR
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('data', 'proxy_scraper.log')),
        logging.StreamHandler()
    ]
)

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
CACHE_EXPIRATION_HOURS = 48  # 缓存过期时间（小时）
CLEANUP_THRESHOLD_HOURS = 72  # 缓存清理阈值（小时）

# 确保数据目录和缓存目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的节点协议正则
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2:\/\/(?:[^:@\/]+(?::[^@\/]*)?@)?(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?"),
    "vmess": re.compile(r"vmess:\/\/[a-zA-Z0-9\-_+=/]+"),
    "trojan": re.compile(r"trojan:\/\/[^@]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?"),
    "ss": re.compile(r"ss:\/\/(?:[a-zA-Z0-9\-_]+:[^@\/]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+|[a-zA-Z0-9\-_+=/]+)(?:#.*)?"),
    "ssr": re.compile(r"ssr:\/\/[a-zA-Z0-9\-_+=/]+"),
    "vless": re.compile(r"vless:\/\/[0-9a-fA-F\-]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?"),
}

# 并发限制
CONCURRENCY_LIMIT = 10

# 支持的 Shadowsocks 加密方法
SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "chacha20-ietf",
    "aes-256-cfb", "aes-128-cfb", "rc4-md5", "none"
}

# 支持的 ShadowsocksR 协议和混淆
SSR_PROTOCOLS = {"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1"}
SSR_OBFS = {"plain", "http_simple", "http_post", "tls1.2_ticket_auth"}

def is_valid_uuid(value: str) -> bool:
    """验证字符串是否为有效的 UUID。"""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        [cite_start]return False [cite: 149]

def is_valid_port(port: str) -> bool:
    """验证端口号是否有效（1-65535）。"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        [cite_start]return False [cite: 149]

def is_valid_host(host: str) -> bool:
    """验证主机是否为有效的域名或 IP 地址（包括 IPv6）。"""
    if not host:
        [cite_start]return False [cite: 149]
    # 稍微放宽对主机名的正则表达式，使其更通用
    # 允许包含非标准DNS字符（例如下划线），这在某些情况下可能是允许的
    [cite_start]return bool(re.match(r'^(?:\[[0-9a-fA-F:\.]+\]|[a-zA-Z0-9\.\-_]+)$', host)) [cite: 149]

def validate_node(node: str, protocol: str) -> tuple[bool, str]:
    """
    验证节点是否符合其协议的官方格式要求。

    Args:
        node (str): 要验证的节点字符串。
        protocol (str): 节点协议（hysteria2, vmess, trojan, ss, ssr, vless）。

    Returns:
        tuple[bool, str]: (是否有效, 错误原因)。
    """
    if protocol == "hysteria2":
        match = re.match(r"hysteria2:\/\/([^@]+)@([^:]+):(\d+)(?:\/|\?|$)", node)
        if not match:
            [cite_start]return False, "格式不匹配，缺少 password、host 或 port" [cite: 151]
        password, host, port = match.groups()
        if not password:
            [cite_start]return False, "password 为空" [cite: 151]
        if not is_valid_host(host):
            [cite_start]return False, f"无效的主机: {host}" [cite: 151]
        if not is_valid_port(port):
            [cite_start]return False, f"无效的端口: {port}" [cite: 151]
        [cite_start]return True, "" [cite: 152]

    elif protocol == "vmess":
        if not node.startswith("vmess://"):
            [cite_start]return False, "缺少 vmess:// 前缀" [cite: 152]
        try:
            # 尝试解码，忽略非 Base64 字符
            [cite_start]decoded = base64.b64decode(node[8:].strip('=').encode('ascii', 'ignore')).decode('utf-8', errors='ignore') [cite: 152]
            [cite_start]data = json.loads(decoded) [cite: 152]
            [cite_start]required_fields = {'v', 'ps', 'add', 'port', 'id', 'aid', 'net'} [cite: 153]
            if not all(field in data for field in required_fields):
                [cite_start]return False, f"缺少必要字段: {required_fields - set(data.keys())}" [cite: 153]
            if not is_valid_host(data['add']):
                [cite_start]return False, f"无效的主机: {data['add']}" [cite: 153]
            if not is_valid_port(str(data['port'])):
                [cite_start]return False, f"无效的端口: {data['port']}" [cite: 154]
            if not is_valid_uuid(data['id']):
                [cite_start]return False, f"无效的 UUID: {data['id']}" [cite: 154]
            if not str(data['aid']).isdigit():
                [cite_start]return False, f"无效的 alterId: {data['aid']}" [cite: 154]
            if data['net'] not in {'tcp', 'ws', 'h2', 'grpc', 'kcp'}: # 添加 kcp 等常见网络类型
                [cite_start]return False, f"无效的网络类型: {data['net']}" [cite: 155]
            [cite_start]return True, "" [cite: 155]
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            [cite_start]return False, f"Base64 解码或 JSON 解析失败: {e}" [cite: 155]

    elif protocol == "trojan":
        match = re.match(r"trojan:\/\/([^@]+)@([^:]+):(\d+)(?:\/|\?|$)", node)
        if not match:
            [cite_start]return False, "格式不匹配，缺少 password、host 或 port" [cite: 156]
        [cite_start]password, host, port = match.groups() [cite: 156]
        if not password:
            [cite_start]return False, "password 为空" [cite: 156]
        if not is_valid_host(host):
            [cite_start]return False, f"无效的主机: {host}" [cite: 156]
        if not is_valid_port(port):
            [cite_start]return False, f"无效的端口: {port}" [cite: 157]
        [cite_start]return True, "" [cite: 157]

    elif protocol == "ss":
        # 简化 SS 匹配，优先处理 Base64 解码后的格式
        if node.startswith("ss://"):
            try:
                # 尝试解码 Base64 部分
                [cite_start]encoded_part = node[5:].split('#')[0].strip('=') [cite: 157]
                # 确保只包含 Base64 安全字符，忽略其他
                [cite_start]encoded_part_ascii = encoded_part.encode('ascii', 'ignore') [cite: 158]
                [cite_start]decoded = base64.b64decode(encoded_part_ascii).decode('utf-8', errors='ignore') [cite: 158]

                [cite_start]match = re.match(r"([a-zA-Z0-9\-_]+):([^@]+)@([^:]+):(\d+)", decoded) [cite: 158]
                if not match:
                    [cite_start]return False, "Base64 解码后格式不匹配" [cite: 159]
                
                [cite_start]method, password, host, port = match.groups() [cite: 159]
                if method not in SS_METHODS:
                    [cite_start]return False, f"不支持的加密方法: {method}" [cite: 159]
                if not password:
                    [cite_start]return False, "password 为空" [cite: 160]
                if not is_valid_host(host):
                    [cite_start]return False, f"无效的主机: {host}" [cite: 160]
                if not is_valid_port(port):
                    [cite_start]return False, f"无效的端口: {port}" [cite: 161]
                [cite_start]return True, "" [cite: 161]
            except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                [cite_start]return False, f"Base64 解码失败或格式错误: {e}" [cite: 161]
        [cite_start]return False, "缺少 ss:// 前缀" # 如果没有 ss:// 前缀，则认为不是 SS 节点 [cite: 161]

    elif protocol == "ssr":
        if not node.startswith("ssr://"):
            [cite_start]return False, "缺少 ssr:// 前缀" [cite: 162]
        try:
            # 尝试解码，忽略非 Base64 字符
            [cite_start]decoded = base64.b64decode(node[6:].strip('=').encode('ascii', 'ignore')).decode('utf-8', errors='ignore') [cite: 162]
            [cite_start]parts = decoded.split(':') [cite: 162]
            if len(parts) < 6:
                [cite_start]return False, "格式不匹配，缺少必要字段" [cite: 163]
            
            [cite_start]host, port, protocol_ssr, method, obfs, password_encoded = parts[:6] # 修改变量名以避免冲突 [cite: 163]
            
            if not is_valid_host(host):
                [cite_start]return False, f"无效的主机: {host}" [cite: 163]
            if not is_valid_port(port):
                [cite_start]return False, f"无效的端口: {port}" [cite: 164]
            if protocol_ssr not in SSR_PROTOCOLS:
                [cite_start]return False, f"不支持的协议: {protocol_ssr}" [cite: 164]
            if method not in SS_METHODS:
                [cite_start]return False, f"不支持的加密方法: {method}" [cite: 164]
            if obfs not in SSR_OBFS:
                [cite_start]return False, f"不支持的混淆: {obfs}" [cite: 165]
            
            try:
                # SSR 的密码部分本身可能是 Base64 编码的
                [cite_start]decoded_password = base64.b64decode(password_encoded.encode('ascii', 'ignore')).decode('utf-8', errors='ignore') [cite: 165]
                if not decoded_password: # 密码为空也视为无效
                    [cite_start]return False, "password 为空或解码后为空" [cite: 166]
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                # 如果密码部分不是 Base64 编码，或者解码失败，则直接使用原始密码部分
                if not password_encoded:
                    [cite_start]return False, "password 为空" [cite: 167]
            
            [cite_start]return True, "" [cite: 167]
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            [cite_start]return False, f"Base64 解码失败: {e}" [cite: 167]

    elif protocol == "vless":
        match = re.match(r"vless:\/\/([0-9a-fA-F\-]+)@([^:]+):(\d+)(?:\/|\?|$)", node)
        if not match:
            [cite_start]return False, "格式不匹配，缺少 uuid、host 或 port" [cite: 168]
        [cite_start]uuid_str, host, port = match.groups() [cite: 168]
        if not is_valid_uuid(uuid_str):
            [cite_start]return False, f"无效的 UUID: {uuid_str}" [cite: 168]
        if not is_valid_host(host):
            [cite_start]return False, f"无效的主机: {host}" [cite: 168]
        if not is_valid_port(port):
            [cite_start]return False, f"无效的端口: {port}" [cite: 168]
        [cite_start]return True, "" [cite: 168]

    [cite_start]return False, "未知协议" [cite: 169]

async def clean_old_cache_files(cleanup_threshold_hours: int):
    """
    清理 data/cache 目录中过期的或不再使用的缓存文件。
    删除修改时间早于指定阈值的文件。
    
    Args:
        cleanup_threshold_hours (int): 缓存文件清理的阈值（小时）。
    """
    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(hours=cleanup_threshold_hours)
    
    [cite_start]logging.info(f"开始清理缓存目录: {CACHE_DIR}，将删除修改时间早于 {cutoff_time} 的文件。") [cite: 169]
    
    deleted_count = 0
    try:
        for filename in os.listdir(CACHE_DIR):
            [cite_start]file_path = os.path.join(CACHE_DIR, filename) [cite: 170]
            if os.path.isfile(file_path):
                try:
                    [cite_start]file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)) [cite: 170]
                    if file_mtime < cutoff_time:
                        [cite_start]os.remove(file_path) [cite: 171]
                        [cite_start]logging.debug(f"已删除过期缓存文件: {filename}") [cite: 171]
                        [cite_start]deleted_count += 1 [cite: 171]
                except OSError as e:
                    [cite_start]logging.warning(f"无法删除文件 {file_path}: {e}") [cite: 171]
        [cite_start]logging.info(f"缓存清理完成，共删除 {deleted_count} 个文件。") [cite: 172]
    except FileNotFoundError:
        [cite_start]logging.info(f"缓存目录 {CACHE_DIR} 不存在，无需清理。") [cite: 172]
    except Exception as e:
        [cite_start]logging.error(f"清理缓存时发生错误: {e}") [cite: 172]

async def _fetch_url_with_retry(client: httpx.AsyncClient, url: str, headers: dict, original_protocol_url: str) -> httpx.Response | None:
    """
    尝试从 URL 获取内容，并支持 HTTP 到 HTTPS 的回退。
    
    Args:
        client (httpx.AsyncClient): HTTP 客户端。
        url (str): 要获取的 URL。
        headers (dict): HTTP 请求头。
        original_protocol_url (str): 初始请求的 URL，用于避免无限回退。
        
    Returns:
        httpx.Response | None: HTTP 响应对象，如果失败则返回 None。
    """
    try:
        [cite_start]logging.info(f"尝试从 {url.split('://')[0].upper()} 获取内容: {url} (User-Agent: {headers.get('User-Agent', 'N/A')})") [cite: 174]
        [cite_start]response = await client.get(url, headers=headers) [cite: 174]
        [cite_start]response.raise_for_status() [cite: 174]
        [cite_start]return response [cite: 174]
    # 捕获更通用的 httpx.RequestError
    except httpx.RequestError as e:
        [cite_start]logging.warning(f"请求 {url} 时发生网络或连接错误: {e}") [cite: 174]
        # 如果是 HTTPS 错误，尝试禁用 SSL 验证
        if isinstance(e, httpx.ConnectError) and "SSL" in str(e):
            [cite_start]logging.info(f"SSL 连接错误，尝试禁用 SSL 验证: {url}") [cite: 175]
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as retry_client:
                try:
                    [cite_start]response = await retry_client.get(url, headers=headers) [cite: 175]
                    [cite_start]response.raise_for_status() [cite: 175]
                    [cite_start]return response [cite: 176]
                except httpx.HTTPStatusError as e_retry:
                    [cite_start]logging.error(f"禁用 SSL 验证后，获取 {url} 时发生 HTTP 状态错误: {e_retry}") [cite: 176]
                except httpx.RequestError as e_retry:
                    [cite_start]logging.error(f"禁用 SSL 验证后，获取 {url} 时发生网络请求错误: {e_retry}") [cite: 176]
        # 如果是 HTTP 到 HTTPS 的回退（但仅在原始请求是 HTTP 时才尝试）
        elif url.startswith("http://") and original_protocol_url.startswith("http://"):
            [cite_start]https_url = url.replace("http://", "https://") [cite: 177]
            [cite_start]logging.info(f"尝试从 HTTPS 回退获取内容: {https_url}") [cite: 177]
            try:
                [cite_start]fallback_headers = dict(headers) [cite: 178]
                [cite_start]fallback_headers.pop('If-None-Match', None) [cite: 178]
                [cite_start]fallback_headers.pop('If-Modified-Since', None) [cite: 178]
                [cite_start]response_https = await client.get(https_url, headers=fallback_headers) [cite: 178]
                [cite_start]response_https.raise_for_status() [cite: 178]
                [cite_start]return response_https [cite: 178]
            except httpx.HTTPStatusError as e_https:
                [cite_start]logging.error(f"获取 {https_url} 时发生 HTTPS 状态错误: {e_https}") [cite: 179]
            except httpx.RequestError as e_https:
                [cite_start]logging.error(f"获取 {https_url} 时发生 HTTPS 网络请求错误: {e_https}") [cite: 179]
        else:
            [cite_start]logging.error(f"获取 {url} 时发生未知网络错误: {e}") [cite: 179]
    except httpx.HTTPStatusError as e:
        [cite_start]logging.error(f"获取 {url} 时发生 HTTP 状态错误: {e}") [cite: 179]
        # 这里移除 HTTP 到 HTTPS 的回退逻辑，因为它已经在 RequestError 中处理
        # 避免重复尝试或逻辑混乱
    except Exception as e:
        [cite_start]logging.error(f"获取 {url} 时发生未知错误: {e}") [cite: 181]
    return None

async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """
    从 URL 获取内容，并支持基于 HTTP 头部的缓存验证。
    
    Args:
        url (str): 要获取的 URL。
        use_cache (bool): 是否使用缓存，默认 True。
        
    Returns:
        str | None: 获取的内容字符串，如果失败则返回 None。
    """
    [cite_start]cache_entry_path = os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + ".json") [cite: 181]
    
    cached_data = None
    if use_cache and os.path.exists(cache_entry_path):
        try:
            async with aiofiles.open(cache_entry_path, 'r', encoding='utf-8') as f:
                [cite_start]cached_data = json.loads(await f.read()) [cite: 182]
            
            [cite_start]cache_timestamp_str = cached_data.get('timestamp', datetime.datetime.min.isoformat()) [cite: 182]
            [cite_start]cache_timestamp = datetime.datetime.fromisoformat(cache_timestamp_str) [cite: 182]
            [cite_start]if (datetime.datetime.now() - cache_timestamp).total_seconds() / 3600 >= CACHE_EXPIRATION_HOURS: [cite: 183]
                [cite_start]logging.info(f"缓存 {url} 已过期（超过 {CACHE_EXPIRATION_HOURS} 小时），将重新检查更新。") [cite: 183]
                cached_data = None
            else:
                [cite_start]logging.info(f"缓存 {url} 有效，尝试使用缓存进行条件请求。") [cite: 183]
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            [cite_start]logging.warning(f"读取或解析缓存文件 {cache_entry_path} 失败: {e}，将重新获取。") [cite: 183]
            [cite_start]cached_data = None [cite: 184]

    async with httpx.AsyncClient(timeout=10, verify=True, follow_redirects=True) as client:
        headers_for_request = {
            [cite_start]"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" [cite: 185]
        }

        if cached_data:
            if cached_data.get('etag'):
                [cite_start]headers_for_request['If-None-Match'] = cached_data['etag'] [cite: 185]
            if cached_data.get('last-modified'):
                [cite_start]headers_for_request['If-Modified-Since'] = cached_data['last-modified'] [cite: 185]

        [cite_start]response = await _fetch_url_with_retry(client, url, headers_for_request, url) [cite: 186]

        if response:
            if response.status_code == 304 and cached_data and cached_data.get('content'):
                [cite_start]logging.info(f"URL: {url} 内容未更新 (304 Not Modified)，从缓存读取。") [cite: 186]
                [cite_start]return base64.b64decode(cached_data['content']).decode('utf-8', errors='ignore') [cite: 186]
            else:
                [cite_start]content = response.text [cite: 186]
                new_cached_data = {
                    [cite_start]"content": base64.b64encode(content.encode('utf-8')).decode('ascii'), [cite: 187]
                    [cite_start]"timestamp": datetime.datetime.now().isoformat() [cite: 187]
                }
                if 'etag' in response.headers:
                    [cite_start]new_cached_data['etag'] = response.headers['etag'] [cite: 188]
                if 'last-modified' in response.headers:
                    [cite_start]new_cached_data['last-modified'] = response.headers['last-modified'] [cite: 188]

                try:
                    async with aiofiles.open(cache_entry_path, 'w', encoding='utf-8') as f:
                        [cite_start]await f.write(json.dumps(new_cached_data, ensure_ascii=False)) [cite: 189]
                    [cite_start]logging.info(f"URL: {url} 内容已更新，已写入缓存。") [cite: 189]
                except (IOError, json.JSONEncodeError) as e:
                    [cite_start]logging.error(f"写入缓存文件 {cache_entry_path} 失败: {e}") [cite: 189]
                
                [cite_start]return content [cite: 190]
        else:
            [cite_start]logging.warning(f"无法获取 URL: {url} 的内容，跳过该 URL 的节点提取。") [cite: 190]
            [cite_start]return None [cite: 190]

async def extract_nodes_from_content(url: str, content: str) -> list[str]:
    """
    从文本内容中提取符合 Vmess, Trojan, SS, SSR, Vless, Hysteria2 格式的节点，并验证其有效性。
    
    Args:
        url (str): 源 URL，用于日志记录。
        content (str): 要解析的内容。
        
    Returns:
        list[str]: 提取的唯一有效节点列表。
    """
    unique_nodes = set()
    
    # 尝试 Base64 解码，但要确保输入是有效的 Base64 字符串
    decoded_content_attempt = None
    # 检查内容是否可能为 Base64，过滤掉非 Base64 字符
    if re.fullmatch(r"^[a-zA-Z0-9\-_+=/\s]+$", content.strip()): # 允许空格，因为某些订阅链接可能是多行Base64
        try:
            # 移除所有空白字符并确保长度是4的倍数
            [cite_start]clean_content = content.strip().replace(" ", "").replace("\n", "").replace("\r", "") [cite: 192]
            padding_needed = len(clean_content) % 4
            if padding_needed != 0:
                [cite_start]clean_content += '=' * (4 - padding_needed) [cite: 192]
            
            [cite_start]decoded_content_attempt = base64.b64decode(clean_content).decode('utf-8', errors='ignore') [cite: 192]
            [cite_start]logging.debug(f"成功 Base64 解码内容 (URL: {url})") [cite: 193]
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            [cite_start]logging.debug(f"Base64 解码失败 (URL: {url}): {e}") [cite: 193]
            pass # 不是有效的 Base64，继续按原始文本处理

    contents_to_search = [content]
    if decoded_content_attempt and decoded_content_attempt != content: # 避免重复搜索
        [cite_start]contents_to_search.append(decoded_content_attempt) [cite: 193]

    for text_content in contents_to_search:
        # 尝试解析 JSON
        try:
            [cite_start]json_data = json.loads(text_content) [cite: 194]
            if isinstance(json_data, list):
                for item in json_data:
                    if isinstance(item, dict) and 'v' in item and 'ps' in item and 'add' in item:
                        [cite_start]vmess_node = "vmess://" + base64.b64encode(json.dumps(item, separators=(',', ':')).encode()).decode() [cite: 195]
                        [cite_start]is_valid, reason = validate_node(vmess_node, "vmess") [cite: 195]
                        if is_valid:
                            [cite_start]unique_nodes.add(vmess_node) [cite: 195]
                        else:
                            [cite_start]logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, JSON 列表): {vmess_node}, 原因: {reason}") [cite: 196]
            elif isinstance(json_data, dict):
                # 处理 V2RayN/Clash config 格式
                [cite_start]if 'outbounds' in json_data and isinstance(json_data['outbounds'], list): [cite: 197]
                    for outbound in json_data['outbounds']:
                        if outbound.get('protocol') == 'vmess' and outbound.get('settings', {}).get('vnext'):
                            # Vmess 节点通常在 vnext[0].users[0]
                            [cite_start]server_settings = outbound['settings']['vnext'][0] [cite: 198]
                            [cite_start]user_settings = server_settings['users'][0] [cite: 198]
                            vmess_config = {
                                [cite_start]"v": "2", [cite: 199]
                                [cite_start]"ps": outbound.get('tag', 'node'), # 使用 tag 或默认名 [cite: 199]
                                [cite_start]"add": server_settings.get('address'), [cite: 199]
                                [cite_start]"port": server_settings.get('port'), [cite: 200]
                                [cite_start]"id": user_settings.get('id'), [cite: 200]
                                [cite_start]"aid": user_settings.get('alterId', '0'), [cite: 200]
                                [cite_start]"net": outbound.get('streamSettings', {}).get('network', 'tcp'), [cite: 201]
                                [cite_start]"type": outbound.get('streamSettings', {}).get('type', ''), [cite: 201]
                                [cite_start]"host": outbound.get('streamSettings', {}).get('wsSettings', {}).get('headers', {}).get('Host', ''), [cite: 201]
                                [cite_start]"path": outbound.get('streamSettings', {}).get('wsSettings', {}).get('path', ''), [cite: 202]
                                [cite_start]"tls": "tls" if outbound.get('streamSettings', {}).get('security') == 'tls' else "" [cite: 202]
                            }
                            [cite_start]vmess_config = {k: v for k, v in vmess_config.items() if v is not None and v != ''} [cite: 203]
                            [cite_start]vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode()).decode() [cite: 203]
                            [cite_start]is_valid, reason = validate_node(vmess_str, "vmess") [cite: 204]
                            if is_valid:
                                [cite_start]unique_nodes.add(vmess_str) [cite: 204]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, V2Ray 配置): {vmess_str}, 原因: {reason}") [cite: 205]
                        elif outbound.get('protocol') == 'trojan' and outbound.get('settings', {}).get('servers'):
                            [cite_start]server_settings = outbound['settings']['servers'][0] [cite: 206]
                            [cite_start]trojan_node = f"trojan://{server_settings.get('password')}@{server_settings.get('address')}:{server_settings.get('port')}" [cite: 206]
                            if outbound.get('streamSettings', {}).get('security') == 'tls':
                                if server_settings.get('sni'):
                                    [cite_start]trojan_node += f"?sni={server_settings['sni']}" [cite: 207]
                                elif outbound.get('streamSettings', {}).get('tlsSettings', {}).get('serverName'):
                                    [cite_start]trojan_node += f"?sni={outbound['streamSettings']['tlsSettings']['serverName']}" [cite: 208]
                                # V2Ray config 中没有直接的 allowInsecure 对应，这里暂不处理
                            [cite_start]is_valid, reason = validate_node(trojan_node, "trojan") [cite: 208]
                            if is_valid:
                                [cite_start]unique_nodes.add(trojan_node) [cite: 209]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, V2Ray 配置): {trojan_node}, 原因: {reason}") [cite: 210]
                
                # 处理 Clash/Sing-Box proxies 格式
                [cite_start]elif 'proxies' in json_data and isinstance(json_data['proxies'], list): [cite: 210]
                    for proxy in json_data['proxies']:
                        if proxy.get('type') == 'vmess':
                            vmess_node = {
                                [cite_start]"v": "2", [cite: 212]
                                [cite_start]"ps": proxy.get('name', 'node'), [cite: 212]
                                [cite_start]"add": proxy.get('server'), [cite: 212]
                                [cite_start]"port": proxy.get('port'), [cite: 213]
                                [cite_start]"id": proxy.get('uuid'), [cite: 213]
                                [cite_start]"aid": proxy.get('alterId', '0'), [cite: 213]
                                [cite_start]"net": proxy.get('network', 'tcp'), [cite: 213]
                                [cite_start]"type": "", # Clash 配置中可能没有直接的 type 字段 [cite: 214]
                                [cite_start]"host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('tls-host', ''), # 兼容不同字段 [cite: 214]
                                [cite_start]"path": proxy.get('ws-path', ''), [cite: 214]
                                [cite_start]"tls": "tls" if proxy.get('tls', False) else "" [cite: 215]
                            }
                            [cite_start]vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''} [cite: 216]
                            [cite_start]vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode() [cite: 216]
                            [cite_start]is_valid, reason = validate_node(vmess_str, "vmess") [cite: 216]
                            if is_valid:
                                [cite_start]unique_nodes.add(vmess_str) [cite: 217]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, Clash/Sing-Box JSON): {vmess_str}, 原因: {reason}") [cite: 218]
                        elif proxy.get('type') == 'trojan':
                            [cite_start]trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}" [cite: 218]
                            if proxy.get('sni'):
                                [cite_start]trojan_node += f"?sni={proxy['sni']}" [cite: 219]
                            if proxy.get('skip-cert-verify', False): # Clash 的 skip-cert-verify
                                [cite_start]trojan_node += "&allowInsecure=1" [cite: 219]
                            [cite_start]is_valid, reason = validate_node(trojan_node, "trojan") [cite: 220]
                            if is_valid:
                                [cite_start]unique_nodes.add(trojan_node) [cite: 220]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, Clash/Sing-Box JSON): {trojan_node}, 原因: {reason}") [cite: 221]
                        elif proxy.get('type') == 'ss':
                            # Clash ss 类型解析
                            [cite_start]ss_node_parts = [] [cite: 222]
                            [cite_start]method = proxy.get('cipher') [cite: 222]
                            [cite_start]password = proxy.get('password') [cite: 222]
                            [cite_start]server = proxy.get('server') [cite: 223]
                            [cite_start]port = proxy.get('port') [cite: 223]
                            if method and password and server and port:
                                # 构建 ss://base64encoded_info 格式
                                [cite_start]ss_info = f"{method}:{password}@{server}:{port}" [cite: 224]
                                [cite_start]encoded_ss_info = base64.b64encode(ss_info.encode()).decode() [cite: 224]
                                [cite_start]ss_node = f"ss://{encoded_ss_info}" [cite: 225]
                                if proxy.get('name'):
                                    [cite_start]ss_node += f"#{proxy['name']}" [cite: 226]
                                
                                [cite_start]is_valid, reason = validate_node(ss_node, "ss") [cite: 226]
                                if is_valid:
                                    [cite_start]unique_nodes.add(ss_node) [cite: 227]
                                else:
                                    [cite_start]logging.debug(f"丢弃无效 SS 节点 (URL: {url}, Clash JSON): {ss_node}, 原因: {reason}") [cite: 228]
                        elif proxy.get('type') == 'vless':
                            # Clash/Sing-Box vless 类型解析
                            vless_node_config = {
                                [cite_start]"uuid": proxy.get('uuid'), [cite: 229]
                                [cite_start]"address": proxy.get('server'), [cite: 229]
                                [cite_start]"port": proxy.get('port'), [cite: 230]
                                [cite_start]"flow": proxy.get('flow'), [cite: 230]
                                [cite_start]"encryption": proxy.get('cipher', 'none'), [cite: 230]
                                [cite_start]"security": proxy.get('tls', False), [cite: 231]
                                [cite_start]"sni": proxy.get('sni'), [cite: 231]
                                [cite_start]"fingerprint": proxy.get('client-fingerprint'), [cite: 231]
                                [cite_start]"alpn": proxy.get('alpn'), [cite: 232]
                                [cite_start]"host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('xudp-header', {}).get('Host', ''), [cite: 232]
                                [cite_start]"path": proxy.get('ws-path', '') or proxy.get('grpc-path', ''), [cite: 232]
                                [cite_start]"mode": proxy.get('grpc-mode') [cite: 233]
                            }
                            # 尝试构建 VLESS 链接
                            # 👇 这行是原 658 行，现在修正缩进
                            [cite_start]if vless_node_config.get('uuid') and vless_node_config.get('address') and vless_node_config.get('port'): [cite: 234]
                                [cite_start]vless_uri = f"vless://{vless_node_config['uuid']}@{vless_node_config['address']}:{vless_node_config['port']}" [cite: 234]
                                [cite_start]params = [] [cite: 235]
                                if vless_node_config.get('security'):
                                    [cite_start]params.append("security=tls") [cite: 235]
                                if vless_node_config.get('sni'):
                                    [cite_start]params.append(f"sni={vless_node_config['sni']}") [cite: 236]
                                if vless_node_config.get('flow'):
                                    [cite_start]params.append(f"flow={vless_node_config['flow']}") [cite: 236]
                                if vless_node_config.get('alpn'):
                                    [cite_start]params.append(f"alpn={','.join(vless_node_config['alpn'])}") [cite: 237]
                                if vless_node_config.get('fingerprint'):
                                    [cite_start]params.append(f"fp={vless_node_config['fingerprint']}") [cite: 238]
                                if vless_node_config.get('host'):
                                    [cite_start]params.append(f"host={vless_node_config['host']}") [cite: 238]
                                if vless_node_config.get('path'):
                                    [cite_start]params.append(f"path={vless_node_config['path']}") [cite: 239]
                                if vless_node_config.get('mode'):
                                    [cite_start]params.append(f"mode={vless_node_config['mode']}") [cite: 240]

                                if params:
                                    vless_uri += "?" + [cite_start]"&".join(params) [cite: 240]
                                
                                if proxy.get('name'):
                                    [cite_start]vless_uri += f"#{proxy['name']}" [cite: 242]

                                [cite_start]is_valid, reason = validate_node(vless_uri, "vless") [cite: 242]
                                if is_valid:
                                    [cite_start]unique_nodes.add(vless_uri) [cite: 243]
                                else:
                                    [cite_start]logging.debug(f"丢弃无效 VLESS 节点 (URL: {url}, Clash/Sing-Box JSON): {vless_uri}, 原因: {reason}") [cite: 243]
                
        except json.JSONDecodeError:
            pass # 不是 JSON 格式，忽略
        except Exception as e:
            [cite_start]logging.warning(f"JSON 解析或处理时发生错误 (URL: {url}): {e}") [cite: 244]

        # 尝试解析 YAML
        try:
            [cite_start]yaml_data = yaml.safe_load(text_content) [cite: 245]
            [cite_start]if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list): [cite: 245]
                for proxy in yaml_data['proxies']:
                    if proxy.get('type') == 'vmess':
                        vmess_node = {
                            [cite_start]"v": "2", [cite: 246]
                            [cite_start]"ps": proxy.get('name', 'node'), [cite: 246]
                            [cite_start]"add": proxy.get('server'), [cite: 246]
                            [cite_start]"port": proxy.get('port'), [cite: 247]
                            [cite_start]"id": proxy.get('uuid'), [cite: 247]
                            [cite_start]"aid": proxy.get('alterId', '0'), [cite: 247]
                            [cite_start]"net": proxy.get('network', 'tcp'), [cite: 247]
                            [cite_start]"type": "", [cite: 248]
                            [cite_start]"host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('tls-host', ''), [cite: 248]
                            [cite_start]"path": proxy.get('ws-path', ''), [cite: 248]
                            [cite_start]"tls": "tls" if proxy.get('tls', False) else "" [cite: 249]
                        }
                        [cite_start]vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''} [cite: 249]
                        [cite_start]vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode() [cite: 250]
                        [cite_start]is_valid, reason = validate_node(vmess_str, "vmess") [cite: 250]
                        if is_valid:
                            [cite_start]unique_nodes.add(vmess_str) [cite: 250]
                        else:
                            [cite_start]logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, YAML): {vmess_str}, 原因: {reason}") [cite: 251]
                    elif proxy.get('type') == 'trojan':
                        [cite_start]trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}" [cite: 252]
                        if proxy.get('sni'):
                            [cite_start]trojan_node += f"?sni={proxy['sni']}" [cite: 252]
                        if proxy.get('skip-cert-verify', False):
                            [cite_start]trojan_node += "&allowInsecure=1" [cite: 253]
                        [cite_start]is_valid, reason = validate_node(trojan_node, "trojan") [cite: 253]
                        if is_valid:
                            [cite_start]unique_nodes.add(trojan_node) [cite: 253]
                        else:
                            [cite_start]logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, YAML): {trojan_node}, 原因: {reason}") [cite: 254]
                    elif proxy.get('type') == 'ss':
                        [cite_start]ss_node_parts = [] [cite: 255]
                        [cite_start]method = proxy.get('cipher') [cite: 255]
                        [cite_start]password = proxy.get('password') [cite: 255]
                        [cite_start]server = proxy.get('server') [cite: 255]
                        [cite_start]port = proxy.get('port') [cite: 256]
                        if method and password and server and port:
                            [cite_start]ss_info = f"{method}:{password}@{server}:{port}" [cite: 256]
                            [cite_start]encoded_ss_info = base64.b64encode(ss_info.encode()).decode() [cite: 257]
                            [cite_start]ss_node = f"ss://{encoded_ss_info}" [cite: 257]
                            if proxy.get('name'):
                                [cite_start]ss_node += f"#{proxy['name']}" [cite: 257]
                            
                            [cite_start]is_valid, reason = validate_node(ss_node, "ss") [cite: 258]
                            if is_valid:
                                [cite_start]unique_nodes.add(ss_node) [cite: 259]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 SS 节点 (URL: {url}, Clash YAML): {ss_node}, 原因: {reason}") [cite: 259]
                    elif proxy.get('type') == 'vless':
                        vless_node_config = {
                            [cite_start]"uuid": proxy.get('uuid'), [cite: 260]
                            [cite_start]"address": proxy.get('server'), [cite: 261]
                            [cite_start]"port": proxy.get('port'), [cite: 261]
                            [cite_start]"flow": proxy.get('flow'), [cite: 261]
                            [cite_start]"encryption": proxy.get('cipher', 'none'), [cite: 261]
                            [cite_start]"security": proxy.get('tls', False), [cite: 262]
                            [cite_start]"sni": proxy.get('sni'), [cite: 262]
                            [cite_start]"fingerprint": proxy.get('client-fingerprint'), [cite: 262]
                            [cite_start]"alpn": proxy.get('alpn'), [cite: 262]
                            [cite_start]"host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('xudp-header', {}).get('Host', ''), [cite: 263]
                            [cite_start]"path": proxy.get('ws-path', '') or proxy.get('grpc-path', ''), [cite: 263]
                            [cite_start]"mode": proxy.get('grpc-mode') [cite: 264]
                        }
                        # 尝试构建 VLESS 链接
                        # 👇 这行是原 YAML 部分对应的错误行，现在修正缩进
                        [cite_start]if vless_node_config.get('uuid') and vless_node_config.get('address') and vless_node_config.get('port'): [cite: 264]
                            [cite_start]vless_uri = f"vless://{vless_node_config['uuid']}@{vless_node_config['address']}:{vless_node_config['port']}" [cite: 264]
                            [cite_start]params = [] [cite: 265]
                            if vless_node_config.get('security'):
                                [cite_start]params.append("security=tls") [cite: 265]
                            if vless_node_config.get('sni'):
                                [cite_start]params.append(f"sni={vless_node_config['sni']}") [cite: 266]
                            if vless_node_config.get('flow'):
                                [cite_start]params.append(f"flow={vless_node_config['flow']}") [cite: 266]
                            if vless_node_config.get('alpn'):
                                [cite_start]params.append(f"alpn={','.join(vless_node_config['alpn'])}") [cite: 267]
                            if vless_node_config.get('fingerprint'):
                                [cite_start]params.append(f"fp={vless_node_config['fingerprint']}") [cite: 268]
                            if vless_node_config.get('host'):
                                [cite_start]params.append(f"host={vless_node_config['host']}") [cite: 268]
                            if vless_node_config.get('path'):
                                [cite_start]params.append(f"path={vless_node_config['path']}") [cite: 269]
                            if vless_node_config.get('mode'):
                                [cite_start]params.append(f"mode={vless_node_config['mode']}") [cite: 269]

                            if params:
                                vless_uri += "?" + [cite_start]"&".join(params) [cite: 270]
                            
                            if proxy.get('name'):
                                [cite_start]vless_uri += f"#{proxy['name']}" [cite: 271]

                            [cite_start]is_valid, reason = validate_node(vless_uri, "vless") [cite: 272]
                            if is_valid:
                                [cite_start]unique_nodes.add(vless_uri) [cite: 272]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 VLESS 节点 (URL: {url}, Clash YAML): {vless_uri}, 原因: {reason}") [cite: 273]

        except yaml.YAMLError:
            pass # 不是 YAML 格式，忽略
        except Exception as e:
            [cite_start]logging.warning(f"YAML 解析或处理时发生错误 (URL: {url}): {e}") [cite: 273]

        # 直接从文本内容中匹配所有协议
        for protocol, pattern in NODE_PATTERNS.items():
            [cite_start]for match in re.finditer(pattern, text_content): [cite: 274]
                [cite_start]node = match.group(0) [cite: 274]
                [cite_start]is_valid, reason = validate_node(node, protocol) [cite: 274]
                if is_valid:
                    [cite_start]unique_nodes.add(node) [cite: 274]
                else:
                    [cite_start]logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, 直接匹配): {node}, 原因: {reason}") [cite: 275]

    # 处理 HTML 内容
    if "<html" in content.lower() or "<!doctype html>" in content.lower():
        [cite_start]soup = BeautifulSoup(content, 'html.parser') [cite: 275]
        # 提取所有文本内容
        for text_element in soup.find_all(string=True):
            [cite_start]text = str(text_element) [cite: 276]
            # 在 HTML 文本中直接匹配节点
            for protocol, pattern in NODE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    [cite_start]node = match.group(0) [cite: 276]
                    [cite_start]is_valid, reason = validate_node(node, protocol) [cite: 276]
                    if is_valid:
                        [cite_start]unique_nodes.add(node) [cite: 277]
                    else:
                        [cite_start]logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, HTML 文本): {node}, 原因: {reason}") [cite: 277]
            
            # 在 HTML 文本中寻找可能的 Base64 编码的节点
            for word_match in re.finditer(r'\b[A-Za-z0-9+/]{20,}=*\b', text): # 匹配可能包含Base64的单词
                [cite_start]word = word_match.group(0) [cite: 278]
                padding_needed = len(word) % 4
                if padding_needed != 0:
                    [cite_start]word += '=' * (4 - padding_needed) # 添加填充 [cite: 279]

                try:
                    # 尝试 Base64 解码
                    [cite_start]decoded_text = base64.b64decode(word.encode('ascii', 'ignore')).decode('utf-8', errors='ignore') [cite: 279]
                    for protocol, pattern in NODE_PATTERNS.items():
                        [cite_start]for match in re.finditer(pattern, decoded_text): [cite: 280]
                            [cite_start]node = match.group(0) [cite: 280]
                            [cite_start]is_valid, reason = validate_node(node, protocol) [cite: 280]
                            if is_valid:
                                [cite_start]unique_nodes.add(node) [cite: 281]
                            else:
                                [cite_start]logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, HTML Base64): {node}, 原因: {reason}") [cite: 282]
                except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                    [cite_start]logging.debug(f"HTML 内容中的 Base64 解码失败或无效: {word}, 错误: {e}") [cite: 282]
                    pass # 非 Base64 字符串，忽略

    [cite_start]return list(unique_nodes) [cite: 282]

async def process_url(url: str, all_nodes_writer: aiofiles.threadpool.text.AsyncTextIOWrapper, semaphore: asyncio.Semaphore):
    """
    处理单个 URL，获取内容，提取节点并写入文件。
    
    Args:
        url (str): 要处理的 URL。
        all_nodes_writer: 异步文件写入对象，用于写入所有节点。
        semaphore (asyncio.Semaphore): 并发控制信号量。
        
    Returns:
        tuple[str, int]: URL 和提取的节点数量。
    """
    async with semaphore:
        [cite_start]logging.info(f"开始处理 URL: {url}") [cite: 284]
        [cite_start]content = await get_url_content(url) [cite: 284]

        if not content:
            [cite_start]logging.warning(f"无法获取 {url} 的内容，跳过该 URL 的节点提取。") [cite: 284]
            [cite_start]return url, 0 [cite: 284]

        [cite_start]logging.info(f"开始解析 {url} 的内容...") [cite: 284]
        [cite_start]unique_nodes = await extract_nodes_from_content(url, content) [cite: 284]
        [cite_start]logging.info(f"完成解析 {url} 的内容。提取到 {len(unique_nodes)} 个有效节点。") [cite: 284]

        # 将提取到的节点写入以 URL MD5 命名的文件
        [cite_start]safe_url_name = hashlib.md5(url.encode()).hexdigest() [cite: 285]
        [cite_start]url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt") [cite: 285]
        try:
            async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes:
                    [cite_start]await f.write(f"{node}\n") [cite: 285]
            [cite_start]logging.info(f"URL: {url} 的节点已保存到 {url_output_file}") [cite: 285]
        except IOError as e:
            [cite_start]logging.error(f"写入 URL 节点文件 {url_output_file} 失败: {e}") [cite: 286]
            [cite_start]return url, 0 # 写入失败也返回 0 个节点 [cite: 286]

        # 将提取到的节点也写入总节点文件
        try:
            for node in unique_nodes:
                [cite_start]await all_nodes_writer.write(f"{node}\n") [cite: 287]
        except IOError as e:
            [cite_start]logging.error(f"写入总节点文件 {ALL_NODES_FILE} 失败: {e}") [cite: 287]
            # 这里不返回 0，因为节点已经提取成功，只是写入all.txt失败

        [cite_start]return url, len(unique_nodes) [cite: 287]

async def main():
    """
    主函数，读取 sources.list 并并行处理 URL。
    """
    [cite_start]await clean_old_cache_files(CLEANUP_THRESHOLD_HOURS) [cite: 287]

    if not os.path.exists('sources.list'):
        [cite_start]logging.error("sources.list 文件不存在，请创建并添加 URL。") [cite: 287]
        return

    with open('sources.list', 'r', encoding='utf-8') as f:
        [cite_start]urls = [line.strip() for line in f if line.strip() and not line.startswith('#')] [cite: 288]

    # 为没有协议的 URL 添加默认协议（https://）
    [cite_start]processed_urls = [] [cite: 288]
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            [cite_start]fixed_url = f"https://{url}" [cite: 288]
            [cite_start]logging.info(f"URL {url} 缺少协议，已自动添加为 {fixed_url}") [cite: 288]
            [cite_start]processed_urls.append(fixed_url) [cite: 288]
        else:
            [cite_start]processed_urls.append(url) [cite: 289]

    if not processed_urls:
        [cite_start]logging.warning("sources.list 中没有找到有效的 URL。") [cite: 289]
        return

    [cite_start]node_counts = defaultdict(int) [cite: 289]
    [cite_start]semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) [cite: 289]

    # 确保 all.txt 在开始处理前是空的
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        [cite_start]await f.truncate(0) # 清空文件 [cite: 289]

    # 在这里打开一次 all_nodes_writer，并在所有任务中共享
    async with aiofiles.open(ALL_NODES_FILE, 'a', encoding='utf-8') as all_nodes_writer:
        [cite_start]tasks = [process_url(url, all_nodes_writer, semaphore) for url in processed_urls] [cite: 290]
        [cite_start]results = await asyncio.gather(*tasks, return_exceptions=True) [cite: 290]

        for result in results:
            if isinstance(result, tuple):
                url, count = result
                node_counts[url] = count
            else:
                [cite_start]logging.error(f"处理 URL 时发生异常: {result}") [cite: 291]

    try:
        async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8', newline='') as f:
            [cite_start]await f.write("URL,NodeCount\n") [cite: 291]
            for url, count in node_counts.items():
                escaped_url = '"{}"'.format(url.replace('"', '""'))
                [cite_start]await f.write(f"{escaped_url},{count}\n") [cite: 292]
    except IOError as e:
        [cite_start]logging.error(f"写入节点计数 CSV 文件 {NODE_COUNT_CSV} 失败: {e}") [cite: 292]

    [cite_start]logging.info("所有 URL 处理完成。") [cite: 292]

if __name__ == "__main__":
    [cite_start]asyncio.run(main()) [cite: 292]
