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
    "hysteria2": r"hysteria2:\/\/(?:[^:@\/]+(?::[^@\/]*)?@)?(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
    "vmess": r"vmess:\/\/[a-zA-Z0-9\-_+=/]+",
    "trojan": r"trojan:\/\/[^@]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
    "ss": r"ss:\/\/(?:[a-zA-Z0-9\-_]+:[^@\/]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+|[a-zA-Z0-9\-_+=/]+)(?:#.*)?",
    "ssr": r"ssr:\/\/[a-zA-Z0-9\-_+=/]+",
    "vless": r"vless:\/\/[0-9a-fA-F\-]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
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
        return False

def is_valid_port(port: str) -> bool:
    """验证端口号是否有效（1-65535）。"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def is_valid_host(host: str) -> bool:
    """验证主机是否为有效的域名或 IP 地址（包括 IPv6）。"""
    if not host:
        return False
    # 稍微放宽对主机名的正则表达式，使其更通用
    # 允许包含非标准DNS字符（例如下划线），这在某些情况下可能是允许的
    return bool(re.match(r'^(?:\[[0-9a-fA-F:\.]+\]|[a-zA-Z0-9\.\-_]+)$', host))

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
            return False, "格式不匹配，缺少 password、host 或 port"
        password, host, port = match.groups()
        if not password:
            return False, "password 为空"
        if not is_valid_host(host):
            return False, f"无效的主机: {host}"
        if not is_valid_port(port):
            return False, f"无效的端口: {port}"
        return True, ""

    elif protocol == "vmess":
        if not node.startswith("vmess://"):
            return False, "缺少 vmess:// 前缀"
        try:
            # 尝试解码，忽略非 Base64 字符
            decoded = base64.b64decode(node[8:].strip('=').encode('ascii', 'ignore')).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            required_fields = {'v', 'ps', 'add', 'port', 'id', 'aid', 'net'}
            if not all(field in data for field in required_fields):
                return False, f"缺少必要字段: {required_fields - set(data.keys())}"
            if not is_valid_host(data['add']):
                return False, f"无效的主机: {data['add']}"
            if not is_valid_port(str(data['port'])):
                return False, f"无效的端口: {data['port']}"
            if not is_valid_uuid(data['id']):
                return False, f"无效的 UUID: {data['id']}"
            if not str(data['aid']).isdigit():
                return False, f"无效的 alterId: {data['aid']}"
            if data['net'] not in {'tcp', 'ws', 'h2', 'grpc', 'kcp'}: # 添加 kcp 等常见网络类型
                return False, f"无效的网络类型: {data['net']}"
            return True, ""
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            return False, f"Base64 解码或 JSON 解析失败: {e}"

    elif protocol == "trojan":
        match = re.match(r"trojan:\/\/([^@]+)@([^:]+):(\d+)(?:\/|\?|$)", node)
        if not match:
            return False, "格式不匹配，缺少 password、host 或 port"
        password, host, port = match.groups()
        if not password:
            return False, "password 为空"
        if not is_valid_host(host):
            return False, f"无效的主机: {host}"
        if not is_valid_port(port):
            return False, f"无效的端口: {port}"
        return True, ""

    elif protocol == "ss":
        # 简化 SS 匹配，优先处理 Base64 解码后的格式
        if node.startswith("ss://"):
            try:
                # 尝试解码 Base64 部分
                encoded_part = node[5:].split('#')[0].strip('=')
                # 确保只包含 Base64 安全字符，忽略其他
                encoded_part_ascii = encoded_part.encode('ascii', 'ignore')
                decoded = base64.b64decode(encoded_part_ascii).decode('utf-8', errors='ignore')

                match = re.match(r"([a-zA-Z0-9\-_]+):([^@]+)@([^:]+):(\d+)", decoded)
                if not match:
                    return False, "Base64 解码后格式不匹配"
                
                method, password, host, port = match.groups()
                if method not in SS_METHODS:
                    return False, f"不支持的加密方法: {method}"
                if not password:
                    return False, "password 为空"
                if not is_valid_host(host):
                    return False, f"无效的主机: {host}"
                if not is_valid_port(port):
                    return False, f"无效的端口: {port}"
                return True, ""
            except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                return False, f"Base64 解码失败或格式错误: {e}"
        return False, "缺少 ss:// 前缀" # 如果没有 ss:// 前缀，则认为不是 SS 节点

    elif protocol == "ssr":
        if not node.startswith("ssr://"):
            return False, "缺少 ssr:// 前缀"
        try:
            # 尝试解码，忽略非 Base64 字符
            decoded = base64.b64decode(node[6:].strip('=').encode('ascii', 'ignore')).decode('utf-8', errors='ignore')
            parts = decoded.split(':')
            if len(parts) < 6:
                return False, "格式不匹配，缺少必要字段"
            
            host, port, protocol_ssr, method, obfs, password_encoded = parts[:6] # 修改变量名以避免冲突
            
            if not is_valid_host(host):
                return False, f"无效的主机: {host}"
            if not is_valid_port(port):
                return False, f"无效的端口: {port}"
            if protocol_ssr not in SSR_PROTOCOLS:
                return False, f"不支持的协议: {protocol_ssr}"
            if method not in SS_METHODS:
                return False, f"不支持的加密方法: {method}"
            if obfs not in SSR_OBFS:
                return False, f"不支持的混淆: {obfs}"
            
            try:
                # SSR 的密码部分本身可能是 Base64 编码的
                decoded_password = base64.b64decode(password_encoded.encode('ascii', 'ignore')).decode('utf-8', errors='ignore')
                if not decoded_password: # 密码为空也视为无效
                    return False, "password 为空或解码后为空"
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                # 如果密码部分不是 Base64 编码，或者解码失败，则直接使用原始密码部分
                if not password_encoded:
                    return False, "password 为空"
            
            return True, ""
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            return False, f"Base64 解码失败: {e}"

    elif protocol == "vless":
        match = re.match(r"vless:\/\/([0-9a-fA-F\-]+)@([^:]+):(\d+)(?:\/|\?|$)", node)
        if not match:
            return False, "格式不匹配，缺少 uuid、host 或 port"
        uuid_str, host, port = match.groups()
        if not is_valid_uuid(uuid_str):
            return False, f"无效的 UUID: {uuid_str}"
        if not is_valid_host(host):
            return False, f"无效的主机: {host}"
        if not is_valid_port(port):
            return False, f"无效的端口: {port}"
        return True, ""

    return False, "未知协议"

async def clean_old_cache_files(cleanup_threshold_hours: int):
    """
    清理 data/cache 目录中过期的或不再使用的缓存文件。
    删除修改时间早于指定阈值的文件。
    
    Args:
        cleanup_threshold_hours (int): 缓存文件清理的阈值（小时）。
    """
    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(hours=cleanup_threshold_hours)
    
    logging.info(f"开始清理缓存目录: {CACHE_DIR}，将删除修改时间早于 {cutoff_time} 的文件。")
    
    deleted_count = 0
    try:
        for filename in os.listdir(CACHE_DIR):
            file_path = os.path.join(CACHE_DIR, filename)
            if os.path.isfile(file_path):
                try:
                    file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                    if file_mtime < cutoff_time:
                        os.remove(file_path)
                        logging.debug(f"已删除过期缓存文件: {filename}")
                        deleted_count += 1
                except OSError as e:
                    logging.warning(f"无法删除文件 {file_path}: {e}")
        logging.info(f"缓存清理完成，共删除 {deleted_count} 个文件。")
    except FileNotFoundError:
        logging.info(f"缓存目录 {CACHE_DIR} 不存在，无需清理。")
    except Exception as e:
        logging.error(f"清理缓存时发生错误: {e}")

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
        logging.info(f"尝试从 {url.split('://')[0].upper()} 获取内容: {url} (User-Agent: {headers.get('User-Agent', 'N/A')})")
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response
    # 捕获更通用的 httpx.RequestError
    except httpx.RequestError as e:
        logging.warning(f"请求 {url} 时发生网络或连接错误: {e}")
        # 如果是 HTTPS 错误，尝试禁用 SSL 验证
        if isinstance(e, httpx.ConnectError) and "SSL" in str(e):
            logging.info(f"SSL 连接错误，尝试禁用 SSL 验证: {url}")
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as retry_client:
                try:
                    response = await retry_client.get(url, headers=headers)
                    response.raise_for_status()
                    return response
                except httpx.HTTPStatusError as e_retry:
                    logging.error(f"禁用 SSL 验证后，获取 {url} 时发生 HTTP 状态错误: {e_retry}")
                except httpx.RequestError as e_retry:
                    logging.error(f"禁用 SSL 验证后，获取 {url} 时发生网络请求错误: {e_retry}")
        # 如果是 HTTP 到 HTTPS 的回退（但仅在原始请求是 HTTP 时才尝试）
        elif url.startswith("http://") and original_protocol_url.startswith("http://"):
            https_url = url.replace("http://", "https://")
            logging.info(f"尝试从 HTTPS 回退获取内容: {https_url}")
            try:
                fallback_headers = dict(headers)
                fallback_headers.pop('If-None-Match', None)
                fallback_headers.pop('If-Modified-Since', None)
                response_https = await client.get(https_url, headers=fallback_headers)
                response_https.raise_for_status()
                return response_https
            except httpx.HTTPStatusError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 状态错误: {e_https}")
            except httpx.RequestError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 网络请求错误: {e_https}")
        else:
            logging.error(f"获取 {url} 时发生未知网络错误: {e}")
    except httpx.HTTPStatusError as e:
        logging.error(f"获取 {url} 时发生 HTTP 状态错误: {e}")
        # 这里移除 HTTP 到 HTTPS 的回退逻辑，因为它已经在 RequestError 中处理
        # 避免重复尝试或逻辑混乱
    except Exception as e:
        logging.error(f"获取 {url} 时发生未知错误: {e}")
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
    cache_entry_path = os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + ".json")
    
    cached_data = None
    if use_cache and os.path.exists(cache_entry_path):
        try:
            async with aiofiles.open(cache_entry_path, 'r', encoding='utf-8') as f:
                cached_data = json.loads(await f.read())
            
            cache_timestamp_str = cached_data.get('timestamp', datetime.datetime.min.isoformat())
            cache_timestamp = datetime.datetime.fromisoformat(cache_timestamp_str)
            if (datetime.datetime.now() - cache_timestamp).total_seconds() / 3600 >= CACHE_EXPIRATION_HOURS:
                logging.info(f"缓存 {url} 已过期（超过 {CACHE_EXPIRATION_HOURS} 小时），将重新检查更新。")
                cached_data = None
            else:
                logging.info(f"缓存 {url} 有效，尝试使用缓存进行条件请求。")
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            logging.warning(f"读取或解析缓存文件 {cache_entry_path} 失败: {e}，将重新获取。")
            cached_data = None

    async with httpx.AsyncClient(timeout=10, verify=True, follow_redirects=True) as client:
        headers_for_request = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        if cached_data:
            if cached_data.get('etag'):
                headers_for_request['If-None-Match'] = cached_data['etag']
            if cached_data.get('last-modified'):
                headers_for_request['If-Modified-Since'] = cached_data['last-modified']

        response = await _fetch_url_with_retry(client, url, headers_for_request, url)

        if response:
            if response.status_code == 304 and cached_data and cached_data.get('content'):
                logging.info(f"URL: {url} 内容未更新 (304 Not Modified)，从缓存读取。")
                return base64.b64decode(cached_data['content']).decode('utf-8', errors='ignore')
            else:
                content = response.text
                new_cached_data = {
                    "content": base64.b64encode(content.encode('utf-8')).decode('ascii'),
                    "timestamp": datetime.datetime.now().isoformat()
                }
                if 'etag' in response.headers:
                    new_cached_data['etag'] = response.headers['etag']
                if 'last-modified' in response.headers:
                    new_cached_data['last-modified'] = response.headers['last-modified']

                try:
                    async with aiofiles.open(cache_entry_path, 'w', encoding='utf-8') as f:
                        await f.write(json.dumps(new_cached_data, ensure_ascii=False))
                    logging.info(f"URL: {url} 内容已更新，已写入缓存。")
                except (IOError, json.JSONEncodeError) as e:
                    logging.error(f"写入缓存文件 {cache_entry_path} 失败: {e}")
                
                return content
        else:
            logging.warning(f"无法获取 URL: {url} 的内容，跳过该 URL 的节点提取。")
            return None

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
            clean_content = content.strip().replace(" ", "").replace("\n", "").replace("\r", "")
            padding_needed = len(clean_content) % 4
            if padding_needed != 0:
                clean_content += '=' * (4 - padding_needed)
            
            decoded_content_attempt = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
            logging.debug(f"成功 Base64 解码内容 (URL: {url})")
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            logging.debug(f"Base64 解码失败 (URL: {url}): {e}")
            pass # 不是有效的 Base64，继续按原始文本处理

    contents_to_search = [content]
    if decoded_content_attempt and decoded_content_attempt != content: # 避免重复搜索
        contents_to_search.append(decoded_content_attempt)

    for text_content in contents_to_search:
        # 尝试解析 JSON
        try:
            json_data = json.loads(text_content)
            if isinstance(json_data, list):
                for item in json_data:
                    if isinstance(item, dict) and 'v' in item and 'ps' in item and 'add' in item:
                        vmess_node = "vmess://" + base64.b64encode(json.dumps(item, separators=(',', ':')).encode()).decode()
                        is_valid, reason = validate_node(vmess_node, "vmess")
                        if is_valid:
                            unique_nodes.add(vmess_node)
                        else:
                            logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, JSON 列表): {vmess_node}, 原因: {reason}")
            elif isinstance(json_data, dict):
                # 处理 V2RayN/Clash config 格式
                if 'outbounds' in json_data and isinstance(json_data['outbounds'], list):
                    for outbound in json_data['outbounds']:
                        if outbound.get('protocol') == 'vmess' and outbound.get('settings', {}).get('vnext'):
                            # Vmess 节点通常在 vnext[0].users[0]
                            server_settings = outbound['settings']['vnext'][0]
                            user_settings = server_settings['users'][0]
                            vmess_config = {
                                "v": "2",
                                "ps": outbound.get('tag', 'node'), # 使用 tag 或默认名
                                "add": server_settings.get('address'),
                                "port": server_settings.get('port'),
                                "id": user_settings.get('id'),
                                "aid": user_settings.get('alterId', '0'),
                                "net": outbound.get('streamSettings', {}).get('network', 'tcp'),
                                "type": outbound.get('streamSettings', {}).get('type', ''),
                                "host": outbound.get('streamSettings', {}).get('wsSettings', {}).get('headers', {}).get('Host', ''),
                                "path": outbound.get('streamSettings', {}).get('wsSettings', {}).get('path', ''),
                                "tls": "tls" if outbound.get('streamSettings', {}).get('security') == 'tls' else ""
                            }
                            vmess_config = {k: v for k, v in vmess_config.items() if v is not None and v != ''}
                            vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode()).decode()
                            is_valid, reason = validate_node(vmess_str, "vmess")
                            if is_valid:
                                unique_nodes.add(vmess_str)
                            else:
                                logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, V2Ray 配置): {vmess_str}, 原因: {reason}")
                        elif outbound.get('protocol') == 'trojan' and outbound.get('settings', {}).get('servers'):
                            server_settings = outbound['settings']['servers'][0]
                            trojan_node = f"trojan://{server_settings.get('password')}@{server_settings.get('address')}:{server_settings.get('port')}"
                            if outbound.get('streamSettings', {}).get('security') == 'tls':
                                if server_settings.get('sni'):
                                    trojan_node += f"?sni={server_settings['sni']}"
                                elif outbound.get('streamSettings', {}).get('tlsSettings', {}).get('serverName'):
                                    trojan_node += f"?sni={outbound['streamSettings']['tlsSettings']['serverName']}"
                                # V2Ray config 中没有直接的 allowInsecure 对应，这里暂不处理
                            is_valid, reason = validate_node(trojan_node, "trojan")
                            if is_valid:
                                unique_nodes.add(trojan_node)
                            else:
                                logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, V2Ray 配置): {trojan_node}, 原因: {reason}")
                
                # 处理 Clash/Sing-Box proxies 格式
                elif 'proxies' in json_data and isinstance(json_data['proxies'], list):
                    for proxy in json_data['proxies']:
                        if proxy.get('type') == 'vmess':
                            vmess_node = {
                                "v": "2",
                                "ps": proxy.get('name', 'node'),
                                "add": proxy.get('server'),
                                "port": proxy.get('port'),
                                "id": proxy.get('uuid'),
                                "aid": proxy.get('alterId', '0'),
                                "net": proxy.get('network', 'tcp'),
                                "type": "", # Clash 配置中可能没有直接的 type 字段
                                "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('tls-host', ''), # 兼容不同字段
                                "path": proxy.get('ws-path', ''),
                                "tls": "tls" if proxy.get('tls', False) else ""
                            }
                            vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                            vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode()
                            is_valid, reason = validate_node(vmess_str, "vmess")
                            if is_valid:
                                unique_nodes.add(vmess_str)
                            else:
                                logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, Clash/Sing-Box JSON): {vmess_str}, 原因: {reason}")
                        elif proxy.get('type') == 'trojan':
                            trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}"
                            if proxy.get('sni'):
                                trojan_node += f"?sni={proxy['sni']}"
                            if proxy.get('skip-cert-verify', False): # Clash 的 skip-cert-verify
                                trojan_node += "&allowInsecure=1"
                            is_valid, reason = validate_node(trojan_node, "trojan")
                            if is_valid:
                                unique_nodes.add(trojan_node)
                            else:
                                logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, Clash/Sing-Box JSON): {trojan_node}, 原因: {reason}")
                        elif proxy.get('type') == 'ss':
                            # Clash ss 类型解析
                            ss_node_parts = []
                            method = proxy.get('cipher')
                            password = proxy.get('password')
                            server = proxy.get('server')
                            port = proxy.get('port')
                            if method and password and server and port:
                                # 构建 ss://base64encoded_info 格式
                                ss_info = f"{method}:{password}@{server}:{port}"
                                encoded_ss_info = base64.b64encode(ss_info.encode()).decode()
                                ss_node = f"ss://{encoded_ss_info}"
                                if proxy.get('name'):
                                    ss_node += f"#{proxy['name']}"
                                
                                is_valid, reason = validate_node(ss_node, "ss")
                                if is_valid:
                                    unique_nodes.add(ss_node)
                                else:
                                    logging.debug(f"丢弃无效 SS 节点 (URL: {url}, Clash JSON): {ss_node}, 原因: {reason}")
                        elif proxy.get('type') == 'vless':
                             # Clash/Sing-Box vless 类型解析
                            vless_node_config = {
                                "uuid": proxy.get('uuid'),
                                "address": proxy.get('server'),
                                "port": proxy.get('port'),
                                "flow": proxy.get('flow'),
                                "encryption": proxy.get('cipher', 'none'),
                                "security": proxy.get('tls', False),
                                "sni": proxy.get('sni'),
                                "fingerprint": proxy.get('client-fingerprint'),
                                "alpn": proxy.get('alpn'),
                                "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('xudp-header', {}).get('Host', ''),
                                "path": proxy.get('ws-path', '') or proxy.get('grpc-path', ''),
                                "mode": proxy.get('grpc-mode')
                            }
                            # 尝试构建 VLESS 链接
                            if vless_node_config.get('uuid') and vless_node_config.get('address') and vless_node_config.get('port'):
                                vless_uri = f"vless://{vless_node_config['uuid']}@{vless_node_config['address']}:{vless_node_config['port']}"
                                params = []
                                if vless_node_config.get('security'):
                                    params.append("security=tls")
                                if vless_node_config.get('sni'):
                                    params.append(f"sni={vless_node_config['sni']}")
                                if vless_node_config.get('flow'):
                                    params.append(f"flow={vless_node_config['flow']}")
                                if vless_node_config.get('alpn'):
                                    params.append(f"alpn={','.join(vless_node_config['alpn'])}")
                                if vless_node_config.get('fingerprint'):
                                    params.append(f"fp={vless_node_config['fingerprint']}")
                                if vless_node_config.get('host'):
                                    params.append(f"host={vless_node_config['host']}")
                                if vless_node_config.get('path'):
                                    params.append(f"path={vless_node_config['path']}")
                                if vless_node_config.get('mode'):
                                    params.append(f"mode={vless_node_config['mode']}")

                                if params:
                                    vless_uri += "?" + "&".join(params)
                                
                                if proxy.get('name'):
                                    vless_uri += f"#{proxy['name']}"

                                is_valid, reason = validate_node(vless_uri, "vless")
                                if is_valid:
                                    unique_nodes.add(vless_uri)
                                else:
                                    logging.debug(f"丢弃无效 VLESS 节点 (URL: {url}, Clash/Sing-Box JSON): {vless_uri}, 原因: {reason}")
                                
        except json.JSONDecodeError:
            pass # 不是 JSON 格式，忽略
        except Exception as e:
            logging.warning(f"JSON 解析或处理时发生错误 (URL: {url}): {e}")

        # 尝试解析 YAML
        try:
            yaml_data = yaml.safe_load(text_content)
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                for proxy in yaml_data['proxies']:
                    if proxy.get('type') == 'vmess':
                        vmess_node = {
                            "v": "2",
                            "ps": proxy.get('name', 'node'),
                            "add": proxy.get('server'),
                            "port": proxy.get('port'),
                            "id": proxy.get('uuid'),
                            "aid": proxy.get('alterId', '0'),
                            "net": proxy.get('network', 'tcp'),
                            "type": "",
                            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('tls-host', ''),
                            "path": proxy.get('ws-path', ''),
                            "tls": "tls" if proxy.get('tls', False) else ""
                        }
                        vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                        vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode()
                        is_valid, reason = validate_node(vmess_str, "vmess")
                        if is_valid:
                            unique_nodes.add(vmess_str)
                        else:
                            logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}, YAML): {vmess_str}, 原因: {reason}")
                    elif proxy.get('type') == 'trojan':
                        trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}"
                        if proxy.get('sni'):
                            trojan_node += f"?sni={proxy['sni']}"
                        if proxy.get('skip-cert-verify', False):
                            trojan_node += "&allowInsecure=1"
                        is_valid, reason = validate_node(trojan_node, "trojan")
                        if is_valid:
                            unique_nodes.add(trojan_node)
                        else:
                            logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}, YAML): {trojan_node}, 原因: {reason}")
                    elif proxy.get('type') == 'ss':
                        ss_node_parts = []
                        method = proxy.get('cipher')
                        password = proxy.get('password')
                        server = proxy.get('server')
                        port = proxy.get('port')
                        if method and password and server and port:
                            ss_info = f"{method}:{password}@{server}:{port}"
                            encoded_ss_info = base64.b64encode(ss_info.encode()).decode()
                            ss_node = f"ss://{encoded_ss_info}"
                            if proxy.get('name'):
                                ss_node += f"#{proxy['name']}"
                            
                            is_valid, reason = validate_node(ss_node, "ss")
                            if is_valid:
                                unique_nodes.add(ss_node)
                            else:
                                logging.debug(f"丢弃无效 SS 节点 (URL: {url}, Clash YAML): {ss_node}, 原因: {reason}")
                    elif proxy.get('type') == 'vless':
                         vless_node_config = {
                            "uuid": proxy.get('uuid'),
                            "address": proxy.get('server'),
                            "port": proxy.get('port'),
                            "flow": proxy.get('flow'),
                            "encryption": proxy.get('cipher', 'none'),
                            "security": proxy.get('tls', False),
                            "sni": proxy.get('sni'),
                            "fingerprint": proxy.get('client-fingerprint'),
                            "alpn": proxy.get('alpn'),
                            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('xudp-header', {}).get('Host', ''),
                            "path": proxy.get('ws-path', '') or proxy.get('grpc-path', ''),
                            "mode": proxy.get('grpc-mode')
                        }
                        if vless_node_config.get('uuid') and vless_node_config.get('address') and vless_node_config.get('port'):
                            vless_uri = f"vless://{vless_node_config['uuid']}@{vless_node_config['address']}:{vless_node_config['port']}"
                            params = []
                            if vless_node_config.get('security'):
                                params.append("security=tls")
                            if vless_node_config.get('sni'):
                                params.append(f"sni={vless_node_config['sni']}")
                            if vless_node_config.get('flow'):
                                params.append(f"flow={vless_node_config['flow']}")
                            if vless_node_config.get('alpn'):
                                params.append(f"alpn={','.join(vless_node_config['alpn'])}")
                            if vless_node_config.get('fingerprint'):
                                params.append(f"fp={vless_node_config['fingerprint']}")
                            if vless_node_config.get('host'):
                                params.append(f"host={vless_node_config['host']}")
                            if vless_node_config.get('path'):
                                params.append(f"path={vless_node_config['path']}")
                            if vless_node_config.get('mode'):
                                params.append(f"mode={vless_node_config['mode']}")

                            if params:
                                vless_uri += "?" + "&".join(params)
                            
                            if proxy.get('name'):
                                vless_uri += f"#{proxy['name']}"

                            is_valid, reason = validate_node(vless_uri, "vless")
                            if is_valid:
                                unique_nodes.add(vless_uri)
                            else:
                                logging.debug(f"丢弃无效 VLESS 节点 (URL: {url}, Clash YAML): {vless_uri}, 原因: {reason}")

        except yaml.YAMLError:
            pass # 不是 YAML 格式，忽略
        except Exception as e:
            logging.warning(f"YAML 解析或处理时发生错误 (URL: {url}): {e}")

        # 直接从文本内容中匹配所有协议
        for protocol, pattern in NODE_PATTERNS.items():
            for match in re.finditer(pattern, text_content):
                node = match.group(0)
                is_valid, reason = validate_node(node, protocol)
                if is_valid:
                    unique_nodes.add(node)
                else:
                    logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, 直接匹配): {node}, 原因: {reason}")

    # 处理 HTML 内容
    if "<html" in content.lower() or "<!doctype html>" in content.lower():
        soup = BeautifulSoup(content, 'html.parser')
        # 提取所有文本内容
        for text_element in soup.find_all(string=True):
            text = str(text_element)
            # 在 HTML 文本中直接匹配节点
            for protocol, pattern in NODE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    node = match.group(0)
                    is_valid, reason = validate_node(node, protocol)
                    if is_valid:
                        unique_nodes.add(node)
                    else:
                        logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, HTML 文本): {node}, 原因: {reason}")
            
            # 在 HTML 文本中寻找可能的 Base64 编码的节点
            for word_match in re.finditer(r'\b[A-Za-z0-9+/]{20,}=*\b', text): # 匹配可能包含Base64的单词
                word = word_match.group(0)
                padding_needed = len(word) % 4
                if padding_needed != 0:
                    word += '=' * (4 - padding_needed) # 添加填充

                try:
                    # 尝试 Base64 解码
                    decoded_text = base64.b64decode(word.encode('ascii', 'ignore')).decode('utf-8', errors='ignore')
                    for protocol, pattern in NODE_PATTERNS.items():
                        for match in re.finditer(pattern, decoded_text):
                            node = match.group(0)
                            is_valid, reason = validate_node(node, protocol)
                            if is_valid:
                                unique_nodes.add(node)
                            else:
                                logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}, HTML Base64): {node}, 原因: {reason}")
                except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                    logging.debug(f"HTML 内容中的 Base64 解码失败或无效: {word}, 错误: {e}")
                    pass # 非 Base64 字符串，忽略

    return list(unique_nodes)


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
        logging.info(f"开始处理 URL: {url}")
        content = await get_url_content(url)

        if not content:
            logging.warning(f"无法获取 {url} 的内容，跳过该 URL 的节点提取。")
            return url, 0

        logging.info(f"开始解析 {url} 的内容...")
        unique_nodes = await extract_nodes_from_content(url, content)
        logging.info(f"完成解析 {url} 的内容。提取到 {len(unique_nodes)} 个有效节点。")

        # 将提取到的节点写入以 URL MD5 命名的文件
        safe_url_name = hashlib.md5(url.encode()).hexdigest()
        url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
        try:
            async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes:
                    await f.write(f"{node}\n")
            logging.info(f"URL: {url} 的节点已保存到 {url_output_file}")
        except IOError as e:
            logging.error(f"写入 URL 节点文件 {url_output_file} 失败: {e}")
            return url, 0 # 写入失败也返回 0 个节点

        # 将提取到的节点也写入总节点文件
        try:
            for node in unique_nodes:
                await all_nodes_writer.write(f"{node}\n")
        except IOError as e:
            logging.error(f"写入总节点文件 {ALL_NODES_FILE} 失败: {e}")
            # 这里不返回 0，因为节点已经提取成功，只是写入all.txt失败

        return url, len(unique_nodes)

async def main():
    """
    主函数，读取 sources.list 并并行处理 URL。
    """
    await clean_old_cache_files(CLEANUP_THRESHOLD_HOURS)

    if not os.path.exists('sources.list'):
        logging.error("sources.list 文件不存在，请创建并添加 URL。")
        return

    with open('sources.list', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # 为没有协议的 URL 添加默认协议（https://）
    processed_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            fixed_url = f"https://{url}"
            logging.info(f"URL {url} 缺少协议，已自动添加为 {fixed_url}")
            processed_urls.append(fixed_url)
        else:
            processed_urls.append(url)

    if not processed_urls:
        logging.warning("sources.list 中没有找到有效的 URL。")
        return

    node_counts = defaultdict(int)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    # 确保 all.txt 在开始处理前是空的
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        await f.truncate(0) # 清空文件

    # 在这里打开一次 all_nodes_writer，并在所有任务中共享
    async with aiofiles.open(ALL_NODES_FILE, 'a', encoding='utf-8') as all_nodes_writer:
        tasks = [process_url(url, all_nodes_writer, semaphore) for url in processed_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                url, count = result
                node_counts[url] = count
            else:
                logging.error(f"处理 URL 时发生异常: {result}")

    try:
        async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8', newline='') as f:
            await f.write("URL,NodeCount\n")
            for url, count in node_counts.items():
                escaped_url = '"{}"'.format(url.replace('"', '""'))
                await f.write(f"{escaped_url},{count}\n")
    except IOError as e:
        logging.error(f"写入节点计数 CSV 文件 {NODE_COUNT_CSV} 失败: {e}")

    logging.info("所有 URL 处理完成。")

if __name__ == "__main__":
    asyncio.run(main())
