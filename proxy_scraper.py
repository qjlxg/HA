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
import time # Added: Required for time.sleep() in retry logic

# 配置日志，同时输出到控制台和文件
logging.basicConfig(
    level=logging.INFO,
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
    return bool(re.match(r'^(?:\[[0-9a-fA-F:\.]+\]|[a-zA-Z0-9\.\-]+)$', host))

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
            decoded = base64.b64decode(node[8:].strip('=')).decode('utf-8')
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
            if data['net'] not in {'tcp', 'ws', 'h2', 'grpc'}:
                return False, f"无效的网络类型: {data['net']}"
            return True, ""
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
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
        if node.startswith("ss://["):
            return False, "不支持 SIP002 格式的 SS 节点"
        match = re.match(r"ss:\/\/([a-zA-Z0-9\-_]+):([^@]+)@([^:]+):(\d+)(?:#|$)", node)
        if not match:
            try:
                decoded = base64.b64decode(node[5:].split('#')[0].strip('=')).decode('utf-8')
                match = re.match(r"([a-zA-Z0-9\-_]+):([^@]+)@([^:]+):(\d+)", decoded)
                if not match:
                    return False, "Base64 解码后格式不匹配"
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                return False, f"Base64 解码失败: {e}"
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

    elif protocol == "ssr":
        if not node.startswith("ssr://"):
            return False, "缺少 ssr:// 前缀"
        try:
            decoded = base64.b64decode(node[6:].strip('=')).decode('utf-8')
            parts = decoded.split(':')
            if len(parts) < 6:
                return False, "格式不匹配，缺少必要字段"
            host, port, protocol, method, obfs, password = parts[:6]
            if not is_valid_host(host):
                return False, f"无效的主机: {host}"
            if not is_valid_port(port):
                return False, f"无效的端口: {port}"
            if protocol not in SSR_PROTOCOLS:
                return False, f"不支持的协议: {protocol}"
            if method not in SS_METHODS:
                return False, f"不支持的加密方法: {method}"
            if obfs not in SSR_OBFS:
                return False, f"不支持的混淆: {obfs}"
            if not base64.b64decode(password).decode('utf-8', errors='ignore'):
                return False, "password 为空"
            return True, ""
        except (base64.binascii.Error, UnicodeDecodeError) as e:
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

async def _fetch_url_with_retry(client: httpx.AsyncClient, url: str, headers: dict, original_url_for_logging: str, retries: int = 3, retry_delay: int = 2) -> httpx.Response | None:
    """
    带重试机制的 URL 内容获取函数。
    此函数仅负责尝试给定的URL，不进行协议回退。
    
    Args:
        client (httpx.AsyncClient): HTTP 客户端。
        url (str): 要获取的 URL。
        headers (dict): HTTP 请求头。
        original_url_for_logging (str): 原始的、未修改的URL，用于日志记录。
        retries (int): 最大重试次数。
        retry_delay (int): 每次重试的等待时间（秒）。
        
    Returns:
        httpx.Response | None: HTTP 响应对象，如果失败则返回 None。
    """
    if retries == 0:
        logging.error(f"URL: {original_url_for_logging} (尝试 {url}) 达到最大重试次数，放弃获取。")
        return None

    try:
        logging.info(f"尝试从 {url.split('://')[0].upper() if '://' in url else 'UNKNOWN'} 获取内容: {url} (User-Agent: {headers.get('User-Agent', 'N/A')})")
        response = await client.get(url, headers=headers)
        response.raise_for_status() # 检查 HTTP 状态码
        return response
    except httpx.SSLError as e:
        # 如果是SSL错误，尝试禁用SSL验证后重试（仅一次）
        logging.warning(f"URL: {original_url_for_logging} (尝试 {url}) SSL 验证失败: {e}, 尝试禁用 SSL 验证...")
        async with httpx.AsyncClient(timeout=client.timeout, verify=False, http2=client.http2, follow_redirects=client.follow_redirects) as retry_client_no_verify:
            try:
                response = await retry_client_no_verify.get(url, headers=headers)
                response.raise_for_status()
                logging.info(f"URL: {original_url_for_logging} (尝试 {url}) 禁用 SSL 验证后成功获取。")
                return response
            except httpx.HTTPStatusError as e_inner:
                logging.error(f"URL: {original_url_for_logging} (尝试 {url}) 禁用 SSL 验证后 HTTP 状态错误: {e_inner}")
            except httpx.RequestError as e_inner:
                logging.error(f"URL: {original_url_for_logging} (尝试 {url}) 禁用 SSL 验证后网络请求错误: {e_inner}")
        return None # Return None if retry with no verify also fails
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logging.warning(f"URL: {original_url_for_logging} (尝试 {url}) 连接或超时错误: {e}, 重试中...")
        await asyncio.sleep(retry_delay)
        return await _fetch_url_with_retry(client, url, headers, original_url_for_logging, retries - 1, retry_delay * 2)
    except httpx.HTTPStatusError as e:
        logging.error(f"URL: {original_url_for_logging} (尝试 {url}) HTTP 状态错误: {e}")
        # 对于HTTP状态错误，不进行重试，直接返回None，让上层决定是否尝试其他协议
        return None
    except httpx.RequestError as e: # Catch other httpx errors, including UnsupportedProtocol
        logging.warning(f"URL: {original_url_for_logging} (尝试 {url}) 请求错误: {e}, 重试中...")
        await asyncio.sleep(retry_delay)
        return await _fetch_url_with_retry(client, url, headers, original_url_for_logging, retries - 1, retry_delay * 2)
    except Exception as e:
        logging.error(f"URL: {original_url_for_logging} (尝试 {url}) 未知错误: {e}, 重试中...")
        await asyncio.sleep(retry_delay)
        return await _fetch_url_with_retry(client, url, headers, original_url_for_logging, retries - 1, retry_delay * 2)

async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """
    从 URL 获取内容，并支持基于 HTTP 头部的缓存验证以及协议自动回退（HTTPS -> HTTP）。
    
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
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            logging.warning(f"读取或解析缓存文件 {cache_entry_path} 失败: {e}，将重新获取。")
            cached_data = None

    headers_for_request = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    if cached_data:
        if cached_data.get('etag'):
            headers_for_request['If-None-Match'] = cached_data['etag']
        if cached_data.get('last-modified'):
            headers_for_request['If-Modified-Since'] = cached_data['last-modified']

    # Determine URLs to try based on scheme presence
    urls_to_attempt = []
    parsed_url = httpx.URL(url)
    if not parsed_url.scheme:
        # If no scheme, try HTTPS first, then HTTP
        urls_to_attempt.append(f"https://{url}")
        urls_to_attempt.append(f"http://{url}")
    else:
        # If scheme is present, just use the provided URL
        urls_to_attempt.append(url)

    async with httpx.AsyncClient(timeout=10, http2=True, follow_redirects=True) as client:
        for current_attempt_url in urls_to_attempt:
            response = await _fetch_url_with_retry(client, current_attempt_url, headers_for_request, url) # Pass original for logging
            
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
                    
                    return content # Return content if successful
            # If response is None, this loop iteration failed, try the next URL in urls_to_attempt

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
    
    decoded_content_attempt = None
    try:
        decoded_content_attempt = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError):
        pass

    if decoded_content_attempt:
        try:
            json_data = json.loads(decoded_content_attempt)
            if isinstance(json_data, list):
                for item in json_data:
                    if isinstance(item, dict) and 'v' in item and 'ps' in item and 'add' in item:
                        vmess_node = "vmess://" + base64.b64encode(json.dumps(item, separators=(',', ':')).encode()).decode()
                        is_valid, reason = validate_node(vmess_node, "vmess")
                        if is_valid:
                            unique_nodes.add(vmess_node)
                        else:
                            logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}): {vmess_node}, 原因: {reason}")
            elif isinstance(json_data, dict):
                if 'outbounds' in json_data and isinstance(json_data['outbounds'], list):
                    for outbound in json_data['outbounds']:
                        if outbound.get('type') == 'vmess' and outbound.get('server'):
                            vmess_node = {
                                "v": "2",
                                "ps": outbound.get('tag', outbound.get('name', 'node')),
                                "add": outbound.get('server'),
                                "port": outbound.get('server_port'),
                                "id": outbound.get('uuid'),
                                "aid": outbound.get('alterId', '0'),
                                "net": outbound.get('network', 'tcp'),
                                "type": outbound.get('tls', {}).get('type', ''),
                                "host": outbound.get('tls', {}).get('server_name', ''),
                                "path": outbound.get('ws_path', ''),
                                "tls": "tls" if outbound.get('tls', {}).get('enabled', False) else ""
                            }
                            vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                            vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode()
                            is_valid, reason = validate_node(vmess_str, "vmess")
                            if is_valid:
                                unique_nodes.add(vmess_str)
                            else:
                                logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}): {vmess_str}, 原因: {reason}")
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
                                "type": "",
                                "host": proxy.get('ws-headers', {}).get('Host', ''),
                                "path": proxy.get('ws-path', ''),
                                "tls": "tls" if proxy.get('tls', False) else ""
                            }
                            vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                            vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode()
                            is_valid, reason = validate_node(vmess_str, "vmess")
                            if is_valid:
                                unique_nodes.add(vmess_str)
                            else:
                                logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}): {vmess_str}, 原因: {reason}")
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
                                logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}): {trojan_node}, 原因: {reason}")
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logging.debug(f"JSON 解析时发生错误: {e}")

        try:
            yaml_data = yaml.safe_load(decoded_content_attempt)
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
                            "host": proxy.get('ws-headers', {}).get('Host', ''),
                            "path": proxy.get('ws-path', ''),
                            "tls": "tls" if proxy.get('tls', False) else ""
                        }
                        vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                        vmess_str = "vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode()
                        is_valid, reason = validate_node(vmess_str, "vmess")
                        if is_valid:
                            unique_nodes.add(vmess_str)
                        else:
                            logging.debug(f"丢弃无效 Vmess 节点 (URL: {url}): {vmess_str}, 原因: {reason}")
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
                            logging.debug(f"丢弃无效 Trojan 节点 (URL: {url}): {trojan_node}, 原因: {reason}")
        except yaml.YAMLError:
            pass
        except Exception as e:
            logging.debug(f"YAML 解析时发生错误: {e}")

    contents_to_search = [content]
    if decoded_content_attempt:
        contents_to_search.append(decoded_content_attempt)

    for text_content in contents_to_search:
        for protocol, pattern in NODE_PATTERNS.items():
            for match in re.finditer(pattern, text_content):
                node = match.group(0)
                is_valid, reason = validate_node(node, protocol)
                if is_valid:
                    unique_nodes.add(node)
                else:
                    logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}): {node}, 原因: {reason}")

    if "<html" in content.lower() or "<!doctype html>" in content.lower():
        soup = BeautifulSoup(content, 'html.parser')
        for text_element in soup.find_all(string=True):
            text = str(text_element)
            for protocol, pattern in NODE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    node = match.group(0)
                    is_valid, reason = validate_node(node, protocol)
                    if is_valid:
                        unique_nodes.add(node)
                    else:
                        logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}): {node}, 原因: {reason}")
            
            for word_match in re.finditer(r'\b[A-Za-z0-9+/=]{20,}\b', text):
                word = word_match.group(0)
                padding_needed = len(word) % 4
                if padding_needed != 0:
                    word += '=' * (4 - padding_needed)
                
                try:
                    decoded_text = base64.b64decode(word).decode('utf-8', errors='ignore')
                    for protocol, pattern in NODE_PATTERNS.items():
                        for match in re.finditer(pattern, decoded_text):
                            node = match.group(0)
                            is_valid, reason = validate_node(node, protocol)
                            if is_valid:
                                unique_nodes.add(node)
                            else:
                                logging.debug(f"丢弃无效 {protocol} 节点 (URL: {url}): {node}, 原因: {reason}")
                except (base64.binascii.Error, UnicodeDecodeError):
                    pass

    return list(unique_nodes)

async def process_url(url: str, all_nodes_writer: aiofiles.threadpool.text.AsyncTextIOWrapper, semaphore: asyncio.Semaphore): # Corrected type hint
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
        logging.info(f"完成解析 {url} 的内容。")

        unique_nodes = list(set(unique_nodes))

        safe_url_name = hashlib.md5(url.encode()).hexdigest()
        url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
        try:
            async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes:
                    await f.write(f"{node}\n")
            logging.info(f"URL: {url} 的节点已保存到 {url_output_file}")
        except IOError as e:
            logging.error(f"写入 URL 节点文件 {url_output_file} 失败: {e}")
            
        try:
            for node in unique_nodes:
                await all_nodes_writer.write(f"{node}\n")
        except IOError as e:
            logging.error(f"写入总节点文件 {ALL_NODES_FILE} 失败: {e}")

        logging.info(f"URL: {url} 成功提取到 {len(unique_nodes)} 个节点。")
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

    if not urls:
        logging.warning("sources.list 中没有找到有效的 URL。")
        return

    node_counts = defaultdict(int)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as all_nodes_writer:
        tasks = [process_url(url, all_nodes_writer, semaphore) for url in urls]
        results = await asyncio.gather(*tasks)

        for url, count in results:
            node_counts[url] = count
    
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
