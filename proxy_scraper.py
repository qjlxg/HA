import httpx
import asyncio
import re
import os
import csv
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import yaml
import base64
import json
import ipaddress
import dns.resolver
import platform
import random
import datetime
import aiofiles
import logging
from playwright.async_api import async_playwright, Playwright

# --- 配置常量 ---
# OUTPUT_DIR = "data"  # 输出目录 (This line will be effectively overridden for the specific files)
CACHE_DIR = "cache"  # 缓存目录
CACHE_EXPIRATION_HOURS = 24  # 缓存过期时间（小时）
MAX_CONCURRENT_REQUESTS = 5  # 最大并发请求数，适配 Playwright 资源消耗
REQUEST_TIMEOUT_SECONDS = 30  # 单次请求超时时间
RETRY_ATTEMPTS = 1  # 失败重试1次

# 配置日志
logger = logging.getLogger('proxy_scraper')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
file_handler = logging.FileHandler('proxy_scraper.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 用户代理列表
USER_AGENTS = {
    "desktop": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    ],
    "tablet": [
        "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 12; SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "harmonyos": [
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; PCT-AL10) AppleWebKit/537.36 (KHTML like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36",
    ]
}

# 节点协议正则表达式 (增强和更新)
NODE_REGEXES = {
    "hysteria2": r"hysteria2:\/\/(?P<id>[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?(?P<host>[a-zA-Z0-9\-\.]+)(?::(?P<port>\d+))?\/?\?.*",
    "vmess": r"vmess:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "trojan": r"trojan:\/\/(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:\/\?.*)?",
    "ss": r"ss:\/\/(?P<method_password>[a-zA-Z0-9+\/=]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:#(?P<name>.*))?",
    "ssr": r"ssr:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "vless": r"vless:\/\/(?P<uuid>[a-zA-Z0-9\-]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?type=(?P<type>[a-zA-Z0-9]+)(?:&security=(?P<security>[a-zA-Z0-9]+))?.*",
    "tuic": r"tuic:\/\/(?P<uuid>[a-zA-Z0-9\-]+):(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?(?:udp_relay=(?P<udp_relay>[^&]*))?",
    "wg": r"wg:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
}

# --- 缓存处理函数 ---
def generate_cache_key(url):
    """生成 URL 的缓存键"""
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    """获取缓存文件路径"""
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
    """读取缓存内容"""
    cache_path = get_cache_path(url)
    if not os.path.exists(cache_path):
        logger.debug(f"缓存文件不存在: {cache_path}")
        return None
    
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path))
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        logger.info(f"缓存 '{url}' 已过期。")
        try:
            os.remove(cache_path)
        except Exception as e:
            logger.warning(f"删除过期缓存 '{cache_path}' 失败: {e}")
        return None
    
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                logger.info(f"从缓存读取 '{url}'。")
                return await f.read()
    except Exception as e:
        logger.error(f"读取缓存 '{url}' 失败: {e}")
        return None

async def write_cache(url, content):
    """写入缓存内容"""
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                await f.write(content)
        logger.info(f"内容已写入缓存 '{url}'。")
    except Exception as e:
        logger.error(f"写入缓存 '{url}' 失败: {e}")

# --- 网络请求相关函数 ---
def get_random_headers():
    """随机选择用户代理"""
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

async def fetch_url(url, http_client, playwright_instance: Playwright):
    """尝试获取 URL 内容，先用 httpx，若失败则用 Playwright，支持重试"""
    # 尝试将 URL 规范化，确保有 scheme
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # 优先尝试 HTTPS，因为现在很多网站都强制 HTTPS
        full_url_https = f"https://{url}"
        full_url_http = f"http://{url}"
    else:
        full_url_https = url
        full_url_http = url.replace("https://", "http://", 1) # 尝试降级到 HTTP

    cached_content = await read_cache(url)
    if cached_content:
        return cached_content
        
    content = None
    
    # 尝试 httpx 获取 HTTPS
    for attempt in range(RETRY_ATTEMPTS):
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                headers = get_random_headers()
                logger.info(f"尝试用 httpx 从 {full_url_https} 获取内容 (第 {attempt + 1} 次)...")
                response = await http_client.get(full_url_https, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers)
                response.raise_for_status()
                content = response.text
                logger.info(f"httpx 成功从 {full_url_https} 获取内容。")
                break
        except asyncio.TimeoutError:
            logger.warning(f"httpx 从 {full_url_https} 获取超时 (第 {attempt + 1} 次)。")
        except httpx.HTTPStatusError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。")
        except httpx.RequestError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。")
        except Exception as e:
            logger.error(f"httpx 从 {full_url_https} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)

    # 如果 HTTPS 失败，尝试 httpx 获取 HTTP
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            try:
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                    headers = get_random_headers()
                    logger.info(f"尝试用 httpx 从 {full_url_http} 获取内容 (第 {attempt + 1} 次)...")
                    response = await http_client.get(full_url_http, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers)
                    response.raise_for_status()
                    content = response.text
                    logger.info(f"httpx 成功从 {full_url_http} 获取内容。")
                    break
            except asyncio.TimeoutError:
                logger.warning(f"httpx 从 {full_url_http} 获取超时 (第 {attempt + 1} 次)。")
            except httpx.HTTPStatusError as e:
                logger.warning(f"httpx 从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。")
            except httpx.RequestError as e:
                logger.warning(f"httpx 从 {full_url_http} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。")
            except Exception as e:
                logger.error(f"httpx 从 {full_url_http} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)
            
    # 如果 httpx 失败，尝试 Playwright
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            logger.info(f"httpx 未能获取 {url} 内容，尝试使用 Playwright (第 {attempt + 1} 次)...")
            browser = None
            try:
                # Playwright 尝试 HTTPS
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 2):  # Playwright 可能需要更长时间
                    browser = await playwright_instance.chromium.launch()
                    page = await browser.new_page()
                    await page.set_extra_http_headers(get_random_headers())
                    
                    full_url_pw = full_url_https # 优先尝试 HTTPS
                    try:
                        await page.goto(full_url_pw, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。")
                        break
                    except Exception as e:
                        logger.warning(f"Playwright 从 {full_url_pw} 获取失败: {e} (第 {attempt + 1} 次)。尝试 HTTP。")
                        # 尝试 Playwright HTTP
                        full_url_pw = full_url_http
                        await page.goto(full_url_pw, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。")
                        break
            except asyncio.TimeoutError:
                logger.warning(f"Playwright 从 {url} 获取超时 (第 {attempt + 1} 次)。")
            except Exception as e:
                logger.error(f"Playwright 从 {url} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)
            finally:
                if browser:
                    try:
                        await browser.close()
                    except Exception as e:
                        logger.warning(f"关闭 Playwright 浏览器失败: {e}")

    if content:
        await write_cache(url, content)
    else:
        logger.error(f"经过 {RETRY_ATTEMPTS} 次尝试，未能获取 {url} 的内容，跳过。")
    return content

# --- DNS 解析函数 ---
async def check_dns_resolution(url):
    """检查域名是否能解析到有效 IP 地址"""
    # 提取域名部分
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path.split('/')[0] # 兼容只有路径的情况
    if not hostname:
        logger.warning(f"无法从 '{url}' 提取有效域名进行 DNS 解析。")
        return False
        
    if is_valid_ip(hostname): # 如果已经是 IP 地址，则直接通过
        return True

    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            answers = await asyncio.to_thread(dns.resolver.resolve, hostname, 'A')
        if answers:
            logger.info(f"域名 '{hostname}' 解析成功，IP: {[str(a) for a in answers]}")
            return True
        else:
            logger.warning(f"域名 '{hostname}' 未能解析到 IP 地址。")
            return False
    except asyncio.TimeoutError:
        logger.warning(f"DNS 解析 '{hostname}' 超时。")
        return False
    except dns.resolver.NXDOMAIN:
        logger.warning(f"域名 '{hostname}' 不存在 (NXDOMAIN)。")
        return False
    except dns.resolver.NoAnswer:
        logger.warning(f"域名 '{hostname}' 没有可用的 A 记录。")
        return False
    except dns.resolver.NoNameservers as e:
        logger.warning(f"DNS 解析 '{hostname}' 失败: 所有名称服务器都未能应答 ({e})。")
        return False
    except Exception as e:
        logger.error(f"DNS 解析 '{hostname}' 时发生未知错误: {e}", exc_info=True)
        return False

# --- 节点验证函数 ---
def is_valid_ip(address):
    """验证是否为有效 IP 地址"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def validate_node(protocol, data):
    """验证节点数据有效性 (增强验证逻辑)"""
    # logger.debug(f"正在验证 {protocol} 节点数据: {data}") # 过多日志，仅在调试时开启
    try:
        if protocol == "hysteria2":
            if not all(k in data for k in ['host', 'port']): return False
            if not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "vmess":
            # 尝试解码，如果解码失败或不是有效JSON，则返回False
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                json_data = json.loads(decoded)
            except Exception:
                return False
            
            if not all(k in json_data for k in ['add', 'port', 'id']): return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False
            if not isinstance(json_data['port'], (int, str)): return False # 端口可以是字符串
            if not (1 <= int(json_data['port']) <= 65535): return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id']): return False
            return True
        elif protocol == "trojan":
            if not all(k in data for k in ['password', 'host', 'port']): return False
            if not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ss":
            if not all(k in data for k in ['method_password', 'host', 'port']): return False
            if not data['method_password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            try:
                # SS的method_password部分可能需要Base64解码
                decoded_mp = base64.b64decode(data['method_password'] + '=' * (4 - len(data['method_password']) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            if ':' not in decoded_mp: return False # 确保包含 method:password
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ssr":
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            parts = decoded.split(':')
            if len(parts) < 6: return False # server:port:protocol:method:obfs:password_base64
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False # server
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False # port
            # 协议、加密、混淆和密码可以更宽松，只要存在即可
            return True
        elif protocol == "vless":
            if not all(k in data for k in ['uuid', 'host', 'port', 'type']): return False
            if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']: return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "tuic":
            if not all(k in data for k in ['uuid', 'password', 'host', 'port']): return False
            if not data['uuid'] or not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid'])): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "wg":
            # WireGuard 通常是 Base64 编码的完整配置，解码后会有特定格式
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                # 简单检查 WireGuard 配置的关键字
                if "PrivateKey" in decoded and "Address" in decoded and "Endpoint" in decoded:
                    return True
            except Exception:
                return False
            return False
        return False
    except Exception as e:
        logger.debug(f"验证节点 {protocol} 失败: {e}")
        return False

# --- 节点规范化与去重函数 ---
def get_node_canonical_fingerprint(node_url: str) -> str | None:
    """生成节点的规范化指纹，用于去重"""
    base_url_no_remark = node_url.split('#', 1)[0]
    try:
        parsed_url = urlparse(base_url_no_remark)
        scheme = parsed_url.scheme
        if not scheme:
            return None

        if scheme == "ss":
            if not parsed_url.netloc:
                return None
            auth_and_host = parsed_url.netloc
            if '@' not in auth_and_host:
                return None
            method_password_encoded, server_port = auth_and_host.split('@', 1)
            try:
                padded_method_password_encoded = method_password_encoded + '=' * (4 - len(method_password_encoded) % 4)
                decoded_method_password = base64.b64decode(padded_method_password_encoded).decode('utf-8', errors='ignore').strip()
                decoded_method_password = decoded_method_password.replace('\n', '').replace('\r', '')
                # 标准化方法和密码的顺序，通常方法在前
                parts = decoded_method_password.split(':', 1)
                method = parts[0]
                password = parts[1] if len(parts) > 1 else ""
                return f"ss://{method}:{password}@{server_port}"
            except Exception:
                return None

        elif scheme == "ssr":
            encoded_params = base_url_no_remark[len("ssr://"):]
            try:
                padded_encoded_params = encoded_params + '=' * (4 - len(encoded_params) % 4)
                decoded_params = base64.b64decode(padded_encoded_params).decode('utf-8', errors='ignore')
                core_params_part = decoded_params.split("/?")[0]
                parts = core_params_part.split(':')
                if len(parts) >= 6:
                    # 解码密码部分并标准化
                    try:
                        password_encoded = parts[5]
                        padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4)
                        # SSR密码可能使用URL安全Base64变体，需要替换字符
                        decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                        parts[5] = decoded_password.strip()
                    except Exception:
                        pass # 如果密码解码失败，保持原样，但这会影响去重精度
                return f"ssr://{':'.join(parts)}"
            except Exception:
                return None

        elif scheme == "vmess":
            encoded_json = base_url_no_remark[len("vmess://"):]
            try:
                padded_encoded_json = encoded_json + '=' * (4 - len(encoded_json) % 4)
                decoded_json = base64.b64decode(padded_encoded_json).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded_json)
                fingerprint_data = {
                    "add": vmess_config.get("add"),
                    "port": vmess_config.get("port"),
                    "id": vmess_config.get("id"),
                }
                # 包含关键的传输配置，如 net, type, tls, host, path, sni 等，按字典序排序
                optional_keys_for_fingerprint = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]
                for key in sorted(optional_keys_for_fingerprint):
                    if key in vmess_config and vmess_config[key] is not None:
                        fingerprint_data[key] = vmess_config[key]
                return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"
            except Exception:
                return None
        elif scheme in ["vless", "trojan", "hysteria2", "tuic"]:
            # 对于这些协议，主机、端口、ID/密码和查询参数是关键
            # 规范化查询参数：排序并重新编码
            query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
            sorted_query_params = []
            for key in sorted(query_params_list.keys()):
                for value in sorted(query_params_list[key]): # 对值也进行排序，确保一致性
                    sorted_query_params.append((key, value))
            sorted_query_string = urlencode(sorted_query_params)
            canonical_url_parts = [scheme, "://"]
            # 用户信息（如果存在）
            if parsed_url.username:
                canonical_url_parts.append(parsed_url.username)
            if parsed_url.password:
                canonical_url_parts.append(f":{parsed_url.password}")
            canonical_url_parts.append("@")
            canonical_url_parts.append(parsed_url.netloc)
            if parsed_url.path:
                canonical_url_parts.append(parsed_url.path)
            if sorted_query_string:
                canonical_url_parts.append("?")
                canonical_url_parts.append(sorted_query_string)
            return "".join(canonical_url_parts)
        elif scheme == "wg":
            encoded_data = base_url_no_remark[len("wg://"):]
            try:
                # WireGuard 指纹可以简单地基于其 Base64 编码的配置（假设配置是唯一的）
                # 理论上可以解析内部配置并规范化，但对于去重，原始编码通常足够
                return f"wg://{encoded_data}"
            except Exception:
                return None
        return None
    except Exception as e:
        logger.debug(f"规范化节点 '{node_url}' 失败: {e}")
        return None

# --- 节点解析与提取函数 ---
def extract_nodes_from_text(text_content):
    """从文本中提取代理节点 (增强提取逻辑)"""
    extracted_nodes = set()
    # 优先匹配已知协议的节点
    for protocol, regex_pattern in NODE_REGEXES.items():
        for match in re.finditer(regex_pattern, text_content, re.IGNORECASE): # 忽略大小写
            full_uri = match.group(0)
            matched_data = match.groupdict()
            if validate_node(protocol, matched_data):
                extracted_nodes.add(full_uri)
    # 尝试 Base64 解码和递归处理
    # 查找可能包含 Base64 编码数据的块
    # 改进的 Base64 正则表达式，尝试匹配更长的、以 = 结尾的有效 Base64 字符串
    # 并且避免匹配太短的、可能是普通文本的字符串
    base64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/])", text_content)
    for b64_block in sorted(base64_candidates, key=len, reverse=True): # 优先处理长块
        if len(b64_block) > 30 and len(b64_block) % 4 == 0: # 设一个合理的长度阈值
            try:
                decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                # 递归处理解码后的内容
                recursive_nodes = extract_nodes_from_text(decoded_content)
                extracted_nodes.update(recursive_nodes)
            except Exception as e:
                logger.debug(f"Base64 解码失败或内容无效 (长度 {len(b64_block)}): {e}")

    return list(extracted_nodes)

async def process_url(url, http_client, playwright_instance: Playwright):
    """处理单个 URL，获取内容并提取节点"""
    logger.info(f"开始处理 URL: {url}")
    content = await fetch_url(url, http_client, playwright_instance)
    if content:
        nodes = extract_nodes_from_text(content)
        logger.info(f"从 {url} 提取到 {len(nodes)} 个节点。")
        return nodes
    logger.warning(f"未能从 {url} 获取内容，跳过节点提取。")
    return []

global_unique_nodes_map = {} # 用于存储所有任务中的唯一节点

async def main():
    """主函数，运行整个代理收集过程"""
    urls_to_scrape = []

    # 从远程 YAML 文件获取 URL
    try:
        async with httpx.AsyncClient() as client:
            yaml_raw_url = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Url.yaml"
            logger.info(f"尝试从 {yaml_raw_url} 获取 URL 列表...")
            response = await client.get(yaml_raw_url, timeout=REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
            yaml_content = response.text
            remote_urls = yaml.safe_load(yaml_content)
            if isinstance(remote_urls, list):
                urls_to_scrape.extend(remote_urls)
                logger.info(f"从远程 YAML 获取到 {len(remote_urls)} 个 URL。")
            else:
                logger.warning(f"远程 YAML 内容格式不正确，期望列表，实际为 {type(remote_urls)}")
    except httpx.RequestError as e:
        logger.error(f"从 {yaml_raw_url} 获取远程 URL 列表失败: {e}")
    except yaml.YAMLError as e:
        logger.error(f"解析远程 YAML 文件失败: {e}")
    except Exception as e:
        logger.error(f"获取或处理远程 YAML URL 时发生未知错误: {e}")

    # 如果没有从远程获取到 URL，可以考虑使用备用 URL 或本地 URL
    if not urls_to_scrape:
        logger.warning("未能获取远程 URL 列表，将使用备用本地 URL。")
        # 可以添加一些默认或本地的 URL
        urls_to_scrape.extend([
            "https://raw.githubusercontent.com/freefq/free/master/v2",
            "https://raw.githubusercontent.com/ripv2ray/free/main/v2",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        ])

    logger.info(f"待处理 URL 总数: {len(urls_to_scrape)}")

    # 过滤掉重复的 URL 并检查 DNS 解析
    unique_urls = list(set(urls_to_scrape))
    valid_urls_after_dns = []
    logger.info("开始检查 URL 的 DNS 解析...")
    dns_check_tasks = [check_dns_resolution(url) for url in unique_urls]
    dns_results = await asyncio.gather(*dns_check_tasks, return_exceptions=True)

    for url, dns_success in zip(unique_urls, dns_results):
        if dns_success is True:
            valid_urls_after_dns.append(url)
        else:
            logger.warning(f"URL '{url}' DNS 解析失败或超时，跳过。")

    logger.info(f"通过 DNS 解析的有效 URL 数量: {len(valid_urls_after_dns)}")

    # 创建输出目录
    OUTPUT_DIR = "."  # 设置为当前目录，以便在 GitHub Actions 根目录生成文件
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logger.info(f"输出目录已设置为: {os.path.abspath(OUTPUT_DIR)}")

    # 使用 httpx 和 playwright 客户端处理 URL
    async with httpx.AsyncClient() as http_client:
        async with async_playwright() as playwright_instance:
            tasks = [process_url(url, http_client, playwright_instance) for url in valid_urls_after_dns]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for url, result in zip(valid_urls_after_dns, results):
                if isinstance(result, Exception):
                    logger.error(f"处理 URL {url} 失败: {result}")

    all_unique_nodes_file = os.path.join(OUTPUT_DIR, "all_unique_nodes.txt")
    try:
        if global_unique_nodes_map:
            async with aiofiles.open(all_unique_nodes_file, 'w', encoding='utf-8') as f:
                for node in sorted(global_unique_nodes_map.values()):
                    await f.write(node + '\n')
            logger.info(f"所有 {len(global_unique_nodes_map)} 个唯一节点已保存到 {all_unique_nodes_file}。")
        else:
            logger.info("未找到任何唯一节点，跳过保存 all_unique_nodes.txt 文件。")
    except Exception as e:
        logger.error(f"保存唯一节点到 {all_unique_nodes_file} 失败: {e}")

    csv_file_path = os.path.join(OUTPUT_DIR, "nodes_summary.csv")
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['URL', '节点数量']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for url, nodes in zip(valid_urls_after_dns, results):
                if not isinstance(nodes, Exception): # 只处理成功的URL
                    writer.writerow({'URL': url, '节点数量': len(nodes)})
        logger.info(f"节点汇总信息已保存到 {csv_file_path}。")
    except Exception as e:
        logger.error(f"保存 CSV 汇总文件失败: {e}")

if __name__ == "__main__":
    asyncio.run(main())
