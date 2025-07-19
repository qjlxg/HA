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
[cite_start]CACHE_DIR = "cache"  # 缓存目录 [cite: 102]
[cite_start]CACHE_EXPIRATION_HOURS = 24  # 缓存过期时间（小时） [cite: 102]
[cite_start]MAX_CONCURRENT_REQUESTS = 5  # 最大并发请求数，适配 Playwright 资源消耗 [cite: 102]
[cite_start]REQUEST_TIMEOUT_SECONDS = 30  # 单次请求超时时间 [cite: 102]
[cite_start]RETRY_ATTEMPTS = 1  # 失败重试1次 [cite: 102]

# 配置日志
[cite_start]logger = logging.getLogger('proxy_scraper') [cite: 102]
[cite_start]logger.setLevel(logging.INFO) [cite: 102]
[cite_start]console_handler = logging.StreamHandler() [cite: 102]
[cite_start]console_handler.setLevel(logging.INFO) [cite: 102]
[cite_start]file_handler = logging.FileHandler('proxy_scraper.log', encoding='utf-8') [cite: 102]
[cite_start]file_handler.setLevel(logging.INFO) [cite: 102]
[cite_start]formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s') [cite: 102]
[cite_start]console_handler.setFormatter(formatter) [cite: 102]
[cite_start]file_handler.setFormatter(formatter) [cite: 102]
[cite_start]logger.addHandler(console_handler) [cite: 102]
[cite_start]logger.addHandler(file_handler) [cite: 102]

# 用户代理列表
USER_AGENTS = {
    "desktop": [
        [cite_start]"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", [cite: 103]
        [cite_start]"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", [cite: 103]
        [cite_start]"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", [cite: 103]
    ],
    "mobile": [
        [cite_start]"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", [cite: 103]
        [cite_start]"Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0", [cite: 103]
        [cite_start]"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36", [cite: 104]
    ],
    "tablet": [
        [cite_start]"Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", [cite: 104]
        [cite_start]"Mozilla/5.0 (Linux; Android 12; SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", [cite: 104]
    ],
    "harmonyos": [
        [cite_start]"Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36", [cite: 105]
        [cite_start]"Mozilla/5.0 (Linux; U; Android 10; zh-cn; PCT-AL10) AppleWebKit/537.36 (KHTML like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36", [cite: 105]
    ]
}

# 节点协议正则表达式 (增强和更新)
NODE_REGEXES = {
    [cite_start]"hysteria2": r"hysteria2:\/\/(?P<id>[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?(?P<host>[a-zA-Z0-9\-\.]+)(?::(?P<port>\d+))?\/?\?.*", [cite: 105]
    [cite_start]"vmess": r"vmess:\/\/(?P<data>[a-zA-Z0-9+\/=]+)", [cite: 105]
    [cite_start]"trojan": r"trojan:\/\/(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:\/\?.*)?", [cite: 105]
    [cite_start]"ss": r"ss:\/\/(?P<method_password>[a-zA-Z0-9+\/=]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:#(?P<name>.*))?", [cite: 105]
    [cite_start]"ssr": r"ssr:\/\/(?P<data>[a-zA-Z0-9+\/=]+)", [cite: 105]
    [cite_start]"vless": r"vless:\/\/(?P<uuid>[a-zA-Z0-9\-]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?type=(?P<type>[a-zA-Z0-9]+)(?:&security=(?P<security>[a-zA-Z0-9]+))?.*", [cite: 105]
    [cite_start]"tuic": r"tuic:\/\/(?P<uuid>[a-zA-Z0-9\-]+):(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?(?:udp_relay=(?P<udp_relay>[^&]*))?", [cite: 105]
    [cite_start]"wg": r"wg:\/\/(?P<data>[a-zA-Z0-9+\/=]+)", [cite: 105]
}

# --- 缓存处理函数 ---
def generate_cache_key(url):
    """生成 URL 的缓存键"""
    [cite_start]return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache" [cite: 106]

def get_cache_path(url):
    """获取缓存文件路径"""
    [cite_start]return os.path.join(CACHE_DIR, generate_cache_key(url)) [cite: 106]

async def read_cache(url):
    """读取缓存内容"""
    [cite_start]cache_path = get_cache_path(url) [cite: 106]
    if not os.path.exists(cache_path):
        [cite_start]logger.debug(f"缓存文件不存在: {cache_path}") [cite: 106]
        return None
    
    [cite_start]mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path)) [cite: 106]
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        [cite_start]logger.info(f"缓存 '{url}' 已过期。") [cite: 107]
        try:
            [cite_start]os.remove(cache_path) [cite: 107]
        except Exception as e:
            [cite_start]logger.warning(f"删除过期缓存 '{cache_path}' 失败: {e}") [cite: 107]
        return None
    
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                [cite_start]logger.info(f"从缓存读取 '{url}'。") [cite: 108]
                [cite_start]return await f.read() [cite: 108]
    except Exception as e:
        [cite_start]logger.error(f"读取缓存 '{url}' 失败: {e}") [cite: 108]
        return None

async def write_cache(url, content):
    """写入缓存内容"""
    [cite_start]cache_path = get_cache_path(url) [cite: 108]
    [cite_start]os.makedirs(CACHE_DIR, exist_ok=True) [cite: 108]
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                [cite_start]await f.write(content) [cite: 109]
        [cite_start]logger.info(f"内容已写入缓存 '{url}'。") [cite: 109]
    except Exception as e:
        [cite_start]logger.error(f"写入缓存 '{url}' 失败: {e}") [cite: 109]

# --- 网络请求相关函数 ---
def get_random_headers():
    """随机选择用户代理"""
    [cite_start]device_type = random.choice(list(USER_AGENTS.keys())) [cite: 109]
    [cite_start]return {"User-Agent": random.choice(USER_AGENTS[device_type])} [cite: 109]

async def fetch_url(url, http_client, playwright_instance: Playwright):
    """尝试获取 URL 内容，先用 httpx，若失败则用 Playwright，支持重试"""
    # 尝试将 URL 规范化，确保有 scheme
    [cite_start]parsed_url = urlparse(url) [cite: 109]
    if not parsed_url.scheme:
        # 优先尝试 HTTPS，因为现在很多网站都强制 HTTPS
        [cite_start]full_url_https = f"https://{url}" [cite: 110]
        [cite_start]full_url_http = f"http://{url}" [cite: 110]
    else:
        [cite_start]full_url_https = url [cite: 110]
        [cite_start]full_url_http = url.replace("https://", "http://", 1) # 尝试降级到 HTTP [cite: 110]

    [cite_start]cached_content = await read_cache(url) [cite: 110]
    if cached_content:
        return cached_content
        
    content = None
    
    # 尝试 httpx 获取 HTTPS
    for attempt in range(RETRY_ATTEMPTS):
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                [cite_start]headers = get_random_headers() [cite: 111]
                [cite_start]logger.info(f"尝试用 httpx 从 {full_url_https} 获取内容 (第 {attempt + 1} 次)...") [cite: 111]
                [cite_start]response = await http_client.get(full_url_https, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers) [cite: 111]
                [cite_start]response.raise_for_status() [cite: 112]
                [cite_start]content = response.text [cite: 112]
                [cite_start]logger.info(f"httpx 成功从 {full_url_https} 获取内容。") [cite: 112]
                break
        except asyncio.TimeoutError:
            [cite_start]logger.warning(f"httpx 从 {full_url_https} 获取超时 (第 {attempt + 1} 次)。") [cite: 112]
        except httpx.HTTPStatusError as e:
            [cite_start]logger.warning(f"httpx 从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。") [cite: 113]
        except httpx.RequestError as e:
            [cite_start]logger.warning(f"httpx 从 {full_url_https} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。") [cite: 113]
        except Exception as e:
            [cite_start]logger.error(f"httpx 从 {full_url_https} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True) [cite: 113]

    # 如果 HTTPS 失败，尝试 httpx 获取 HTTP
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            try:
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                    [cite_start]headers = get_random_headers() [cite: 114]
                    [cite_start]logger.info(f"尝试用 httpx 从 {full_url_http} 获取内容 (第 {attempt + 1} 次)...") [cite: 114]
                    [cite_start]response = await http_client.get(full_url_http, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers) [cite: 115]
                    [cite_start]response.raise_for_status() [cite: 115]
                    [cite_start]content = response.text [cite: 115]
                    [cite_start]logger.info(f"httpx 成功从 {full_url_http} 获取内容。") [cite: 115]
                    break
            except asyncio.TimeoutError:
                [cite_start]logger.warning(f"httpx 从 {full_url_http} 获取超时 (第 {attempt + 1} 次)。") [cite: 116]
            except httpx.HTTPStatusError as e:
                [cite_start]logger.warning(f"httpx 从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。") [cite: 116]
            except httpx.RequestError as e:
                [cite_start]logger.warning(f"httpx 从 {full_url_http} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。") [cite: 117]
            except Exception as e:
                [cite_start]logger.error(f"httpx 从 {full_url_http} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True) [cite: 117]
            
    # 如果 httpx 失败，尝试 Playwright
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            [cite_start]logger.info(f"httpx 未能获取 {url} 内容，尝试使用 Playwright (第 {attempt + 1} 次)...") [cite: 118]
            browser = None
            try:
                # Playwright 尝试 HTTPS
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 2):  # Playwright 可能需要更长时间
                    [cite_start]browser = await playwright_instance.chromium.launch() [cite: 119]
                    [cite_start]page = await browser.new_page() [cite: 119]
                    [cite_start]await page.set_extra_http_headers(get_random_headers()) [cite: 119]
                    
                    [cite_start]full_url_pw = full_url_https # 优先尝试 HTTPS [cite: 120]
                    try:
                        [cite_start]await page.goto(full_url_pw, timeout=30000, wait_until='networkidle') [cite: 120]
                        [cite_start]content = await page.content() [cite: 120]
                        [cite_start]logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。") [cite: 121]
                        break
                    except Exception as e:
                        [cite_start]logger.warning(f"Playwright 从 {full_url_pw} 获取失败: {e} (第 {attempt + 1} 次)。尝试 HTTP。") [cite: 121]
                        # 尝试 Playwright HTTP
                        [cite_start]full_url_pw = full_url_http [cite: 122]
                        [cite_start]await page.goto(full_url_pw, timeout=30000, wait_until='networkidle') [cite: 122]
                        [cite_start]content = await page.content() [cite: 122]
                        [cite_start]logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。") [cite: 123]
                        break
            except asyncio.TimeoutError:
                [cite_start]logger.warning(f"Playwright 从 {url} 获取超时 (第 {attempt + 1} 次)。") [cite: 123]
            except Exception as e:
                [cite_start]logger.error(f"Playwright 从 {url} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True) [cite: 124]
            finally:
                if browser:
                    try:
                        [cite_start]await browser.close() [cite: 125]
                    except Exception as e:
                        [cite_start]logger.warning(f"关闭 Playwright 浏览器失败: {e}") [cite: 125]

    if content:
        [cite_start]await write_cache(url, content) [cite: 125]
    else:
        [cite_start]logger.error(f"经过 {RETRY_ATTEMPTS} 次尝试，未能获取 {url} 的内容，跳过。") [cite: 125]
    return content

# --- DNS 解析函数 ---
async def check_dns_resolution(url):
    """检查域名是否能解析到有效 IP 地址"""
    # 提取域名部分
    [cite_start]parsed_url = urlparse(url) [cite: 126]
    [cite_start]hostname = parsed_url.hostname or parsed_url.path.split('/')[0] # 兼容只有路径的情况 [cite: 126]
    if not hostname:
        [cite_start]logger.warning(f"无法从 '{url}' 提取有效域名进行 DNS 解析。") [cite: 126]
        return False
        
    if is_valid_ip(hostname): # 如果已经是 IP 地址，则直接通过
        return True

    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            [cite_start]answers = await asyncio.to_thread(dns.resolver.resolve, hostname, 'A') [cite: 127]
        if answers:
                [cite_start]logger.info(f"域名 '{hostname}' 解析成功，IP: {[str(a) for a in answers]}") [cite: 127]
                return True
            else:
                [cite_start]logger.warning(f"域名 '{hostname}' 未能解析到 IP 地址。") [cite: 127]
                return False
    except asyncio.TimeoutError:
        [cite_start]logger.warning(f"DNS 解析 '{hostname}' 超时。") [cite: 128]
        return False
    except dns.resolver.NXDOMAIN:
        [cite_start]logger.warning(f"域名 '{hostname}' 不存在 (NXDOMAIN)。") [cite: 128]
        return False
    except dns.resolver.NoAnswer:
        [cite_start]logger.warning(f"域名 '{hostname}' 没有可用的 A 记录。") [cite: 128]
        return False
    except dns.resolver.NoNameservers as e:
        [cite_start]logger.warning(f"DNS 解析 '{hostname}' 失败: 所有名称服务器都未能应答 ({e})。") [cite: 129]
        return False
    except Exception as e:
        [cite_start]logger.error(f"DNS 解析 '{hostname}' 时发生未知错误: {e}", exc_info=True) [cite: 129]
        return False

# --- 节点验证函数 ---
def is_valid_ip(address):
    """验证是否为有效 IP 地址"""
    try:
        [cite_start]ipaddress.ip_address(address) [cite: 129]
        return True
    except ValueError:
        return False

def validate_node(protocol, data):
    """验证节点数据有效性 (增强验证逻辑)"""
    # logger.debug(f"正在验证 {protocol} 节点数据: {data}") # 过多日志，仅在调试时开启
    try:
        if protocol == "hysteria2":
            [cite_start]if not all(k in data for k in ['host', 'port']): return False [cite: 130]
            [cite_start]if not data['host'] or not data['port'] or not data['port'].isdigit(): return False [cite: 130]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False [cite: 130]
            [cite_start]if not (1 <= int(data['port']) <= 65535): return False [cite: 131]
            return True
        elif protocol == "vmess":
            # 尝试解码，如果解码失败或不是有效JSON，则返回False
            try:
                [cite_start]decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore') [cite: 131]
                [cite_start]json_data = json.loads(decoded) [cite: 132]
            except Exception:
                return False
            
            [cite_start]if not all(k in json_data for k in ['add', 'port', 'id']): return False [cite: 132]
            [cite_start]if not json_data['add'] or not json_data['port'] or not json_data['id']: return False [cite: 132]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False [cite: 133]
            [cite_start]if not isinstance(json_data['port'], (int, str)): return False # 端口可以是字符串 [cite: 133]
            [cite_start]if not (1 <= int(json_data['port']) <= 65535): return False [cite: 133]
            [cite_start]if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id']): return False [cite: 133]
            return True
        elif protocol == "trojan":
            [cite_start]if not all(k in data for k in ['password', 'host', 'port']): return False [cite: 134]
            [cite_start]if not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False [cite: 134]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False [cite: 134]
            [cite_start]if not (1 <= int(data['port']) <= 65535): return False [cite: 134]
            return True
        elif protocol == "ss":
            [cite_start]if not all(k in data for k in ['method_password', 'host', 'port']): return False [cite: 135]
            [cite_start]if not data['method_password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False [cite: 135]
            try:
                # SS的method_password部分可能需要Base64解码
                [cite_start]decoded_mp = base64.b64decode(data['method_password'] + '=' * (4 - len(data['method_password']) % 4)).decode('utf-8', errors='ignore') [cite: 135]
            except Exception:
                [cite_start]return False [cite: 136]
            [cite_start]if ':' not in decoded_mp: return False # 确保包含 method:password [cite: 136]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False [cite: 136]
            [cite_start]if not (1 <= int(data['port']) <= 65535): return False [cite: 136]
            return True
        elif protocol == "ssr":
            try:
                [cite_start]decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore') [cite: 137]
            except Exception:
                [cite_start]return False [cite: 137]
            [cite_start]parts = decoded.split(':') [cite: 137]
            [cite_start]if len(parts) < 6: return False # server:port:protocol:method:obfs:password_base64 [cite: 138]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False # server [cite: 138]
            [cite_start]if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False # port [cite: 138]
            # 协议、加密、混淆和密码可以更宽松，只要存在即可
            return True
        elif protocol == "vless":
            [cite_start]if not all(k in data for k in ['uuid', 'host', 'port', 'type']): return False [cite: 139]
            [cite_start]if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']: return False [cite: 139]
            [cite_start]if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']): return False [cite: 139]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False [cite: 139]
            [cite_start]if not (1 <= int(data['port']) <= 65535): return False [cite: 140]
            return True
        elif protocol == "tuic":
            [cite_start]if not all(k in data for k in ['uuid', 'password', 'host', 'port']): return False [cite: 140]
            [cite_start]if not data['uuid'] or not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False [cite: 140]
            [cite_start]if not (re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid'])): return False [cite: 141]
            [cite_start]if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False [cite: 141]
            [cite_start]if not (1 <= int(data['port']) <= 65535): return False [cite: 141]
            return True
        elif protocol == "wg":
            # WireGuard 通常是 Base64 编码的完整配置，解码后会有特定格式
            try:
                [cite_start]decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore') [cite: 142]
                # 简单检查 WireGuard 配置的关键字
                [cite_start]if "PrivateKey" in decoded and "Address" in decoded and "Endpoint" in decoded: [cite: 142]
                    return True
            except Exception:
                [cite_start]return False [cite: 143]
            return False
        return False
    except Exception as e:
        [cite_start]logger.debug(f"验证节点 {protocol} 失败: {e}") [cite: 143]
        return False

# --- 节点规范化与去重函数 ---
def get_node_canonical_fingerprint(node_url: str) -> str | [cite_start]None: [cite: 144]
    """生成节点的规范化指纹，用于去重"""
    [cite_start]base_url_no_remark = node_url.split('#', 1)[0] [cite: 144]
    try:
        [cite_start]parsed_url = urlparse(base_url_no_remark) [cite: 144]
        [cite_start]scheme = parsed_url.scheme [cite: 144]
        if not scheme:
            [cite_start]return None [cite: 144]

        if scheme == "ss":
            if not parsed_url.netloc:
                [cite_start]return None [cite: 145]
            [cite_start]auth_and_host = parsed_url.netloc [cite: 145]
            if '@' not in auth_and_host:
                [cite_start]return None [cite: 145]
            [cite_start]method_password_encoded, server_port = auth_and_host.split('@', 1) [cite: 145]
            try:
                [cite_start]padded_method_password_encoded = method_password_encoded + '=' * (4 - len(method_password_encoded) % 4) [cite: 146]
                [cite_start]decoded_method_password = base64.b64decode(padded_method_password_encoded).decode('utf-8', errors='ignore').strip() [cite: 146]
                [cite_start]decoded_method_password = decoded_method_password.replace('\n', '').replace('\r', '') [cite: 146]
                # 标准化方法和密码的顺序，通常方法在前
                [cite_start]parts = decoded_method_password.split(':', 1) [cite: 146]
                [cite_start]method = parts[0] [cite: 147]
                [cite_start]password = parts[1] if len(parts) > 1 else "" [cite: 147]
                [cite_start]return f"ss://{method}:{password}@{server_port}" [cite: 147]
            except Exception:
                [cite_start]return None [cite: 147]

        elif scheme == "ssr":
            [cite_start]encoded_params = base_url_no_remark[len("ssr://"):] [cite: 148]
            try:
                [cite_start]padded_encoded_params = encoded_params + '=' * (4 - len(encoded_params) % 4) [cite: 148]
                [cite_start]decoded_params = base64.b64decode(padded_encoded_params).decode('utf-8', errors='ignore') [cite: 148]
                [cite_start]core_params_part = decoded_params.split("/?")[0] [cite: 148]
                [cite_start]parts = core_params_part.split(':') [cite: 149]
                [cite_start]if len(parts) >= 6: [cite: 149]
                    # 解码密码部分并标准化
                    try:
                        [cite_start]password_encoded = parts[5] [cite: 149]
                        [cite_start]padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4) [cite: 150]
                        # SSR密码可能使用URL安全Base64变体，需要替换字符
                        [cite_start]decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore') [cite: 150]
                        [cite_start]parts[5] = decoded_password.strip() [cite: 151]
                    except Exception:
                        pass # 如果密码解码失败，保持原样，但这会影响去重精度
                [cite_start]return f"ssr://{':'.join(parts)}" [cite: 151]
            except Exception:
                [cite_start]return None [cite: 151]

        elif scheme == "vmess":
            [cite_start]encoded_json = base_url_no_remark[len("vmess://"):] [cite: 152]
            try:
                [cite_start]padded_encoded_json = encoded_json + '=' * (4 - len(encoded_json) % 4) [cite: 152]
                [cite_start]decoded_json = base64.b64decode(padded_encoded_json).decode('utf-8', errors='ignore') [cite: 152]
                [cite_start]vmess_config = json.loads(decoded_json) [cite: 152]
                fingerprint_data = {
                    [cite_start]"add": vmess_config.get("add"), [cite: 153]
                    [cite_start]"port": vmess_config.get("port"), [cite: 153]
                    [cite_start]"id": vmess_config.get("id"), [cite: 153]
                }
                # 包含关键的传输配置，如 net, type, tls, host, path, sni 等，按字典序排序
                [cite_start]optional_keys_for_fingerprint = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"] [cite: 154]
                for key in sorted(optional_keys_for_fingerprint):
                    [cite_start]if key in vmess_config and vmess_config[key] is not None: [cite: 154]
                        fingerprint_data[key] = vmess_config[key]
                
                [cite_start]return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}" [cite: 155]
            except Exception:
                [cite_start]return None [cite: 155]

        elif scheme in ["vless", "trojan", "hysteria2", "tuic"]:
            # 对于这些协议，主机、端口、ID/密码和查询参数是关键
            # 规范化查询参数：排序并重新编码
            [cite_start]query_params_list = parse_qs(parsed_url.query, keep_blank_values=True) [cite: 156]
            [cite_start]sorted_query_params = [] [cite: 156]
            for key in sorted(query_params_list.keys()):
                [cite_start]for value in sorted(query_params_list[key]): # 对值也进行排序，确保一致性 [cite: 156]
                    [cite_start]sorted_query_params.append((key, value)) [cite: 157]
            [cite_start]sorted_query_string = urlencode(sorted_query_params) [cite: 157]

            [cite_start]canonical_url_parts = [scheme, "://"] [cite: 157]
            # 用户信息（如果存在）
            if parsed_url.username:
                [cite_start]canonical_url_parts.append(parsed_url.username) [cite: 157]
                if parsed_url.password:
                    [cite_start]canonical_url_parts.append(f":{parsed_url.password}") [cite: 158]
                [cite_start]canonical_url_parts.append("@") [cite: 158]
            
            [cite_start]canonical_url_parts.append(parsed_url.netloc) [cite: 158]
            
            if parsed_url.path:
                [cite_start]canonical_url_parts.append(parsed_url.path) [cite: 158]
            if sorted_query_string:
                [cite_start]canonical_url_parts.append("?") [cite: 159]
                [cite_start]canonical_url_parts.append(sorted_query_string) [cite: 159]
            return "".join(canonical_url_parts)
            
        elif scheme == "wg":
            [cite_start]encoded_data = base_url_no_remark[len("wg://"):] [cite: 159]
            try:
                # WireGuard 指纹可以简单地基于其 Base64 编码的配置（假设配置是唯一的）
                # 理论上可以解析内部配置并规范化，但对于去重，原始编码通常足够
                [cite_start]return f"wg://{encoded_data}" [cite: 160]
            except Exception:
                [cite_start]return None [cite: 160]
            
        return None
    except Exception as e:
        [cite_start]logger.debug(f"规范化节点 '{node_url}' 失败: {e}") [cite: 161]
        return None

# --- 节点解析与提取函数 ---
def extract_nodes_from_text(text_content):
    """从文本中提取代理节点 (增强提取逻辑)"""
    extracted_nodes = set()
    
    # 优先匹配已知协议的节点
    [cite_start]for protocol, regex_pattern in NODE_REGEXES.items(): [cite: 161]
        [cite_start]for match in re.finditer(regex_pattern, text_content, re.IGNORECASE): # 忽略大小写 [cite: 162]
            [cite_start]full_uri = match.group(0) [cite: 162]
            [cite_start]matched_data = match.groupdict() [cite: 162]
            [cite_start]if validate_node(protocol, matched_data): [cite: 162]
                extracted_nodes.add(full_uri)

    # 尝试 Base64 解码和递归处理
    # 查找可能包含 Base64 编码数据的块
    # 改进的 Base64 正则表达式，尝试匹配更长的、以 = 结尾的有效 Base64 字符串
    # 并且避免匹配太短的、可能是普通文本的字符串
    [cite_start]base64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/])", text_content) [cite: 162]
    [cite_start]for b64_block in sorted(base64_candidates, key=len, reverse=True): # 优先处理长块 [cite: 162]
        [cite_start]if len(b64_block) > 30 and len(b64_block) % 4 == 0: # 设一个合理的长度阈值 [cite: 163]
            try:
                [cite_start]decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore') [cite: 163]
                # 递归处理解码后的内容
                [cite_start]recursive_nodes = extract_nodes_from_text(decoded_content) [cite: 163]
                [cite_start]extracted_nodes.update(recursive_nodes) [cite: 163]
            except Exception as e:
                [cite_start]logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...") [cite: 164]
        # 如果是订阅链接，有时会直接是 Base64 编码的订阅内容，长度可能会很长
        [cite_start]elif len(b64_block) > 100: # 对很长的Base64块也尝试一下 [cite: 164]
            try:
                [cite_start]decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore') [cite: 164]
                [cite_start]recursive_nodes = extract_nodes_from_text(decoded_content) [cite: 164]
                [cite_start]extracted_nodes.update(recursive_nodes) [cite: 165]
            except Exception:
                pass


    # 递归处理嵌套结构 (YAML/JSON)
    def extract_from_nested(data_obj):
        if isinstance(data_obj, dict):
            [cite_start]for key, value in data_obj.items(): [cite: 165]
                if isinstance(value, str):
                    [cite_start]extracted_nodes.update(extract_nodes_from_text(value)) [cite: 166]
                elif isinstance(value, (dict, list)):
                    [cite_start]extract_from_nested(value) [cite: 166]
        elif isinstance(data_obj, list):
            [cite_start]for item in data_obj: [cite: 166]
                if isinstance(item, str):
                    [cite_start]extracted_nodes.update(extract_nodes_from_text(item)) [cite: 167]
                elif isinstance(item, (dict, list)):
                    [cite_start]extract_from_nested(item) [cite: 167]

    try:
        [cite_start]yaml_content = yaml.safe_load(text_content) [cite: 167]
        if isinstance(yaml_content, (dict, list)):
            [cite_start]extract_from_nested(yaml_content) [cite: 167]
    except yaml.YAMLError as e:
        [cite_start]logger.debug(f"YAML 解析失败: {e}") [cite: 168]

    try:
        [cite_start]json_content = json.loads(text_content) [cite: 168]
        if isinstance(json_content, (dict, list)):
            [cite_start]extract_from_nested(json_content) [cite: 168]
    except json.JSONDecodeError as e:
        [cite_start]logger.debug(f"JSON 解析失败: {e}") [cite: 168]

    return extracted_nodes

def parse_and_extract_nodes(content):
    """从 HTML 内容中解析并提取节点 (增强HTML解析范围)"""
    [cite_start]nodes_from_html = set() [cite: 169]
    try:
        [cite_start]soup = BeautifulSoup(content, 'html.parser') [cite: 169]

        # 优先从常见包含配置的标签中提取
        [cite_start]for tag_name in ['pre', 'code', 'textarea']: [cite: 169]
            [cite_start]for tag in soup.find_all(tag_name): [cite: 169]
                [cite_start]text_content = tag.get_text(separator='\n', strip=True) # 使用换行符分隔，并去除空白 [cite: 169]
                if text_content:
                    [cite_start]nodes_from_html.update(extract_nodes_from_text(text_content)) [cite: 170]

        # 尝试从 <script> 标签中提取 JSON 或其他配置
        [cite_start]for script_tag in soup.find_all('script'): [cite: 170]
            [cite_start]script_content = script_tag.string [cite: 170]
            if script_content:
                # 尝试解析 JSON 格式的脚本内容
                try:
                    [cite_start]json_data = json.loads(script_content) [cite: 170]
                    [cite_start]nodes_from_html.update(extract_nodes_from_text(json.dumps(json_data))) [cite: 171]
                except json.JSONDecodeError:
                    # 如果不是标准JSON，也尝试作为普通文本处理
                    [cite_start]nodes_from_html.update(extract_nodes_from_text(script_content)) [cite: 171]
            
        # 如果以上标签未找到节点，或者为了更全面，检查整个 body 文本
        if not nodes_from_html:
            [cite_start]body_text = soup.body.get_text(separator='\n', strip=True) if soup.body else soup.get_text(separator='\n', strip=True) [cite: 172]
            [cite_start]nodes_from_html.update(extract_nodes_from_text(body_text)) [cite: 172]

    except Exception as e:
        [cite_start]logger.error(f"解析 HTML 内容时发生错误: {e}") [cite: 172]
    return nodes_from_html

async def process_url(url, http_client, playwright_instance: Playwright, processed_urls, all_nodes_count, global_unique_nodes_map):
    """处理单个 URL，提取节点并递归处理相关链接"""
    if url in processed_urls:
        [cite_start]logger.debug(f"URL '{url}' 已经处理过，跳过。") [cite: 172]
        return set()

    [cite_start]processed_urls.add(url) [cite: 173]
    [cite_start]logger.info(f"正在处理 URL: {url}") [cite: 173]
    
    [cite_start]content = await fetch_url(url, http_client, playwright_instance) [cite: 173]
    if not content:
        [cite_start]logger.error(f"未能获取 {url} 的内容，跳过节点提取。") [cite: 173]
        return set()

    [cite_start]nodes_from_current_url_content = parse_and_extract_nodes(content) [cite: 173]
    [cite_start]collected_nodes_for_this_url_tree = set() [cite: 173]

    # 去重当前 URL 的节点
    [cite_start]for node in nodes_from_current_url_content: [cite: 174]
        [cite_start]canonical_fingerprint = get_node_canonical_fingerprint(node) [cite: 174]
        [cite_start]if canonical_fingerprint and canonical_fingerprint not in global_unique_nodes_map: [cite: 174]
            [cite_start]global_unique_nodes_map[canonical_fingerprint] = node [cite: 174]
            [cite_start]collected_nodes_for_this_url_tree.add(node) [cite: 174]
        elif canonical_fingerprint:
            [cite_start]logger.debug(f"节点 '{node[:50]}...' 已存在，跳过。") [cite: 174]

    try:
        [cite_start]soup = BeautifulSoup(content, 'html.parser') [cite: 174]
        [cite_start]found_links = set() [cite: 175]
        [cite_start]for a_tag in soup.find_all('a', href=True): [cite: 175]
            [cite_start]href = a_tag['href'] [cite: 175]
            [cite_start]parsed_href = urlparse(href) [cite: 175]

            # 提取域名部分进行比较
            [cite_start]current_base_domain = urlparse(f"http://{url}").netloc # 确保当前处理的URL有scheme [cite: 175]
            [cite_start]target_netloc = parsed_href.netloc # 提取链接的netloc [cite: 176]

            # 如果链接是相对路径，或者与当前域名相同，或者包含特定关键词
            if parsed_href.scheme and target_netloc and (
                "subscribe" in href.lower() or 
                "config" in href.lower() or 
                "proxy" in href.lower() or 
                [cite_start]target_netloc == current_base_domain # 同域名链接 [cite: 176]
            ):
                # 进一步规范化链接，只保留域名部分用于去重和递归
                [cite_start]domain_to_add = target_netloc [cite: 177]
                if domain_to_add and domain_to_add not in processed_urls:
                    [cite_start]found_links.add(domain_to_add) [cite: 177]
            elif not parsed_href.scheme and href.startswith('/') and len(href) > 1: # 相对路径
                if current_base_domain and current_base_domain not in processed_urls:
                    [cite_start]found_links.add(current_base_domain) # 相对路径回到本域名 [cite: 178]

        for link_to_process in found_links:
            if link_to_process not in processed_urls:
                [cite_start]logger.info(f"发现新链接，准备递归处理: {link_to_process}") [cite: 178]
                try:
                    async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 4):  # 递归调用给更长时间
                        [cite_start]recursive_nodes = await process_url(link_to_process, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map) [cite: 179]
                        for node in recursive_nodes:
                            [cite_start]canonical_fingerprint = get_node_canonical_fingerprint(node) [cite: 179]
                            if canonical_fingerprint and canonical_fingerprint not in global_unique_nodes_map:
                                [cite_start]global_unique_nodes_map[canonical_fingerprint] = node [cite: 180]
                                [cite_start]collected_nodes_for_this_url_tree.add(node) [cite: 180]
                            elif canonical_fingerprint:
                                [cite_start]logger.debug(f"递归节点 '{node[:50]}...' 已存在，跳过。") [cite: 181]
                except asyncio.TimeoutError:
                    [cite_start]logger.warning(f"递归处理链接 {link_to_process} 超时，跳过。") [cite: 181]
                except Exception as e:
                    [cite_start]logger.error(f"递归处理链接 {link_to_process} 失败: {e}") [cite: 182]
    except Exception as e:
        [cite_start]logger.error(f"处理 URL {url} 的链接时发生错误: {e}") [cite: 182]

    [cite_start]nodes_count = len(collected_nodes_for_this_url_tree) [cite: 183]
    [cite_start]logger.info(f"从 {url} (及其子链接) 提取了 {nodes_count} 个有效节点。") [cite: 183]
    [cite_start]all_nodes_count[url] = nodes_count [cite: 183]

    # --- 文件输出逻辑修改：只有有节点时才生成文件 ---
    if nodes_count > 0:
        file_domain_name = None
        try:
            [cite_start]temp_url_for_parse = url [cite: 183]
            if not urlparse(url).scheme:
                [cite_start]temp_url_for_parse = f"http://{url}" [cite: 183]

            [cite_start]parsed_url_for_filename = urlparse(temp_url_for_parse) [cite: 184]
            # 优先使用 netloc 作为文件名
            [cite_start]file_domain_name = parsed_url_for_filename.netloc [cite: 184]

            if not file_domain_name:
                # 如果 netloc 为空（例如，URL 只有路径），尝试从路径中生成文件名
                [cite_start]path_segments = [seg for seg in parsed_url_for_filename.path.strip('/').split('/') if seg] [cite: 184]
                if path_segments:
                    # 取路径的最后一段或多段作为文件名基础
                    [cite_start]file_domain_name = '_'.join(path_segments[-2:]) # 取最后两段，更具描述性 [cite: 185]
                else:
                    # 最终的兜底，直接使用原始 URL进行简单清理
                    [cite_start]file_domain_name = url.replace('/', '_').replace(':', '_').replace('.', '_') [cite: 185]
            
            # 清理文件名，确保合法且不包含特殊字符
            [cite_start]file_domain_name = re.sub(r'[<>:"/\\|?*]', '_', file_domain_name) [cite: 186]
            [cite_start]file_domain_name = file_domain_name.strip().lower() # 移除首尾空格，转换为小写 [cite: 186]
            # 避免文件名过长
            if len(file_domain_name) > 100:
                [cite_start]file_domain_name = hashlib.md5(file_domain_name.encode('utf-8')).hexdigest() [cite: 186]
            
            if not file_domain_name:
                [cite_start]file_domain_name = None # 如果清理后仍然为空，则设为None [cite: 187]

        except Exception as e:
            [cite_start]logger.error(f"生成 URL '{url}' 的文件名前发生错误: {e}") [cite: 187]
            file_domain_name = None

        if file_domain_name:
            # Output individual node files to the 'data' directory (unchanged)
            output_file = os.path.join("data", f"{file_domain_name}.txt") 
            try:
                async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
                    for node in collected_nodes_for_this_url_tree:
                        [cite_start]await f.write(node + '\n') [cite: 188]
                [cite_start]logger.info(f"从 {url} 获取的 {nodes_count} 个节点已保存到 {output_file}。") [cite: 188]
            except Exception as e:
                [cite_start]logger.error(f"保存节点到 {output_file} 失败: {e}") [cite: 189]
        else:
            [cite_start]logger.warning(f"无法为 URL '{url}' 生成有效的文件名，该 URL 的节点未单独保存。") [cite: 189]
    else:
        [cite_start]logger.info(f"URL '{url}' 及其子链接未提取到任何节点，跳过生成独立文件。") [cite: 189]
            
    return collected_nodes_for_this_url_tree

def get_short_url_name(url):
    """从 URL 生成简短文件名 (旧函数，实际已在 process_url 中优化)"""
    # [cite_start]此函数已不再用于生成单独的文件名，但保留以防万一或未来其他用途 [cite: 190]
    try:
        if not urlparse(url).scheme:
            [cite_start]url_with_scheme = f"http://{url}" [cite: 190]
        else:
            [cite_start]url_with_scheme = url [cite: 191]
            
        [cite_start]parsed_url = urlparse(url_with_scheme) [cite: 191]
        [cite_start]domain = parsed_url.netloc or parsed_url.path [cite: 191]
        
        [cite_start]domain = domain.replace('www.', '') [cite: 191]
        [cite_start]domain = re.sub(r'\.(com|net|org|xyz|top|info|io|cn|jp|ru|uk|de|fr|me|tv|cc|pw|win|online|site|space|fun|club|link|shop|icu|vip|bid|red|rocks|gdn|click|fans|live|loan|mom|monster|pics|press|pro|rest|review|rocks|run|sbs|store|tech|website|wiki|work|world|zone)(?:\.[a-z]{2,3})?$', '', domain, flags=re.IGNORECASE) [cite: 191]
        
        if is_valid_ip(domain):
            [cite_start]return domain.replace('.', '_') [cite: 192]
        [cite_start]parts = domain.split('.') [cite: 192]
        if len(parts) > 1:
            [cite_start]return parts[-2] if len(parts) >= 2 else parts[0] [cite: 192]
        else:
            [cite_start]return parts[0] [cite: 192]
    except Exception as e:
        [cite_start]logger.error(f"处理 URL 名称时发生错误 {url}: {e}") [cite: 192]
        return None

async def main():
    """主函数，协调抓取和保存过程"""
    # Remove creation of OUTPUT_DIR here, as all_unique_nodes.txt and nodes_summary.csv
    # will be saved in the root, and individual files are handled in process_url
    # os.makedirs(OUTPUT_DIR, exist_ok=True) 
    [cite_start]os.makedirs(CACHE_DIR, exist_ok=True) [cite: 193]
    
    raw_urls = []
    try:
        with open("sources.list", 'r', encoding='utf-8') as f:
            for line in f:
                [cite_start]url = line.strip() [cite: 193]
                if url:
                    [cite_start]raw_urls.append(url) [cite: 193]
    except FileNotFoundError:
        [cite_start]logger.critical("错误: sources.list 文件未找到。请确保它存在于根目录。") [cite: 193]
        return
    except Exception as e:
        [cite_start]logger.error(f"读取 sources.list 文件失败: {e}") [cite: 194]
        return

    [cite_start]valid_urls_after_dns = [] [cite: 194]
    [cite_start]logger.info("--- 开始 DNS 解析预检查 ---") [cite: 194]
    [cite_start]dns_check_tasks = [check_dns_resolution(url) for url in raw_urls] [cite: 194]
    [cite_start]dns_results = await asyncio.gather(*dns_check_tasks, return_exceptions=True) [cite: 194]

    [cite_start]for i, url in enumerate(raw_urls): [cite: 195]
        if isinstance(dns_results[i], Exception):
            [cite_start]logger.warning(f"DNS 解析 '{url}' 失败: {dns_results[i]}") [cite: 195]
        elif dns_results[i]:
            [cite_start]valid_urls_after_dns.append(url) [cite: 195]
        else:
            [cite_start]logger.info(f"URL '{url}' DNS 解析失败，已跳过。") [cite: 195]
            
    [cite_start]logger.info(f"--- DNS 解析预检查完成。成功解析 {len(valid_urls_after_dns)} 个 URL ---") [cite: 195]

    if not valid_urls_after_dns:
        [cite_start]logger.warning("没有可用的有效 URL 进行抓取，程序退出。") [cite: 195]
        return

    [cite_start]processed_urls = set() [cite: 196]
    [cite_start]all_nodes_count = {} [cite: 196]
    [cite_start]global_unique_nodes_map = {} [cite: 196]

    async with async_playwright() as p:
        async with httpx.AsyncClient(http2=True, follow_redirects=True) as http_client:
            [cite_start]semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS) [cite: 196]
            
            async def bounded_process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map, semaphore):
                """封装 URL 处理任务，确保错误不会中断整体运行"""
                try:
                    async with semaphore:
                        [cite_start]return await process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map) [cite: 197]
                except Exception as e:
                    [cite_start]logger.error(f"处理 URL {url} 时发生错误: {e}") [cite: 197]
                    return set()

            [cite_start]tasks = [bounded_process_url(url, http_client, p, processed_urls, all_nodes_count, global_unique_nodes_map, semaphore) for url in valid_urls_after_dns] [cite: 198]
            
            [cite_start]logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个 URL 的抓取任务，最大并发数：{MAX_CONCURRENT_REQUESTS}") [cite: 198]
            [cite_start]results = await asyncio.gather(*tasks, return_exceptions=True) [cite: 198]
            
            [cite_start]for url, result in zip(valid_urls_after_dns, results): [cite: 199]
                if isinstance(result, Exception):
                    [cite_start]logger.error(f"处理 URL {url} 失败: {result}") [cite: 199]

    # --- 修改保存路径到根目录 ---
    all_unique_nodes_file = "all_unique_nodes.txt"  # 直接指定文件名，使其保存在根目录
    try:
        if global_unique_nodes_map:
            async with aiofiles.open(all_unique_nodes_file, 'w', encoding='utf-8') as f:
                for node in sorted(global_unique_nodes_map.values()):
                    [cite_start]await f.write(node + '\n') [cite: 200]
            [cite_start]logger.info(f"所有 {len(global_unique_nodes_map)} 个唯一节点已保存到 {all_unique_nodes_file}。") [cite: 200]
        else:
            [cite_start]logger.info("未找到任何唯一节点，跳过保存 all_unique_nodes.txt 文件。") [cite: 200]
    except Exception as e:
        [cite_start]logger.error(f"保存唯一节点到 {all_unique_nodes_file} 失败: {e}") [cite: 200]

    csv_file_path = "nodes_summary.csv"  # 直接指定文件名，使其保存在根目录
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            [cite_start]fieldnames = ['URL', '节点数量'] [cite: 201]
            [cite_start]writer = csv.DictWriter(csvfile, fieldnames=fieldnames) [cite: 201]
            [cite_start]writer.writeheader() [cite: 201]
            for url, count in all_nodes_count.items():
                [cite_start]writer.writerow({'URL': url, '节点数量': count}) [cite: 201]
        [cite_start]logger.info(f"节点数量统计已保存到 {csv_file_path}。") [cite: 201]
    except Exception as e:
        [cite_start]logger.error(f"保存节点统计到 {csv_file_path} 失败: {e}") [cite: 201]
    
    [cite_start]logger.info("--- 脚本运行结束 ---") [cite: 202]

if __name__ == "__main__":
    asyncio.run(main())
