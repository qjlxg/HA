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
OUTPUT_DIR = "data"  # 输出目录
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

# 节点协议正则表达式（保留旧脚本的详细正则）
NODE_REGEXES = {
    "hysteria2": r"hysteria2:\/\/(?P<id>[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?(?P<host>[a-zA-Z0-9\-\.]+)(?::(?P<port>\d+))?\/?\?.*",
    "vmess": r"vmess:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "trojan": r"trojan:\/\/(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:\/\?.*)?",
    "ss": r"ss:\/\/(?P<method_password>[a-zA-Z0-9+\/=]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:#(?P<name>.*))?",
    "ssr": r"ssr:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "vless": r"vless:\/\/(?P<uuid>[a-zA-Z0-9\-]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?type=(?P<type>[a-zA-Z0-9]+)(?:&security=(?P<security>[a-zA-Z0-9]+))?.*",
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
    full_url_http = f"http://{url}"
    full_url_https = f"https://{url}"
    
    cached_content = await read_cache(url)
    if cached_content:
        return cached_content
        
    content = None
    
    # 尝试 httpx 获取 HTTP
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

    # 尝试 httpx 获取 HTTPS
    if content is None:
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
    
    # 如果 httpx 失败，尝试 Playwright
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            logger.info(f"httpx 未能获取 {url} 内容，尝试使用 Playwright (第 {attempt + 1} 次)...")
            browser = None
            try:
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 2):  # Playwright 可能需要更长时间
                    browser = await playwright_instance.chromium.launch()
                    page = await browser.new_page()
                    await page.set_extra_http_headers(get_random_headers())
                    full_url = f"https://{url}"
                    try:
                        await page.goto(full_url, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url} 获取内容。")
                        break
                    except Exception as e:
                        logger.warning(f"Playwright 从 {full_url} 获取失败: {e} (第 {attempt + 1} 次)。尝试 HTTP。")
                        full_url = f"http://{url}"
                        await page.goto(full_url, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url} 获取内容。")
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
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            answers = await asyncio.to_thread(dns.resolver.resolve, url, 'A')
            if answers:
                logger.info(f"域名 '{url}' 解析成功，IP: {[str(a) for a in answers]}")
                return True
            else:
                logger.warning(f"域名 '{url}' 未能解析到 IP 地址。")
                return False
    except asyncio.TimeoutError:
        logger.warning(f"DNS 解析 '{url}' 超时。")
        return False
    except dns.resolver.NXDOMAIN:
        logger.warning(f"域名 '{url}' 不存在 (NXDOMAIN)。")
        return False
    except dns.resolver.NoAnswer:
        logger.warning(f"域名 '{url}' 没有可用的 A 记录。")
        return False
    except dns.resolver.NoNameservers as e:
        logger.warning(f"DNS 解析 '{url}' 失败: 所有名称服务器都未能应答 ({e})。")
        return False
    except Exception as e:
        logger.error(f"DNS 解析 '{url}' 时发生未知错误: {e}", exc_info=True)
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
    """验证节点数据有效性"""
    logger.debug(f"正在验证 {protocol} 节点数据: {data}")
    try:
        if protocol == "hysteria2":
            if not all(k in data for k in ['host', 'port']): return False
            if not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "vmess":
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8', errors='ignore')
            json_data = json.loads(decoded)
            if not all(k in json_data for k in ['add', 'port', 'id']): return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False
            if not isinstance(json_data['port'], int) or not (1 <= json_data['port'] <= 65535): return False
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
            decoded_mp = base64.b64decode(data['method_password']).decode('utf-8', errors='ignore')
            if ':' not in decoded_mp: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ssr":
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8', errors='ignore')
            parts = decoded.split(':')
            if len(parts) < 6: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False
            return True
        elif protocol == "vless":
            if not all(k in data for k in ['uuid', 'host', 'port', 'type']): return False
            if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']: return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
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
                return f"ss://{decoded_method_password}@{server_port}"
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
                    try:
                        password_encoded = parts[5]
                        padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4)
                        decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                        parts[5] = decoded_password.strip()
                    except Exception:
                        pass
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
                optional_keys = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]
                optional_params = {key: vmess_config[key] for key in optional_keys if key in vmess_config and vmess_config[key] is not None}
                sorted_optional_params = sorted(optional_params.items())
                for k, v in sorted_optional_params:
                    fingerprint_data[k] = v
                return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"
            except Exception:
                return None

        elif scheme in ["vless", "trojan", "hysteria2"]:
            query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
            sorted_query_params = []
            for key in sorted(query_params_list.keys()):
                for value in query_params_list[key]:
                    sorted_query_params.append((key, value))
            sorted_query_string = urlencode(sorted_query_params)
            canonical_url_parts = [scheme, "://", parsed_url.netloc]
            if parsed_url.path:
                canonical_url_parts.append(parsed_url.path)
            if sorted_query_string:
                canonical_url_parts.append("?")
                canonical_url_parts.append(sorted_query_string)
            return "".join(canonical_url_parts)
            
        return None
    except Exception as e:
        logger.debug(f"规范化节点 '{node_url}' 失败: {e}")
        return None

# --- 节点解析与提取函数 ---
def extract_nodes_from_text(text_content):
    """从文本中提取代理节点"""
    extracted_nodes = set()
    try:
        for protocol, regex_pattern in NODE_REGEXES.items():
            for match in re.finditer(regex_pattern, text_content):
                matched_data = match.groupdict()
                if validate_node(protocol, matched_data):
                    extracted_nodes.add(match.group(0))

        base64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text_content)
        for b64_block in base64_matches:
            if len(b64_block) > 16 and len(b64_block) % 4 == 0:
                try:
                    decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                    extracted_nodes.update(extract_nodes_from_text(decoded_content))
                except Exception as e:
                    logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...")

        def extract_from_nested(data_obj):
            if isinstance(data_obj, dict):
                for key, value in data_obj.items():
                    if isinstance(value, str):
                        extracted_nodes.update(extract_nodes_from_text(value))
                    elif isinstance(value, (dict, list)):
                        extract_from_nested(value)
            elif isinstance(data_obj, list):
                for item in data_obj:
                    if isinstance(item, str):
                        extracted_nodes.update(extract_nodes_from_text(item))
                    elif isinstance(item, (dict, list)):
                        extract_from_nested(item)

        try:
            yaml_content = yaml.safe_load(text_content)
            if isinstance(yaml_content, (dict, list)):
                extract_from_nested(yaml_content)
        except yaml.YAMLError as e:
            logger.debug(f"YAML 解析失败: {e}")

        try:
            json_content = json.loads(text_content)
            if isinstance(json_content, (dict, list)):
                extract_from_nested(json_content)
        except json.JSONDecodeError as e:
            logger.debug(f"JSON 解析失败: {e}")
    except Exception as e:
        logger.error(f"提取节点时发生错误: {e}")
    return extracted_nodes

def parse_and_extract_nodes(content):
    """从 HTML 内容中解析并提取节点"""
    nodes_from_html = set()
    try:
        soup = BeautifulSoup(content, 'html.parser')
        for tag_name in ['pre', 'code', 'textarea']:
            for tag in soup.find_all(tag_name):
                text_content = tag.get_text()
                if text_content:
                    nodes_from_html.update(extract_nodes_from_text(text_content))
        if not nodes_from_html:
            body_text = soup.get_text()
            nodes_from_html.update(extract_nodes_from_text(body_text))
    except Exception as e:
        logger.error(f"解析 HTML 内容时发生错误: {e}")
    return nodes_from_html

async def process_url(url, http_client, playwright_instance: Playwright, processed_urls, all_nodes_count, global_unique_nodes_map):
    """处理单个 URL，提取节点并递归处理相关链接"""
    if url in processed_urls:
        logger.debug(f"URL '{url}' 已经处理过，跳过。")
        return set()

    processed_urls.add(url)
    logger.info(f"正在处理 URL: {url}")
    
    content = await fetch_url(url, http_client, playwright_instance)
    if not content:
        logger.error(f"未能获取 {url} 的内容，跳过节点提取。")
        return set()

    nodes_from_current_url_content = parse_and_extract_nodes(content)
    collected_nodes_for_this_url_tree = set()

    # 去重当前 URL 的节点
    for node in nodes_from_current_url_content:
        canonical_fingerprint = get_node_canonical_fingerprint(node)
        if canonical_fingerprint and canonical_fingerprint not in global_unique_nodes_map:
            global_unique_nodes_map[canonical_fingerprint] = node
            collected_nodes_for_this_url_tree.add(node)

    try:
        soup = BeautifulSoup(content, 'html.parser')
        found_links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            parsed_href = urlparse(href)
            if parsed_href.netloc:
                if "subscribe" in href or "config" in href or "proxy" in href or parsed_href.netloc == urlparse(f"http://{url}").netloc:
                    domain_match = re.match(r"(?:https?://)?(?:www\.)?([^/]+)", parsed_href.netloc)
                    if domain_match:
                        found_links.add(domain_match.group(1))
            elif href.startswith('/') and len(href) > 1:
                base_domain = urlparse(f"http://{url}").netloc
                if base_domain:
                    found_links.add(base_domain)
        
        for link_to_process in found_links:
            if link_to_process not in processed_urls:
                logger.info(f"发现新链接，准备递归处理: {link_to_process}")
                try:
                    async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 4):  # 递归调用给更长时间
                        recursive_nodes = await process_url(link_to_process, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map)
                        for node in recursive_nodes:
                            canonical_fingerprint = get_node_canonical_fingerprint(node)
                            if canonical_fingerprint and canonical_fingerprint not in global_unique_nodes_map:
                                global_unique_nodes_map[canonical_fingerprint] = node
                                collected_nodes_for_this_url_tree.add(node)
                except asyncio.TimeoutError:
                    logger.warning(f"递归处理链接 {link_to_process} 超时，跳过。")
                except Exception as e:
                    logger.error(f"递归处理链接 {link_to_process} 失败: {e}")
    except Exception as e:
        logger.error(f"处理 URL {url} 的链接时发生错误: {e}")

    nodes_count = len(collected_nodes_for_this_url_tree)
    logger.info(f"从 {url} (及其子链接) 提取了 {nodes_count} 个有效节点。")
    all_nodes_count[url] = nodes_count

    # --- 修改这里，以完整域名保存文件 ---
    file_domain_name = None
    try:
        # 确保 URL 有 scheme，以便 urlparse 正确解析 netloc
        temp_url_for_parse = url
        if not urlparse(url).scheme:
            temp_url_for_parse = f"http://{url}" # 假设默认是 http，因为原始 URL 可能没有 scheme

        parsed_url_for_filename = urlparse(temp_url_for_parse)
        file_domain_name = parsed_url_for_filename.netloc

        # 如果 netloc 为空（例如，URL 只有路径），尝试从路径中生成文件名
        if not file_domain_name and parsed_url_for_filename.path:
            # 清理路径，将非文件名的字符替换掉，例如 / : .
            file_domain_name = parsed_url_for_filename.path.strip('/').replace('/', '_').replace(':', '_').replace('.', '_')
        elif not file_domain_name: # 最终的兜底，直接使用原始 URL进行简单清理
            file_domain_name = url.replace('/', '_').replace(':', '_').replace('.', '_')

        # 进一步清理，确保文件名合法
        file_domain_name = re.sub(r'[<>:"/\\|?*]', '_', file_domain_name) # 移除非法文件名字符
        file_domain_name = file_domain_name.strip() # 移除首尾空格
        if not file_domain_name: # 如果清理后文件名为空，则设置为 None
            file_domain_name = None

    except Exception as e:
        logger.error(f"生成 URL '{url}' 的文件名前发生错误: {e}")
        file_domain_name = None

    if file_domain_name:
        output_file = os.path.join(OUTPUT_DIR, f"{file_domain_name}.txt")
        try:
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
                for node in collected_nodes_for_this_url_tree:
                    await f.write(node + '\n')
            logger.info(f"从 {url} 获取的 {nodes_count} 个节点已保存到 {output_file}。")
        except Exception as e:
            logger.error(f"保存节点到 {output_file} 失败: {e}")
    else:
        logger.warning(f"无法为 URL '{url}' 生成有效的文件名，节点未单独保存。")
        
    return collected_nodes_for_this_url_tree

def get_short_url_name(url):
    """从 URL 生成简短文件名"""
    try:
        if not urlparse(url).scheme:
            url_with_scheme = f"http://{url}"
        else:
            url_with_scheme = url
            
        parsed_url = urlparse(url_with_scheme)
        domain = parsed_url.netloc or parsed_url.path
        
        domain = domain.replace('www.', '')
        domain = re.sub(r'\.(com|net|org|xyz|top|info|io|cn|jp|ru|uk|de|fr|me|tv|cc|pw|win|online|site|space|fun|club|link|shop|icu|vip|bid|red|rocks|gdn|click|fans|live|loan|mom|monster|pics|press|pro|rest|review|rocks|run|sbs|store|tech|website|wiki|work|world|zone)(?:\.[a-z]{2,3})?$', '', domain, flags=re.IGNORECASE)
        
        if is_valid_ip(domain):
            return domain.replace('.', '_')
        parts = domain.split('.')
        if len(parts) > 1:
            return parts[-2] if len(parts) >= 2 else parts[0]
        else:
            return parts[0]
    except Exception as e:
        logger.error(f"处理 URL 名称时发生错误 {url}: {e}")
        return None

async def main():
    """主函数，协调抓取和保存过程"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    raw_urls = []
    try:
        with open("sources.list", 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    raw_urls.append(url)
    except FileNotFoundError:
        logger.critical("错误: sources.list 文件未找到。请确保它存在于根目录。")
        return
    except Exception as e:
        logger.error(f"读取 sources.list 文件失败: {e}")
        return

    valid_urls_after_dns = []
    logger.info("--- 开始 DNS 解析预检查 ---")
    dns_check_tasks = [check_dns_resolution(url) for url in raw_urls]
    dns_results = await asyncio.gather(*dns_check_tasks, return_exceptions=True)

    for i, url in enumerate(raw_urls):
        if isinstance(dns_results[i], Exception):
            logger.warning(f"DNS 解析 '{url}' 失败: {dns_results[i]}")
        elif dns_results[i]:
            valid_urls_after_dns.append(url)
        else:
            logger.info(f"URL '{url}' DNS 解析失败，已跳过。")
            
    logger.info(f"--- DNS 解析预检查完成。成功解析 {len(valid_urls_after_dns)} 个 URL ---")

    if not valid_urls_after_dns:
        logger.warning("没有可用的有效 URL 进行抓取，程序退出。")
        return

    processed_urls = set()
    all_nodes_count = {}
    global_unique_nodes_map = {}

    async with async_playwright() as p:
        async with httpx.AsyncClient(http2=True, follow_redirects=True) as http_client:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def bounded_process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map, semaphore):
                """封装 URL 处理任务，确保错误不会中断整体运行"""
                try:
                    async with semaphore:
                        return await process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map)
                except Exception as e:
                    logger.error(f"处理 URL {url} 时发生错误: {e}")
                    return set()

            tasks = [bounded_process_url(url, http_client, p, processed_urls, all_nodes_count, global_unique_nodes_map, semaphore) for url in valid_urls_after_dns]
            
            logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个 URL 的抓取任务，最大并发数：{MAX_CONCURRENT_REQUESTS}")
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
            for url, count in all_nodes_count.items():
                writer.writerow({'URL': url, '节点数量': count})
        logger.info(f"节点数量统计已保存到 {csv_file_path}。")
    except Exception as e:
        logger.error(f"保存节点统计到 {csv_file_path} 失败: {e}")
    
    logger.info("--- 脚本运行结束 ---")

if __name__ == "__main__":
    asyncio.run(main())
