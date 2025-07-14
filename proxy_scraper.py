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
OUTPUT_DIR = "data"
CACHE_DIR = "cache"
CACHE_EXPIRATION_HOURS = 24
MAX_CONCURRENT_REQUESTS = 5 # 调低并发数以适应 Playwright 资源消耗

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

# 更新后的 NODE_REGEXES，更严格地识别 URL 的结束位置
NODE_REGEXES = {
    "ss": r"ss://[^#\s]+(?:#.*)?",
    "ssr": r"ssr://[^#\s]+(?:#.*)?",
    "vmess": r"vmess://[^#\s]+(?:#.*)?",
    "vless": r"vless://[^#\s]+(?:#.*)?",
    "trojan": r"trojan://[^#\s]+(?:#.*)?",
    "hysteria2": r"hysteria2://[^#\s]+(?:#.*)?"
}

# --- 缓存处理函数 ---
def generate_cache_key(url):
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
    cache_path = get_cache_path(url)
    if not os.path.exists(cache_path):
        logger.debug(f"缓存文件不存在: {cache_path}")
        return None
    
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path))
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        logger.info(f"缓存 '{url}' 已过期。")
        os.remove(cache_path)
        return None
    
    async with asyncio.Lock():
        async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
            logger.info(f"从缓存读取 '{url}'。")
            return await f.read()

async def write_cache(url, content):
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True)
    async with asyncio.Lock():
        async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
            await f.write(content)
    logger.info(f"内容已写入缓存 '{url}'。")

# --- 网络请求相关函数 ---
def get_random_headers():
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

# 修改后的 fetch_url，优先尝试 httpx，失败后尝试 Playwright
async def fetch_url(url, http_client, playwright_instance: Playwright):
    full_url_http = f"http://{url}"
    full_url_https = f"https://{url}"
    
    cached_content = await read_cache(url)
    if cached_content:
        return cached_content
        
    content = None
    
    # --- 尝试使用 httpx 获取 ---
    try:
        headers = get_random_headers()
        logger.info(f"尝试用 httpx 从 {full_url_http} 获取内容...")
        response = await http_client.get(full_url_http, timeout=30, headers=headers)
        response.raise_for_status()
        content = response.text
        logger.info(f"httpx 成功从 {full_url_http} 获取内容。")
    except httpx.HTTPStatusError as e:
        logger.warning(f"httpx 从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code})。尝试 HTTPS。URL: {url}")
    except httpx.RequestError as e:
        logger.warning(f"httpx 从 {full_url_http} 获取失败 (请求错误: {e})。尝试 HTTPS。URL: {url}")
    except Exception as e:
        logger.error(f"httpx 从 {full_url_http} 获取时发生未知错误: {e}。URL: {url}", exc_info=True)

    if content is None:
        try:
            headers = get_random_headers()
            logger.info(f"尝试用 httpx 从 {full_url_https} 获取内容...")
            response = await http_client.get(full_url_https, timeout=30, headers=headers)
            response.raise_for_status()
            content = response.text
            logger.info(f"httpx 成功从 {full_url_https} 获取内容。")
        except httpx.HTTPStatusError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code})。URL: {url}")
        except httpx.RequestError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (请求错误: {e})。URL: {url}")
        except Exception as e:
            logger.error(f"httpx 从 {full_url_https} 获取时发生未知错误: {e}。URL: {url}", exc_info=True)
    
    # --- 如果 httpx 失败，尝试使用 Playwright 获取 ---
    if content is None:
        logger.info(f"httpx 未能获取 {url} 内容，尝试使用 Playwright...")
        try:
            browser = await playwright_instance.chromium.launch() # 启动 Chromium 浏览器
            page = await browser.new_page()
            # 设置 Playwright 的 User-Agent 与随机生成的一致
            await page.set_extra_http_headers(get_random_headers())
            
            full_url = f"https://{url}" # 优先尝试 HTTPS，因为 Playwright 通常处理得更好
            try:
                await page.goto(full_url, timeout=30000, wait_until='networkidle') # 等待网络空闲
                content = await page.content() # 获取渲染后的 HTML 内容
                logger.info(f"Playwright 成功从 {full_url} 获取内容。")
            except Exception as e:
                logger.warning(f"Playwright 从 {full_url} 获取失败: {e}。尝试 HTTP。URL: {url}")
                full_url = f"http://{url}"
                await page.goto(full_url, timeout=30000, wait_until='networkidle')
                content = await page.content()
                logger.info(f"Playwright 成功从 {full_url} 获取内容。")
            finally:
                await browser.close() # 关闭浏览器
        except Exception as e:
            logger.error(f"Playwright 从 {url} 获取时发生未知错误: {e}。URL: {url}", exc_info=True)
            content = None # 确保在 Playwright 失败时内容为 None

    if content:
        await write_cache(url, content)
    else:
        logger.error(f"未能获取 {url} 的内容，跳过。")
    return content

# --- DNS 解析函数 ---
async def check_dns_resolution(url):
    """
    检查给定 URL 的域名是否可以解析到有效的 IP 地址。
    """
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, url, 'A')
        if answers:
            logger.info(f"域名 '{url}' 解析成功，IP: {[str(a) for a in answers]}")
            return True
        else:
            logger.warning(f"域名 '{url}' 未能解析到 IP 地址。")
            return False
    except dns.resolver.NXDOMAIN:
        logger.warning(f"域名 '{url}' 不存在 (NXDOMAIN)。")
        return False
    except dns.resolver.Timeout:
        logger.warning(f"DNS 解析 '{url}' 超时。")
        return False
    except dns.resolver.NoAnswer:
        logger.warning(f"域名 '{url}' 没有可用的 A 记录。")
        return False
    except dns.resolver.NoNameservers as e:
        logger.warning(f"DNS 解析 '{url}' 失败: 所有名称服务器都未能应答 ({e})。")
    except Exception as e:
        logger.error(f"DNS 解析 '{url}' 时发生未知错误: {e}", exc_info=True)
        return False
    return False

# --- 节点验证函数 ---
def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def validate_node(protocol, url_components):
    # This validation is now less detailed, relying more on get_node_canonical_fingerprint
    # to catch malformed URLs by returning None.
    # We just do basic structural checks here.
    
    if protocol in ["ss", "ssr", "vmess", "vless", "trojan", "hysteria2"]:
        # Simply check if the basic URL parsing worked and scheme matches
        return url_components.scheme == protocol
    return False

# 2. 新增节点规范化函数 get_node_canonical_fingerprint
def get_node_canonical_fingerprint(node_url: str) -> str | None:
    """
    接收一个原始节点 URL，然后根据协议类型进行解析和规范化以生成唯一的指纹。

    规范化规则：
    - 忽略备注：统一移除 # 及其后的备注信息。
    - SS 节点：解码 method_password 部分，并清理其中的潜在杂质（如 Cg== 导致的换行符）。
    - VLESS/Trojan/Hysteria2 节点：解析 URL 中的查询参数，并对它们进行排序。
    - SSR 节点：解码其 base64 数据并提取核心连接参数作为指纹。
    - VMess 节点：解码其 base64 编码的 JSON 数据，并提取 add、port、id 等关键字段
      以及排序后的关键可选参数（如 net, type, security, path 等）作为指纹。
    - 如果节点无法被有效规范化（例如格式错误），该函数将返回 None。
    """
    
    # 统一移除 # 及其后的备注信息
    base_url_no_remark = node_url.split('#', 1)[0]

    try:
        parsed_url = urlparse(base_url_no_remark)
        scheme = parsed_url.scheme

        if not scheme:
            return None # Must have a scheme

        if scheme == "ss":
            # Format: ss://base64_encoded_method_password@server:port
            if not parsed_url.netloc:
                return None
            
            # netloc is method_password_encoded@server:port
            auth_and_host = parsed_url.netloc
            
            if '@' not in auth_and_host:
                return None # Invalid SS format without @

            method_password_encoded, server_port = auth_and_host.split('@', 1)
            
            # Decode method_password part
            try:
                # Add padding if necessary for base64 decoding
                padded_method_password_encoded = method_password_encoded + '=' * (4 - len(method_password_encoded) % 4)
                decoded_method_password = base64.b64decode(padded_method_password_encoded).decode('utf-8', errors='ignore').strip()
            except Exception:
                return None # Malformed base64
            
            # Clean potential impurities like newlines from Cg==
            decoded_method_password = decoded_method_password.replace('\n', '').replace('\r', '')

            # Reconstruct for fingerprint
            return f"ss://{decoded_method_password}@{server_port}"

        elif scheme == "ssr":
            # Format: ssr://base64_encoded_params
            encoded_params = base_url_no_remark[len("ssr://"):]
            try:
                padded_encoded_params = encoded_params + '=' * (4 - len(encoded_params) % 4)
                decoded_params = base64.b64decode(padded_encoded_params).decode('utf-8', errors='ignore')
            except Exception:
                return None # Malformed base64

            # SSR parameters are usually like server:port:protocol:method:obfs:password_base64/?params...
            # Extract core connection parameters as fingerprint.
            # We split by /? to ignore optional query parameters and remarks in the SSR payload itself.
            core_params_part = decoded_params.split("/?")[0]
            
            # Further clean up password if it has base64 padding
            parts = core_params_part.split(':')
            if len(parts) >= 6:
                # The 6th part is usually the base64 encoded password
                try:
                    password_encoded = parts[5]
                    # Ensure it's padded correctly before decoding
                    padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4)
                    decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                    parts[5] = decoded_password.strip() # Remove padding and extra chars
                except Exception:
                    pass # Leave as is if decoding fails, for robustness

            # Reconstruct the core part
            return f"ssr://{':'.join(parts)}"

        elif scheme == "vmess":
            # Format: vmess://base64_encoded_json
            encoded_json = base_url_no_remark[len("vmess://"):]
            try:
                padded_encoded_json = encoded_json + '=' * (4 - len(encoded_json) % 4)
                decoded_json = base64.b64decode(padded_encoded_json).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded_json)
            except Exception:
                return None # Malformed base64 or JSON

            # Extract essential fields
            fingerprint_data = {
                "add": vmess_config.get("add"),
                "port": vmess_config.get("port"),
                "id": vmess_config.get("id"),
            }

            # Sort key optional parameters for consistent fingerprint
            # Common optional parameters in VMess config
            optional_keys = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]
            optional_params = {}
            for key in optional_keys:
                if key in vmess_config and vmess_config[key] is not None:
                    optional_params[key] = vmess_config[key]
            
            # Sort optional parameters by key for consistent representation
            sorted_optional_params = sorted(optional_params.items())
            
            # Convert to a tuple for hashing and consistency if put into a larger structure
            # For JSON dump, we just ensure original dict is built with sorted items.
            for k, v in sorted_optional_params:
                fingerprint_data[k] = v
            
            # Use JSON dump with sorted keys to create a consistent string representation
            return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"

        elif scheme in ["vless", "trojan", "hysteria2"]:
            # These protocols typically follow a standard URL structure with query parameters.
            # Reconstruct the URL without fragment (remarks) but with sorted query parameters.
            
            # Components to keep: scheme, netloc (userinfo@host:port), path, and sorted query.
            # We discard fragment and params as they are not typically for core deduplication.
            
            # parsed_url.query gives 'key1=val1&key2=val2'
            query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Convert to a list of (key, value) tuples and sort by key
            sorted_query_params = []
            for key in sorted(query_params_list.keys()):
                for value in query_params_list[key]: # parse_qs returns lists of values
                    sorted_query_params.append((key, value))
            
            # Re-encode sorted query parameters
            sorted_query_string = urlencode(sorted_query_params)
            
            # Reconstruct the URL, including userinfo, host, port, path, and sorted query
            # parsed_url.path might contain some parameters for VLESS, e.g., /?ed=2048
            # So, we should keep it.
            
            # Building a canonical URL for fingerprinting.
            # The netloc usually contains userinfo, host, and port.
            # For VLESS, userinfo is UUID. For Trojan, it's password. For Hysteria2, it's ID:Password.
            canonical_url_parts = [scheme, "://", parsed_url.netloc]
            
            if parsed_url.path:
                canonical_url_parts.append(parsed_url.path)
            
            if sorted_query_string:
                # If path contains query-like string, we must handle it.
                # However, parsed_url.query should already separate true query from path.
                # So, we just append '?' and sorted_query_string.
                canonical_url_parts.append("?")
                canonical_url_parts.append(sorted_query_string)
            
            return "".join(canonical_url_parts)
            
        else:
            return None # Unsupported protocol

    except Exception as e:
        logger.debug(f"规范化节点 '{node_url}' 失败: {e}", exc_info=True)
        return None

# --- 节点解析与提取函数 ---
def extract_nodes_from_text(text_content):
    extracted_nodes = set() 

    for protocol, regex_pattern in NODE_REGEXES.items():
        # Use re.finditer to get all matches
        for match in re.finditer(regex_pattern, text_content):
            node_url = match.group(0) # Get the full matched URL string
            try:
                # Perform a basic parse to validate the scheme before deeper validation
                parsed_node = urlparse(node_url)
                if parsed_node.scheme == protocol: # Ensure the matched scheme is correct
                    extracted_nodes.add(node_url)
            except Exception as e:
                logger.debug(f"URL解析失败 for {node_url}: {e}")

    # Try parsing Base64 encoded content
    try:
        # This regex looks for base64-like blocks. It's broad.
        # It needs to be careful not to match too many random strings.
        # Adding a minimum length can help.
        base64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text_content)
        for b64_block in base64_matches:
            if len(b64_block) > 16 and len(b64_block) % 4 == 0: # Minimum length to avoid false positives
                try:
                    decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                    extracted_nodes.update(extract_nodes_from_text(decoded_content)) # Recursive call
                except Exception as e:
                    logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...")
    except Exception as e:
        logger.debug(f"处理 Base64 块时发生错误: {e}")

    # Try parsing YAML and JSON content
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

    return extracted_nodes 

def parse_and_extract_nodes(content):
    nodes_from_html = set()
    soup = BeautifulSoup(content, 'html.parser')
    
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            if text_content:
                nodes_from_html.update(extract_nodes_from_text(text_content))

    if not nodes_from_html:
        body_text = soup.get_text()
        nodes_from_html.update(extract_nodes_from_text(body_text))

    return nodes_from_html 

# process_url 函数不再直接修改 global_unique_nodes，而是返回它收集到的节点
async def process_url(url, http_client, playwright_instance: Playwright, processed_urls, all_nodes_count):
    if url in processed_urls:
        logger.debug(f"URL '{url}' 已经处理过，跳过。")
        return set() # Return an empty set, as no new nodes will be processed from this URL

    processed_urls.add(url)
    logger.info(f"正在处理 URL: {url}")
    
    content = await fetch_url(url, http_client, playwright_instance)
    if not content:
        logger.error(f"未能获取 {url} 的内容，跳过节点提取。")
        return set()

    nodes_from_current_url_content = parse_and_extract_nodes(content)
    collected_nodes_for_this_url_tree = set(nodes_from_current_url_content)

    soup = BeautifulSoup(content, 'html.parser')
    found_links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        parsed_href = urlparse(href)
        if parsed_href.netloc:
            # Check if link is a potential subscription or related to the same domain
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
            # 递归调用 process_url，并将返回的节点添加到当前 URL 的节点集合中
            recursive_nodes_from_child = await process_url(link_to_process, http_client, playwright_instance, processed_urls, all_nodes_count)
            collected_nodes_for_this_url_tree.update(recursive_nodes_from_child)

    nodes_count = len(collected_nodes_for_this_url_tree) 
    logger.info(f"从 {url} (及其子链接) 提取了 {nodes_count} 个有效节点。")
    all_nodes_count[url] = nodes_count

    domain_name = get_short_url_name(url)
    if domain_name:
        if nodes_count > 0:
            output_file = os.path.join(OUTPUT_DIR, f"{domain_name}.txt")
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
                for node in collected_nodes_for_this_url_tree: 
                    await f.write(node + '\n')
            logger.info(f"从 {url} 获取的 {nodes_count} 个节点已保存到 {output_file}。")
        else:
            logger.info(f"从 {url} 未提取到节点，跳过保存文件。")
    else:
        logger.warning(f"无法为 URL '{url}' 生成有效的文件名，节点未单独保存。")
        
    return collected_nodes_for_this_url_tree # Return the unique nodes collected from this URL's tree

def get_short_url_name(url):
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
        logger.error(f"处理 URL 名称时发生错误 {url}: {e}", exc_info=True)
        return None

async def main():
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

    valid_urls_after_dns = []
    logger.info("--- 开始 DNS 解析预检查 ---")
    dns_check_tasks = [check_dns_resolution(url) for url in raw_urls]
    dns_results = await asyncio.gather(*dns_check_tasks)

    for i, url in enumerate(raw_urls):
        if dns_results[i]:
            valid_urls_after_dns.append(url)
        else:
            logger.info(f"URL '{url}' DNS 解析失败，已跳过。")
            
    logger.info(f"--- DNS 解析预检查完成。成功解析 {len(valid_urls_after_dns)} 个 URL ---")

    if not valid_urls_after_dns:
        logger.warning("没有可用的有效 URL 进行抓取，程序退出。")
        return

    processed_urls = set()
    all_nodes_count = {} 
    # 使用字典进行全局去重，键是节点核心部分，值是完整的节点字符串
    global_unique_nodes_map = {} 

    async with async_playwright() as p:
        async with httpx.AsyncClient(http2=True, follow_redirects=True) as http_client:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def bounded_process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count, global_unique_nodes_map_ref, semaphore):
                async with semaphore:
                    # process_url 返回从当前 URL 及其子链接收集到的节点
                    nodes_from_tree = await process_url(url, http_client, playwright_instance, processed_urls, all_nodes_count)
                    
                    # 将这些节点添加到全局唯一节点字典中进行去重
                    for node in nodes_from_tree:
                        # 3. 修改全局去重逻辑，调用 get_node_canonical_fingerprint
                        canonical_fingerprint = get_node_canonical_fingerprint(node)
                        if canonical_fingerprint is not None:
                            if canonical_fingerprint not in global_unique_nodes_map_ref:
                                global_unique_nodes_map_ref[canonical_fingerprint] = node # 保留第一个遇到的完整节点字符串
                        else:
                            logger.debug(f"节点 '{node}' 无法生成规范化指纹，跳过去重。")
                    return nodes_from_tree

            tasks = [bounded_process_url(url, http_client, p, processed_urls, all_nodes_count, global_unique_nodes_map, semaphore) for url in valid_urls_after_dns]
            
            logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个 URL 的抓取任务，最大并发数：{MAX_CONCURRENT_REQUESTS}")
            await asyncio.gather(*tasks)

    # --- 保存全局唯一节点列表 ---
    all_unique_nodes_file = os.path.join(OUTPUT_DIR, "all_unique_nodes.txt")
    if global_unique_nodes_map: # 现在使用字典检查是否有唯一节点
        async with aiofiles.open(all_unique_nodes_file, 'w', encoding='utf-8') as f:
            # 遍历字典的值（即完整的唯一节点字符串），并排序写入文件
            for node in sorted(global_unique_nodes_map.values()): 
                await f.write(node + '\n')
        logger.info(f"所有 {len(global_unique_nodes_map)} 个唯一节点已保存到 {all_unique_nodes_file}。")
    else:
        logger.info("未找到任何唯一节点，跳过保存 all_unique_nodes.txt 文件。")

    # --- 保存节点数量统计 ---
    csv_file_path = os.path.join(OUTPUT_DIR, "nodes_summary.csv")
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for url, count in all_nodes_count.items():
            writer.writerow({'URL': url, '节点数量': count})
    logger.info(f"节点数量统计已保存到 {csv_file_path}。")
    logger.info("--- 脚本运行结束 ---")

if __name__ == "__main__":
    asyncio.run(main())
