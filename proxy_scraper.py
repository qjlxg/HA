import httpx
import asyncio
import re
import os
import csv
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import yaml
import base64
import json
import ipaddress
import dns.resolver  # 用于 DNS 解析
import platform
import random
import datetime
import aiofiles  # 异步文件操作库
import logging   # 日志模块

# --- 配置常量 ---
OUTPUT_DIR = "data"  # 结果输出目录
CACHE_DIR = "cache"    # 缓存目录
CACHE_EXPIRATION_HOURS = 24 # 缓存过期时间（小时）
MAX_CONCURRENT_REQUESTS = 20  # 定义最大并发请求数，可以根据需要调整

# 配置日志
# 创建一个名为 'proxy_scraper' 的日志器
logger = logging.getLogger('proxy_scraper')
logger.setLevel(logging.INFO) # 设置日志级别为 INFO，可以根据需要改为 DEBUG
# 创建一个控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
# 创建一个文件处理器，日志将写入 proxy_scraper.log 文件
file_handler = logging.FileHandler('proxy_scraper.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
# 定义日志输出格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
# 将处理器添加到日志器
logger.addHandler(console_handler)
logger.addHandler(file_handler)


# 请求头配置，包含不同设备类型，用于模拟浏览器访问
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
        "Mozilla/5.0 (Linux; Android 12; SM-T510) AppleWebKit=537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "harmonyos": [
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; PCT-AL10) AppleWebKit/537.36 (KHTML like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36",
    ]
}

# 代理协议正则表达式，包含捕获组以便后续提取不同协议的参数
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
    """根据 URL 生成缓存文件名（使用 MD5 哈希确保唯一性和文件名合法性）"""
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    """获取缓存文件的完整路径"""
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
    """读取缓存，如果文件不存在或已过期则返回 None"""
    cache_path = get_cache_path(url)
    if not os.path.exists(cache_path):
        logger.debug(f"缓存文件不存在: {cache_path}")
        return None
    
    # 检查缓存文件修改时间，判断是否过期
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path))
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        logger.info(f"缓存 '{url}' 已过期。")
        os.remove(cache_path) # 删除过期缓存
        return None
    
    # 使用 asyncio.Lock 确保文件操作安全，防止并发读取写入冲突
    async with asyncio.Lock():
        async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
            logger.info(f"从缓存读取 '{url}'。")
            return await f.read()

async def write_cache(url, content):
    """写入内容到缓存文件"""
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True) # 确保缓存目录存在
    async with asyncio.Lock(): # 使用锁确保文件操作安全
        async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
            await f.write(content)
    logger.info(f"内容已写入缓存 '{url}'。")

# --- 网络请求相关函数 ---
def get_random_headers():
    """随机获取一个请求头，模拟不同设备"""
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

async def fetch_url(url, client):
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    请求超时设置为 30 秒，以应对响应较慢的网站。
    """
    full_url_http = f"http://{url}"
    full_url_https = f"https://{url}"
    
    # 首先尝试从缓存读取
    cached_content = await read_cache(url)
    if cached_content:
        return cached_content
        
    content = None
    try:
        headers = get_random_headers()
        logger.info(f"尝试从 {full_url_http} 获取内容...")
        response = await client.get(full_url_http, timeout=30, headers=headers)
        response.raise_for_status() # 如果状态码表示错误（如 4xx, 5xx），则抛出异常
        content = response.text
    except httpx.HTTPStatusError as e:
        logger.warning(f"从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code})。尝试 HTTPS。URL: {url}")
    except httpx.RequestError as e:
        # 捕获更具体的请求错误，如连接超时、DNS错误等
        logger.warning(f"从 {full_url_http} 获取失败 (请求错误: {e})。尝试 HTTPS。URL: {url}")
    except Exception as e:
        logger.error(f"从 {full_url_http} 获取时发生未知错误: {e}。URL: {url}", exc_info=True) # Added exc_info=True for full traceback


    if content is None: # 如果 HTTP 尝试失败，则尝试 HTTPS
        try:
            headers = get_random_headers()
            logger.info(f"尝试从 {full_url_https} 获取内容...")
            response = await client.get(full_url_https, timeout=30, headers=headers)
            response.raise_for_status() # 如果状态码表示错误，则抛出异常
            content = response.text
        except httpx.HTTPStatusError as e:
            logger.warning(f"从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code})。URL: {url}")
        except httpx.RequestError as e:
            # 捕获更具体的请求错误，如SSL证书问题等
            logger.warning(f"从 {full_url_https} 获取失败 (请求错误: {e})。URL: {url}")
        except Exception as e:
            logger.error(f"从 {full_url_https} 获取时发生未知错误: {e}。URL: {url}", exc_info=True) # Added exc_info=True
    
    if content:
        await write_cache(url, content) # 成功获取内容后写入缓存
    else:
        logger.error(f"未能获取 {url} 的内容，跳过。")
    return content

# --- DNS 解析函数 ---
async def check_dns_resolution(url):
    """
    检查给定 URL 的域名是否可以解析到有效的 IP 地址。
    """
    try:
        # 尝试解析域名
        answers = await asyncio.to_thread(dns.resolver.resolve, url, 'A') # 解析 IPv4 地址
        if answers:
            # 也可以解析 IPv6 地址，根据需要
            # answers_aaaa = await asyncio.to_thread(dns.resolver.resolve, url, 'AAAA')
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
    except dns.resolver.NoNameservers as e: # 捕获 NoNameservers 错误，表示所有名称服务器都无法应答
        logger.warning(f"DNS 解析 '{url}' 失败: 所有名称服务器都未能应答 ({e})。")
        return False
    except Exception as e:
        logger.error(f"DNS 解析 '{url}' 时发生未知错误: {e}", exc_info=True) # Added exc_info=True
        return False

# --- 节点验证函数 ---
def is_valid_ip(address):
    """检查字符串是否是有效的 IPv4 或 IPv6 地址"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def validate_node(protocol, data):
    """
    根据协议验证节点信息的完整性和合法性。
    只有完全符合已知代理协议格式且信息完整的节点才会被保留，其他所有不符合或信息不全的节点都将被直接丢弃。
    """
    # 记录详细的验证过程，方便调试
    logger.debug(f"正在验证 {protocol} 节点数据: {data}")

    if protocol == "hysteria2":
        if not all(k in data for k in ['host', 'port']): return False
        if not data['host'] or not data['port'] or not data['port'].isdigit(): return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
        if not (1 <= int(data['port']) <= 65535): return False
        return True
    elif protocol == "vmess":
        try:
            # 使用 errors='ignore' 忽略无效的 UTF-8 字节
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8', errors='ignore')
            json_data = json.loads(decoded)
            if not all(k in json_data for k in ['add', 'port', 'id']): return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False
            if not isinstance(json_data['port'], int) or not (1 <= json_data['port'] <= 65535): return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id']): return False
            return True
        except (base64.binascii.Error, json.JSONDecodeError) as e:
            logger.debug(f"VMess 解码或 JSON 解析失败: {e}")
            return False
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
            # 使用 errors='ignore' 忽略无效的 UTF-8 字节
            decoded_mp = base64.b64decode(data['method_password']).decode('utf-8', errors='ignore')
            if ':' not in decoded_mp: return False
        except base64.binascii.Error as e:
            logger.debug(f"SS method_password 解码失败: {e}")
            return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
        if not (1 <= int(data['port']) <= 65535): return False
        return True
    elif protocol == "ssr":
        try:
            # 使用 errors='ignore' 忽略无效的 UTF-8 字节
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8', errors='ignore')
            parts = decoded.split(':')
            if len(parts) < 6: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False
            return True
        except (base64.binascii.Error, IndexError) as e:
            logger.debug(f"SSR 解码或格式错误: {e}")
            return False
    elif protocol == "vless":
        if not all(k in data for k in ['uuid', 'host', 'port', 'type']): return False
        if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']: return False
        if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']): return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
        if not (1 <= int(data['port']) <= 65535): return False
        return True
    return False

# --- 节点解析与提取函数 ---
def parse_and_extract_nodes(content):
    """
    解析网页内容，提取代理节点。
    优先处理 <pre>、<code>、<textarea> 等可能包含节点内容的标签。
    也尝试解析 YAML、JSON、Base64 编码的节点。
    """
    nodes = set() # 使用集合避免重复，确保提取到的节点是唯一的
    
    # 尝试解析 HTML 内容
    soup = BeautifulSoup(content, 'html.parser')
    
    # 优先处理特定标签中的内容，这些标签常用于存放代码或纯文本，更容易找到节点
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            if text_content:
                nodes.update(extract_nodes_from_text(text_content))

    # 如果特定标签中没有找到节点，或者需要从非结构化文本中提取，则处理整个页面的文本
    if not nodes: # 如果特定标签中没有找到任何节点
        body_text = soup.get_text()
        nodes.update(extract_nodes_from_text(body_text))

    return list(nodes)

def extract_nodes_from_text(text_content):
    """从纯文本中提取代理节点（包括直接匹配、Base64解码、YAML和JSON解析）"""
    extracted_nodes = set()

    # 尝试直接匹配各种协议
    for protocol, regex_pattern in NODE_REGEXES.items():
        for match in re.finditer(regex_pattern, text_content):
            matched_data = match.groupdict()
            if validate_node(protocol, matched_data):
                node_string = match.group(0)
                # 对节点名称进行截断处理
                if '#' in node_string:
                    parts = node_string.split('#')
                    if len(parts) > 1:
                        name = parts[-1]
                        if len(name) > 5: # 如果名称超过5个字符则截断
                            name = name[:5]
                        node_string = '#'.join(parts[:-1]) + '#' + name
                extracted_nodes.add(node_string)

    # 尝试解析 Base64 编码的内容
    try:
        # 匹配看起来像 Base64 的字符串块
        base64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text_content)
        for b64_block in base64_matches:
            # 过滤掉过短或长度不符合Base64特征的块
            if len(b64_block) > 16 and len(b64_block) % 4 == 0:
                try:
                    # Crucial: 使用 errors='ignore' 来处理无效的 UTF-8 字节
                    decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                    # 递归处理解码后的内容
                    extracted_nodes.update(extract_nodes_from_text(decoded_content))
                except Exception as e:
                    logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...")
    except Exception as e:
        logger.debug(f"处理 Base64 块时发生错误: {e}")

    # 尝试解析 YAML 和 JSON 格式的内容
    try:
        yaml_content = yaml.safe_load(text_content)
        if isinstance(yaml_content, (dict, list)):
            if isinstance(yaml_content, dict):
                for key, value in yaml_content.items():
                    if isinstance(value, str): extracted_nodes.update(extract_nodes_from_text(value))
                    elif isinstance(value, (dict, list)): extracted_nodes.update(extract_nodes_from_text(json.dumps(value)))
            elif isinstance(yaml_content, list):
                for item in yaml_content:
                    if isinstance(item, str): extracted_nodes.update(extract_nodes_from_text(item))
                    elif isinstance(item, (dict, list)): extracted_nodes.update(extract_nodes_from_text(json.dumps(item)))
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}")
    
    try:
        json_content = json.loads(text_content)
        if isinstance(json_content, (dict, list)):
            if isinstance(json_content, dict):
                for key, value in json_content.items():
                    if isinstance(value, str): extracted_nodes.update(extract_nodes_from_text(value))
                    elif isinstance(value, (dict, list)): extracted_nodes.update(extract_nodes_from_text(json.dumps(value)))
            elif isinstance(json_content, list):
                for item in json_content:
                    if isinstance(item, str): extracted_nodes.update(extract_nodes_from_text(item))
                    elif isinstance(item, (dict, list)): extracted_nodes.update(extract_nodes_from_text(json.dumps(item)))
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}")

    return list(extracted_nodes)

async def process_url(url, client, processed_urls, all_nodes_count):
    """
    处理单个 URL，抓取内容，提取节点，并递归处理发现的子链接。
    此函数现在由信号量控制并发。
    """
    if url in processed_urls:
        logger.debug(f"URL '{url}' 已经处理过，跳过。")
        return []

    processed_urls.add(url) # 将当前 URL 加入已处理列表
    logger.info(f"正在处理 URL: {url}")
    
    content = await fetch_url(url, client) # 获取 URL 内容
    if not content:
        logger.error(f"未能获取 {url} 的内容，跳过节点提取。")
        return []

    extracted_nodes = parse_and_extract_nodes(content) # 从内容中提取节点
    
    # 递归查找并处理内嵌链接
    soup = BeautifulSoup(content, 'html.parser')
    found_links = set() # 存储发现的新链接
    for a_tag in soup.find_all('a', href=True): # 查找所有带有 href 属性的 <a> 标签
        href = a_tag['href']
        parsed_href = urlparse(href)
        # 检查是否是完整的URL且域名存在，且链接包含特定关键词或与当前域名相同
        if parsed_href.netloc: # 如果有网络位置（域名）
            if "subscribe" in href or "config" in href or "proxy" in href or parsed_href.netloc == urlparse(f"http://{url}").netloc:
                domain_match = re.match(r"(?:https?://)?(?:www\.)?([^/]+)", parsed_href.netloc)
                if domain_match:
                    found_links.add(domain_match.group(1)) # 只添加域名部分
        elif href.startswith('/') and len(href) > 1: # 如果是相对路径
            base_domain = urlparse(f"http://{url}").netloc
            if base_domain:
                found_links.add(base_domain) # 添加基础域名以便递归处理
            
    for link_to_process in found_links:
        if link_to_process not in processed_urls:
            logger.info(f"发现新链接，准备递归处理: {link_to_process}")
            recursive_nodes = await process_url(link_to_process, client, processed_urls, all_nodes_count)
            extracted_nodes.extend(recursive_nodes) # 合并递归获取的节点

    nodes_count = len(extracted_nodes)
    logger.info(f"从 {url} 提取了 {nodes_count} 个有效节点。")
    all_nodes_count[url] = nodes_count # 记录每个 URL 的节点数量

    # 将每个 URL 获取到的节点单独保存为文件
    domain_name = get_short_url_name(url) # 获取简短的域名作为文件名
    if domain_name:
        # --- 关键修改在这里：只有当有节点时才创建和写入文件 ---
        if nodes_count > 0: # 仅在提取到节点时执行文件写入
            output_file = os.path.join(OUTPUT_DIR, f"{domain_name}.txt")
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
                for node in extracted_nodes:
                    await f.write(node + '\n')
            logger.info(f"从 {url} 获取的 {nodes_count} 个节点已保存到 {output_file}。")
        else:
            logger.info(f"从 {url} 未提取到节点，跳过保存文件。") # 可以添加一条日志提示
    else:
        logger.warning(f"无法为 URL '{url}' 生成有效的文件名，节点未单独保存。")
    
    return extracted_nodes

def get_short_url_name(url):
    """
    根据原始 URL 获取一个简短的、不带 http/https 和后缀的域名作为文件名。
    例如：a5.dyxli21.ddns-ip.net -> dyxli21
    www.jingrunyuan.com -> jingrunyuan
    """
    try:
        if not urlparse(url).scheme:
            url_with_scheme = f"http://{url}"
        else:
            url_with_scheme = url
            
        parsed_url = urlparse(url_with_scheme)
        domain = parsed_url.netloc or parsed_url.path # 获取域名或路径作为基础
        
        domain = domain.replace('www.', '') # 移除 www.
        
        # 移除常见的顶级域名和二级域名后缀，保留主要部分
        domain = re.sub(r'\.(com|net|org|xyz|top|info|io|cn|jp|ru|uk|de|fr|me|tv|cc|pw|win|online|site|space|fun|club|link|shop|icu|vip|bid|red|rocks|gdn|click|fans|live|loan|mom|monster|pics|press|pro|rest|review|rocks|run|sbs|store|tech|website|wiki|work|world|zone)(?:\.[a-z]{2,3})?$', '', domain, flags=re.IGNORECASE)
        
        if is_valid_ip(domain): # 如果是IP地址，用下划线替换点
            return domain.replace('.', '_')

        parts = domain.split('.')
        # 尝试获取倒数第二部分作为主域名，例如 my.domain.com -> domain
        if len(parts) > 1:
            return parts[-2] if len(parts) >= 2 else parts[0]
        else:
            return parts[0] # 如果只有一部分，就用这一部分
    except Exception as e:
        logger.error(f"处理 URL 名称时发生错误 {url}: {e}", exc_info=True)
        return None

async def main():
    """主函数，负责读取 URL 列表，进行 DNS 预检查，并发处理，并保存结果"""
    os.makedirs(OUTPUT_DIR, exist_ok=True) # 创建输出目录
    os.makedirs(CACHE_DIR, exist_ok=True) # 创建缓存目录
    
    raw_urls = []
    try:
        with open("sources.list", 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url: # 确保行不为空
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

    processed_urls = set() # 记录已处理的 URL，防止重复和循环抓取
    all_nodes_count = {} # 存储每个 URL 获取到的节点数量

    # 使用 httpx.AsyncClient 管理会话，支持 HTTP/2，自动处理重定向
    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        # 创建一个信号量，限制最大并发请求数，避免资源耗尽导致任务取消
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS) 
        
        # 封装 process_url 函数，使其受信号量控制
        async def bounded_process_url(url, client, processed_urls, all_nodes_count, semaphore):
            async with semaphore: # 协程进入此上下文时会尝试获取信号量，如果信号量计数为0则等待
                return await process_url(url, client, processed_urls, all_nodes_count)

        # 为通过 DNS 解析的 URL 创建一个受信号量控制的任务
        tasks = [bounded_process_url(url, client, processed_urls, all_nodes_count, semaphore) for url in valid_urls_after_dns]
        
        logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个 URL 的抓取任务，最大并发数：{MAX_CONCURRENT_REQUESTS}")
        await asyncio.gather(*tasks) # 并发运行所有任务

    # 将节点数量统计保存为 CSV 文件
    csv_file_path = os.path.join(OUTPUT_DIR, "nodes_summary.csv")
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量'] # CSV 表头
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader() # 写入表头
        for url, count in all_nodes_count.items():
            writer.writerow({'URL': url, '节点数量': count}) # 写入数据行
    logger.info(f"节点数量统计已保存到 {csv_file_path}。")
    logger.info("--- 脚本运行结束 ---")

if __name__ == "__main__":

    asyncio.run(main()) # 运行主异步函数
