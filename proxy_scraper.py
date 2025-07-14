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
import dns.resolver # For aiodns, although aiodns is not directly used for resolution, dns.resolver is part of dnspython.
import platform
import random
import datetime
import aiofiles 

# 配置常量
OUTPUT_DIR = "data"
CACHE_DIR = "cache"
CACHE_EXPIRATION_HOURS = 24 # 缓存过期时间

# 请求头配置，包含不同设备类型
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

# 代理协议正则表达式，包含捕获组以便后续提取
NODE_REGEXES = {
    "hysteria2": r"hysteria2:\/\/(?P<id>[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?(?P<host>[a-zA-Z0-9\-\.]+)(?::(?P<port>\d+))?\/?\?.*",
    "vmess": r"vmess:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "trojan": r"trojan:\/\/(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:\/\?.*)?",
    "ss": r"ss:\/\/(?P<method_password>[a-zA-Z0-9+\/=]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:#(?P<name>.*))?",
    "ssr": r"ssr:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "vless": r"vless:\/\/(?P<uuid>[a-zA-Z0-9\-]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?type=(?P<type>[a-zA-Z0-9]+)(?:&security=(?P<security>[a-zA-Z0-9]+))?.*",
}

def generate_cache_key(url):
    """根据URL生成缓存文件名"""
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    """获取缓存文件的完整路径"""
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
    """读取缓存，如果过期则返回None"""
    cache_path = get_cache_path(url)
    if not os.path.exists(cache_path):
        return None
    
    # 检查缓存文件修改时间
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path))
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        print(f"缓存 '{url}' 已过期。")
        os.remove(cache_path) # 删除过期缓存
        return None
    
    async with asyncio.Lock(): # 使用锁确保文件操作安全
        async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
            print(f"从缓存读取 '{url}'。")
            return await f.read()

async def write_cache(url, content):
    """写入内容到缓存"""
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True)
    async with asyncio.Lock(): # 使用锁确保文件操作安全
        async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
            await f.write(content)
    print(f"内容已写入缓存 '{url}'。")

def get_random_headers():
    """随机获取一个请求头"""
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

async def fetch_url(url, client):
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    同时支持递归抓取内嵌链接。
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
        print(f"尝试从 {full_url_http} 获取内容...")
        response = await client.get(full_url_http, timeout=10, headers=headers)
        response.raise_for_status() # 抛出 HTTPError 异常
        content = response.text
    except httpx.HTTPStatusError as e:
        print(f"从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code})。尝试 HTTPS...")
    except httpx.RequestError as e:
        print(f"从 {full_url_http} 获取失败 (请求错误: {e})。尝试 HTTPS...")

    if content is None:
        try:
            headers = get_random_headers()
            print(f"尝试从 {full_url_https} 获取内容...")
            response = await client.get(full_url_https, timeout=10, headers=headers)
            response.raise_for_status() # 抛出 HTTPError 异常
            content = response.text
        except httpx.HTTPStatusError as e:
            print(f"从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code})。")
        except httpx.RequestError as e:
            print(f"从 {full_url_https} 获取失败 (请求错误: {e})。")
    
    if content:
        await write_cache(url, content) # 写入内容到缓存
    return content

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
    此函数需要根据具体的协议规范进行详细实现。
    这里仅提供简化示例，实际应更严格。
    """
    if protocol == "hysteria2":
        # Hysteria2 至少需要host和port
        if not all(k in data for k in ['host', 'port']):
            return False
        if not data['host'] or not data['port'] or not data['port'].isdigit():
            return False
        # 进一步可以检查 host 是否是有效的域名或 IP，port是否在合理范围
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])):
            return False
        if not (1 <= int(data['port']) <= 65535):
            return False
        return True
    elif protocol == "vmess":
        # 对于 vmess，需要能够成功解码 base64 且是有效的 JSON
        try:
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8')
            json_data = json.loads(decoded)
            # 检查 vmess 节点必要字段，例如 'add', 'port', 'id'
            if not all(k in json_data for k in ['add', 'port', 'id']):
                return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']:
                return False
            # 进一步检查地址、端口、UUID格式
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])):
                return False
            if not isinstance(json_data['port'], int) or not (1 <= json_data['port'] <= 65535):
                return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id']):
                return False
            return True
        except (base64.binascii.Error, json.JSONDecodeError):
            return False
    elif protocol == "trojan":
        # Trojan 至少需要 password, host, port
        if not all(k in data for k in ['password', 'host', 'port']):
            return False
        if not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit():
            return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])):
            return False
        if not (1 <= int(data['port']) <= 65535):
            return False
        return True
    elif protocol == "ss":
        # SS 至少需要 method_password, host, port
        if not all(k in data for k in ['method_password', 'host', 'port']):
            return False
        if not data['method_password'] or not data['host'] or not data['port'] or not data['port'].isdigit():
            return False
        # method_password 部分需要 base64 解码后检查
        try:
            decoded_mp = base64.b64decode(data['method_password']).decode('utf-8')
            # 简单的检查，确保包含冒号分隔的加密方法和密码
            if ':' not in decoded_mp:
                return False
        except base64.binascii.Error:
            return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])):
            return False
        if not (1 <= int(data['port']) <= 65535):
            return False
        return True
    elif protocol == "ssr":
        # SSR 需要能够成功解码 base64
        try:
            decoded = base64.b64decode(data.get('data', '')).decode('utf-8')
            # SSR 格式通常是 host:port:protocol:method:obfs:password_base64/?params
            parts = decoded.split(':')
            if len(parts) < 6: # 至少需要六个部分
                return False
            # 简单检查 host, port
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])):
                return False
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535):
                return False
            return True
        except (base64.binascii.Error, IndexError):
            return False
    elif protocol == "vless":
        # VLESS 至少需要 uuid, host, port, type
        if not all(k in data for k in ['uuid', 'host', 'port', 'type']):
            return False
        if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']:
            return False
        # 进一步检查 uuid, host, port, type 格式
        if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']):
            return False
        if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])):
            return False
        if not (1 <= int(data['port']) <= 65535):
            return False
        return True
    return False

def parse_and_extract_nodes(content):
    """
    解析网页内容，提取代理节点。
    优先处理 <pre>、<code>、<textarea> 等标签中的内容。
    也尝试解析 YAML、JSON、Base64 编码的节点。
    """
    nodes = set() # 使用集合避免重复
    
    # 尝试解析 HTML 内容
    soup = BeautifulSoup(content, 'html.parser')
    
    # 优先处理特定标签中的内容
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            if text_content:
                nodes.update(extract_nodes_from_text(text_content))

    # 如果特定标签中没有找到，或者需要从非结构化文本中提取，则处理整个页面的文本
    if not nodes: # 如果特定标签中没有找到节点
        body_text = soup.get_text()
        nodes.update(extract_nodes_from_text(body_text))

    return list(nodes)

def extract_nodes_from_text(text_content):
    """从纯文本中提取代理节点"""
    extracted_nodes = set()

    # 尝试直接匹配各种协议
    for protocol, regex_pattern in NODE_REGEXES.items():
        for match in re.finditer(regex_pattern, text_content):
            # 将匹配到的组转换为字典，方便传递给验证函数
            matched_data = match.groupdict()
            if validate_node(protocol, matched_data):
                node_string = match.group(0)
                # 只保留原节点名称前5位（如果节点有名称的话），多余的全部删除。
                # 由于节点格式多样，这里简化处理，如果节点字符串过长，截取一部分作为标识。
                # 实际的“节点名称”可能在协议内部的某个字段（如 vmess 的 ps 字段），
                # 这里我们直接截取整个节点字符串的前缀作为其在列表中的标识。
                if '#': # 如果有名称字段，尝试处理
                    parts = node_string.split('#')
                    if len(parts) > 1:
                        name = parts[-1]
                        if len(name) > 5:
                            name = name[:5]
                        node_string = '#'.join(parts[:-1]) + '#' + name
                
                # 去除明显不是节点的内容或者是节点不全的内容 - 由 validate_node 处理
                extracted_nodes.add(node_string)

    # 尝试解析 Base64 编码的内容
    try:
        # 寻找看起来像 Base64 的块，通常是多行且只包含 Base64 字符
        base64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text_content)
        for b64_block in base64_matches:
            if len(b64_block) > 16 and len(b64_block) % 4 == 0: # 长度检查，防止误判
                try:
                    decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                    # 递归调用自身处理解码后的内容
                    extracted_nodes.update(extract_nodes_from_text(decoded_content))
                except Exception:
                    pass # 非有效的 Base64
    except Exception:
        pass # 捕捉其他可能的解码错误

    # 尝试解析 YAML 和 JSON
    try:
        # 尝试将整个文本作为 YAML 解析
        yaml_content = yaml.safe_load(text_content)
        if isinstance(yaml_content, (dict, list)):
            # 如果是字典或列表，遍历并提取字符串中的节点
            if isinstance(yaml_content, dict):
                for key, value in yaml_content.items():
                    if isinstance(value, str):
                        extracted_nodes.update(extract_nodes_from_text(value))
                    elif isinstance(value, (dict, list)): # 递归处理嵌套结构
                        extracted_nodes.update(extract_nodes_from_text(json.dumps(value))) # 转换为JSON字符串再处理
            elif isinstance(yaml_content, list):
                for item in yaml_content:
                    if isinstance(item, str):
                        extracted_nodes.update(extract_nodes_from_text(item))
                    elif isinstance(item, (dict, list)):
                        extracted_nodes.update(extract_nodes_from_text(json.dumps(item)))
    except yaml.YAMLError:
        pass # 不是有效的 YAML
    
    try:
        # 尝试将整个文本作为 JSON 解析
        json_content = json.loads(text_content)
        if isinstance(json_content, (dict, list)):
            # 如果是字典或列表，遍历并提取字符串中的节点
            if isinstance(json_content, dict):
                for key, value in json_content.items():
                    if isinstance(value, str):
                        extracted_nodes.update(extract_nodes_from_text(value))
                    elif isinstance(value, (dict, list)): # 递归处理嵌套结构
                        extracted_nodes.update(extract_nodes_from_text(json.dumps(value)))
            elif isinstance(json_content, list):
                for item in json_content:
                    if isinstance(item, str):
                        extracted_nodes.update(extract_nodes_from_text(item))
                    elif isinstance(item, (dict, list)):
                        extracted_nodes.update(extract_nodes_from_text(json.dumps(item)))
    except json.JSONDecodeError:
        pass # 不是有效的 JSON

    return list(extracted_nodes)

async def process_url(url, client, processed_urls, all_nodes_count):
    """
    处理单个 URL，抓取内容，提取节点，并递归处理发现的子链接。
    """
    if url in processed_urls:
        return []

    processed_urls.add(url)
    print(f"正在处理 URL: {url}")
    
    content = await fetch_url(url, client)
    if not content:
        print(f"未能获取 {url} 的内容。")
        return []

    extracted_nodes = parse_and_extract_nodes(content)
    
    # 递归查找并处理内嵌链接
    soup = BeautifulSoup(content, 'html.parser')
    found_links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # 尝试从 href 中提取域名
        parsed_href = urlparse(href)
        if parsed_href.netloc: # 如果有网络位置（域名）
            # 过滤掉外部链接，只处理与当前 URL 相似的域名，或者明显是代理订阅链接
            # 这里简单判断，如果包含 "subscribe" 或 "config" 等关键字，可以考虑
            if "subscribe" in href or "config" in href or "proxy" in href or parsed_href.netloc == urlparse(f"http://{url}").netloc:
                # 提取裸域名
                domain_match = re.match(r"(?:https?://)?(?:www\.)?([^/]+)", parsed_href.netloc)
                if domain_match:
                    found_links.add(domain_match.group(1)) # 添加裸域名
        elif href.startswith('/') and len(href) > 1: # 相对路径
            base_domain = urlparse(f"http://{url}").netloc
            if base_domain:
                found_links.add(base_domain) # 保持在当前域名下
            
    for link_to_process in found_links:
        if link_to_process not in processed_urls:
            print(f"发现新链接，准备递归处理: {link_to_process}")
            recursive_nodes = await process_url(link_to_process, client, processed_urls, all_nodes_count)
            extracted_nodes.extend(recursive_nodes) # 将递归获取的节点也添加到当前列表

    # 统计节点数量
    nodes_count = len(extracted_nodes)
    print(f"从 {url} 提取了 {nodes_count} 个有效节点。")
    all_nodes_count[url] = nodes_count

    # 将每个 URL 获取到的节点单独保存
    domain_name = get_short_url_name(url)
    if domain_name:
        output_file = os.path.join(OUTPUT_DIR, f"{domain_name}.txt")
        async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
            for node in extracted_nodes:
                await f.write(node + '\n')
        print(f"从 {url} 获取的 {nodes_count} 个节点已保存到 {output_file}。")
    
    return extracted_nodes

def get_short_url_name(url):
    """
    根据原始 URL 获取一个简短的、不带 http/https 和后缀的域名作为文件名。
    例如：a5.dyxli21.ddns-ip.net -> dyxli21
    www.jingrunyuan.com -> jingrunyuan
    """
    try:
        # 如果 URL 缺少 scheme，urlparse 会将整个当作 path，导致 netloc 为空。
        # 因此，先手动添加一个scheme。
        if not urlparse(url).scheme:
            url_with_scheme = f"http://{url}"
        else:
            url_with_scheme = url
            
        parsed_url = urlparse(url_with_scheme)
        domain = parsed_url.netloc or parsed_url.path # 如果是裸域名，netloc可能为空，则使用path
        
        # 移除 www.
        domain = domain.replace('www.', '')
        
        # 移除顶级域名后缀，例如 .com, .net, .org, .co.jp 等
        # 这是一个简单的正则匹配，可能无法覆盖所有复杂情况
        # 更严谨的方案需要一个公共后缀列表 (Public Suffix List)
        domain = re.sub(r'\.(com|net|org|xyz|top|info|io|cn|jp|ru|uk|de|fr|me|tv|cc|pw|win|online|site|space|fun|club|link|shop|icu|vip|bid|red|rocks|gdn|click|fans|live|loan|mom|monster|pics|press|pro|rest|review|rocks|run|sbs|store|tech|website|wiki|work|world|zone)(?:\.[a-z]{2,3})?$', '', domain, flags=re.IGNORECASE)
        
        # 移除 IP 地址的后缀
        if is_valid_ip(domain):
            return domain.replace('.', '_') # IP地址用下划线代替点

        # 进一步处理，只保留中间的域名部分
        parts = domain.split('.')
        if len(parts) > 1:
            # 尽可能取倒数第二部分，避免一些ddns的复杂情况
            return parts[-2] if len(parts) >= 2 else parts[0]
        else:
            return parts[0]
    except Exception as e:
        print(f"处理 URL 名称时发生错误 {url}: {e}")
        return None


async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True) # 创建缓存目录
    
    urls_to_scrape = []
    try:
        with open("sources.list", 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    urls_to_scrape.append(url)
    except FileNotFoundError:
        print("错误: sources.list 文件未找到。请确保它存在于根目录。")
        return

    processed_urls = set()
    all_nodes_count = {} # 存储每个URL获取到的节点数量

    # 使用 httpx.AsyncClient 管理会话，支持 HTTP/2
    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        tasks = [process_url(url, client, processed_urls, all_nodes_count) for url in urls_to_scrape]
        await asyncio.gather(*tasks)

    # 将节点数量统计保存为 CSV 文件
    csv_file_path = os.path.join(OUTPUT_DIR, "nodes_summary.csv")
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for url, count in all_nodes_count.items():
            writer.writerow({'URL': url, '节点数量': count})
    print(f"节点数量统计已保存到 {csv_file_path}。")

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
