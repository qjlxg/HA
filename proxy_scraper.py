import httpx
import asyncio
import aiofiles
import re
import os
import yaml
import base64
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import csv
import random
import hashlib
import ipaddress

# --- 配置 ---
DATA_DIR = "data"
CACHE_DIR = "cache"
CACHE_EXPIRY_HOURS = 24  # 缓存有效期
MAX_DEPTH = 3            # 递归抓取最大深度
CONCURRENT_REQUEST_LIMIT = 5 # 限制同时进行的 HTTP 请求数量

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Vivaldi/5.1.2567.49",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 OPR/86.0.4363.32",
    "Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Mobile Safari/537.36",
]

# 节点协议正则表达式
NODE_PATTERNS = {
    "hysteria2": r"hysteria2://[^\"'\s]+",
    "vmess": r"vmess://[a-zA-Z0-9+/=]+",
    "trojan": r"trojan://[^\"'\s]+",
    "ss": r"ss://[a-zA-Z0-9+/=@:\.-]+",
    "ssr": r"ssr://[a-zA-Z0-9+/=@:\.-]+",
    "vless": r"vless://[^\"'\s]+",
}

# --- 辅助函数 ---
# 确保目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

async def read_sources_list(file_path="sources.list"):
    """从 sources.list 文件中读取 URL 列表。"""
    urls = []
    try:
        async with aiofiles.open(file_path, 'r') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'): # 忽略空行和注释行
                    urls.append(line)
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 未找到。")
    return urls

def get_cache_path(url):
    """根据 URL 生成缓存文件路径。"""
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    return os.path.join(CACHE_DIR, f"{url_hash}.cache")

def get_url_content_hash(content):
    """生成内容哈希值。"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def decode_base64_content(content):
    """尝试解码 Base64 内容。"""
    try:
        # Base64 strings are often padded with '='
        return base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
    except Exception:
        return None

def is_valid_ip(ip_string):
    """检查字符串是否是有效的IP地址。"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

# --- 核心抓取和解析逻辑 ---

async def fetch_url_content(url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore):
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    加入信号量限制并发请求。
    """
    schemes = ["http://", "https://"]
    
    async with semaphore: # 限制并发
        # 增加随机延迟，避免过快请求
        await asyncio.sleep(random.uniform(0.5, 2.0))

        for scheme in schemes:
            full_url = f"{scheme}{url}" if not url.startswith(("http://", "https://")) else url
            cache_path = get_cache_path(full_url)

            # 检查缓存
            if os.path.exists(cache_path):
                with open(cache_path, 'r') as f:
                    try:
                        cache_data = json.load(f)
                        cached_timestamp = datetime.fromisoformat(cache_data['timestamp'])
                        # If content hash also matches, and within expiry, use cache
                        if datetime.now() - cached_timestamp < timedelta(hours=CACHE_EXPIRY_HOURS):
                            print(f"从缓存读取: {full_url}")
                            return cache_data['content']
                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"缓存文件 {cache_path} 损坏或格式错误: {e}. 删除并重新获取。")
                        os.remove(cache_path) # 删除损坏的缓存

            try:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
                    "Connection": "keep-alive",
                    "DNT": "1",
                    "Upgrade-Insecure-Requests": "1", # Some sites look for this
                }
                print(f"尝试获取: {full_url}")
                response = await client.get(full_url, follow_redirects=True, timeout=15, headers=headers) # 增加超时时间
                response.raise_for_status()  # 检查 HTTP 状态码

                content = response.text
                # 写入缓存
                cache_data = {
                    'timestamp': datetime.now().isoformat(),
                    'content_hash': get_url_content_hash(content),
                    'content': content
                }
                with open(cache_path, 'w') as f:
                    json.dump(cache_data, f)
                print(f"成功获取并缓存: {full_url}")
                return content
            except httpx.RequestError as e:
                print(f"获取 {full_url} 失败: {e}")
                if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 403:
                    print(f"403 Forbidden: {full_url} - Server denied access. Response: {e.response.text[:200]}...")
                elif isinstance(e, httpx.RequestError) and "hostname nor servname provided" in str(e):
                    print(f"DNS解析失败或URL无效: {full_url}")
                continue # 尝试下一个scheme或返回None
        return None

def extract_nodes_from_text(text: str):
    """从文本中提取所有已知格式的节点。"""
    nodes = []
    for node_type, pattern in NODE_PATTERNS.items():
        nodes.extend(re.findall(pattern, text))
    return nodes

def parse_and_extract_nodes(content: str, current_depth=0):
    """
    解析网页内容，提取节点和嵌套链接，并递归读取。
    """
    all_nodes = set()
    new_urls_to_fetch = set()

    # 尝试解析 HTML
    soup = BeautifulSoup(content, 'html.parser')

    # 提取所有文本内容，去除 HTML 标签，包括JS脚本和CSS样式
    for script_or_style in soup(["script", "style"]):
        script_or_style.extract() # 移除脚本和样式标签

    plain_text = soup.get_text(separator='\n', strip=True)

    # 提取 Base64 编码的链接 (长度至少20，通常Base64节点会更长)
    # 修正：Base64 字符串可能出现在文本的任何位置，不再仅限于URL格式
    base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', plain_text)
    for b64_str in base64_matches:
        decoded = decode_base64_content(b64_str)
        if decoded:
            extracted_from_decoded = extract_nodes_from_text(decoded)
            if extracted_from_decoded: # 只有当解码内容确实包含节点时才添加
                all_nodes.update(extracted_from_decoded)
                # 尝试从解码内容中寻找新的 URL
                new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))

    # 提取明文节点
    all_nodes.update(extract_nodes_from_text(plain_text))

    # 尝试解析 YAML 或 JSON
    try:
        data = yaml.safe_load(content)
        if isinstance(data, (dict, list)):
            def walk_data(item):
                if isinstance(item, str):
                    all_nodes.update(extract_nodes_from_text(item))
                    new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
                elif isinstance(item, (dict, list)):
                    for sub_item in (item.values() if isinstance(item, dict) else item):
                        walk_data(sub_item)
            walk_data(data)
    except (yaml.YAMLError, json.JSONDecodeError):
        pass # 不是 YAML 或 JSON，忽略

    # 提取页面中的其他链接进行深度抓取
    if current_depth < MAX_DEPTH:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # 只考虑绝对 URL 或协议相对 URL
            if href.startswith('http://') or href.startswith('https://'):
                new_urls_to_fetch.add(href)

    return list(all_nodes), list(new_urls_to_fetch)


def validate_node(node: str) -> bool:
    """
    根据官方要求验证节点格式是否符合要求。
    这个函数需要根据不同协议的实际规范进行详细实现。
    """
    if not node or len(node) < 10: # 基本长度检查
        return False

    # Helper for common host:port validation
    def validate_host_port(host, port_str):
        if not (host and port_str and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$', host):
            return False # 检查域名格式
        if not (1 <= int(port_str) <= 65535):
            return False
        return True

    if node.startswith("hysteria2://"):
        parts = node[len("hysteria2://"):].split('?')
        host_port_str = parts[0]
        if ':' not in host_port_str: return False
        host, port = host_port_str.split(':', 1)
        return validate_host_port(host, port) and 'password' in node # 简单检查密码存在

    elif node.startswith("vmess://"):
        try:
            encoded_str = node[len("vmess://"):]
            decoded_json = base64.b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8')
            data = json.loads(decoded_json)
            if not all(k in data for k in ['v', 'ps', 'add', 'port', 'id']): return False
            return validate_host_port(data['add'], str(data['port']))
        except Exception: return False

    elif node.startswith("trojan://"):
        parts = node[len("trojan://"):].split('@')
        if len(parts) < 2: return False
        password = parts[0][len("trojan://"):] if "trojan://" in parts[0] else parts[0] # remove prefix if present
        host_port_path = parts[1].split('#')[0].split('?')[0] # 忽略备注和参数
        if ':' not in host_port_path: return False
        host, port_str = host_port_path.split(':', 1)
        return password and validate_host_port(host, port_str)

    elif node.startswith("ss://"):
        try:
            encoded_str_with_prefix = node[len("ss://"):]
            if '@' not in encoded_str_with_prefix: # 可能是 Base64 编码
                decoded_str = base64.urlsafe_b64decode(encoded_str_with_prefix + '=' * (-len(encoded_str_with_prefix) % 4)).decode('utf-8')
            else:
                decoded_str = encoded_str_with_prefix

            parts = decoded_str.split('@')
            if len(parts) < 2: return False
            method_password = parts[0]
            host_port = parts[1].split('#')[0].split('?')[0] # 忽略备注和参数

            if ':' not in method_password or ':' not in host_port: return False
            method, password = method_password.split(':', 1)
            host, port_str = host_port.split(':', 1)

            return method and password and validate_host_port(host, port_str)
        except Exception: return False

    elif node.startswith("ssr://"):
        try:
            encoded_str = node[len("ssr://"):]
            decoded_str = base64.urlsafe_b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8')
            parts = decoded_str.split(':')
            if len(parts) < 6: return False # host:port:protocol:method:obfs:password_base64
            host, port_str, protocol, method, obfs, password_b64 = parts[:6]
            return validate_host_port(host, port_str) and protocol and method and obfs and password_b64
        except Exception: return False

    elif node.startswith("vless://"):
        try:
            uuid_host_port_params = node[len("vless://"):].split('#')[0] # 忽略备注
            if '@' not in uuid_host_port_params or ':' not in uuid_host_port_params: return False
            uuid_part, host_port_params = uuid_host_port_params.split('@', 1)
            host_part, port_part = host_port_params.split(':', 1)
            host = host_part.split('?')[0] # remove parameters from host
            port_str = port_part.split('?')[0] # remove parameters from port

            if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid_part):
                return False # UUID格式检查
            return validate_host_port(host, port_str)
        except Exception: return False

    # 对于明文节点，检查是否为 host:port 格式
    # 并且如果是非协议的明文，长度不应过短
    if ':' in node and len(node.split(':')) >= 2:
        host, port_str = node.split(':', 1)
        if validate_host_port(host, port_str):
            return True

    return False # 未知协议或不符合任何已知格式

async def process_url(url: str, client: httpx.AsyncClient, processed_urls: set, all_collected_nodes: dict, semaphore: asyncio.Semaphore, current_depth=0):
    """处理单个 URL，获取内容，提取节点，并进行递归抓取。"""
    if url in processed_urls:
        return

    processed_urls.add(url)
    print(f"开始处理 URL: {url} (深度: {current_depth})")
    
    content = await fetch_url_content(url, client, semaphore)

    if not content:
        return

    nodes, new_urls = parse_and_extract_nodes(content, current_depth)
    validated_nodes_for_url = []
    
    for node in nodes:
        if validate_node(node):
            # 只保留原节点名称前5位，多余的全部删除。
            # 这部分逻辑需要根据节点协议的实际情况来调整如何提取和修改名称
            processed_node = node
            # 尝试匹配 # 后面的名称或特定协议的名称字段
            match = re.search(r'#(.*?)(?:&|\s|$)', node) # 匹配 # 到下一个 & 或空格或行尾
            if match:
                original_name = match.group(1)
                if original_name:
                    new_name = original_name[:5] # 保留前5位
                    # 替换原名称，这里需要小心，避免误替换
                    # 最稳妥的方式是重新构建节点字符串
                    processed_node = node.replace(f"#{original_name}", f"#{new_name}")
            
            validated_nodes_for_url.append(processed_node)
        else:
            print(f"无效或不完整的节点被丢弃: {node[:min(len(node), 100)]}...") # 打印部分以便调试

    # 使用 set 进行去重，因为不同深度可能抓取到相同节点
    if url not in all_collected_nodes:
        all_collected_nodes[url] = set()
    all_collected_nodes[url].update(validated_nodes_for_url)

    # 递归抓取新发现的链接
    if current_depth < MAX_DEPTH:
        tasks = []
        for new_url in new_urls:
            # 避免重复处理已处理的URL
            if new_url not in processed_urls:
                tasks.append(process_url(new_url, client, processed_urls, all_collected_nodes, semaphore, current_depth + 1))
        if tasks:
            await asyncio.gather(*tasks)

async def main():
    """主函数，协调抓取和保存过程。"""
    source_urls = await read_sources_list()
    if not source_urls:
        print("未找到任何要处理的 URL。请检查 sources.list 文件。")
        return

    # 使用 set 收集所有发现的 URL 的节点，以便在保存时合并
    # 键为原始URL，值为该URL及其递归抓取到的所有节点的去重集合
    all_collected_nodes_by_url = {} 
    processed_urls = set() # 跟踪所有已尝试或正在处理的URL，避免循环抓取

    semaphore = asyncio.Semaphore(CONCURRENT_REQUEST_LIMIT)

    async with httpx.AsyncClient(http2=True, verify=False, timeout=20) as client: # 增加客户端级别超时
        tasks = [process_url(url, client, processed_urls, all_collected_nodes_by_url, semaphore) for url in source_urls]
        await asyncio.gather(*tasks)

    # 保存每个原始 URL 获取到的所有节点（包括递归抓取到的）
    for url, nodes_set in all_collected_nodes_by_url.items():
        if nodes_set:
            safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url) # 将URL转换为安全文件名
            output_file_path = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
            async with aiofiles.open(output_file_path, 'w') as f:
                await f.write('\n'.join(sorted(list(nodes_set)))) # 排序并保存
            print(f"已保存 {url} 及其递归获取到的节点到 {output_file_path}，共 {len(nodes_set)} 个节点。")

    # 统计节点数量并保存为 CSV
    csv_file_path = os.path.join(DATA_DIR, "node_counts.csv")
    async with aiofiles.open(csv_file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Node Count"])
        for url, nodes_set in all_collected_nodes_by_url.items():
            writer.writerow([url, len(nodes_set)])
    print(f"节点统计已保存到 {csv_file_path}")

if __name__ == "__main__":
    asyncio.run(main())
