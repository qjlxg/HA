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

# 配置
DATA_DIR = "data"
CACHE_DIR = "cache"
CACHE_EXPIRY_HOURS = 24  # 缓存有效期
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    # 更多用户代理...
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

async def fetch_url_content(url: str, client: httpx.AsyncClient):
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    """
    schemes = ["http://", "https://"]
    for scheme in schemes:
        full_url = f"{scheme}{url}" if not url.startswith(("http://", "https://")) else url
        cache_path = get_cache_path(full_url)

        # 检查缓存
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as f:
                try:
                    cache_data = json.load(f)
                    cached_timestamp = datetime.fromisoformat(cache_data['timestamp'])
                    if datetime.now() - cached_timestamp < timedelta(hours=CACHE_EXPIRY_HOURS):
                        print(f"从缓存读取: {full_url}")
                        return cache_data['content']
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"缓存文件 {cache_path} 损坏或格式错误: {e}")
                    os.remove(cache_path) # 删除损坏的缓存

        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = await client.get(full_url, follow_redirects=True, timeout=10, headers=headers)
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
            continue
    return None

def decode_base64_content(content):
    """尝试解码 Base64 内容。"""
    try:
        return base64.b64decode(content).decode('utf-8')
    except Exception:
        return None

def extract_nodes_from_text(text: str):
    """从文本中提取所有已知格式的节点。"""
    nodes = []
    for node_type, pattern in NODE_PATTERNS.items():
        nodes.extend(re.findall(pattern, text))
    return nodes

def parse_and_extract_nodes(content: str, current_depth=0, max_depth=3):
    """
    解析网页内容，提取节点和嵌套链接，并递归读取。
    """
    all_nodes = set()
    new_urls_to_fetch = set()

    # 尝试解析 HTML
    soup = BeautifulSoup(content, 'html.parser')

    # 提取所有文本内容，去除 HTML 标签
    plain_text = soup.get_text(separator='\n')

    # 提取 Base64 编码的链接
    base64_matches = re.findall(r'[a-zA-Z0-9+/=]{20,}', plain_text) # 匹配可能的Base64字符串
    for b64_str in base64_matches:
        decoded = decode_base64_content(b64_str)
        if decoded:
            all_nodes.update(extract_nodes_from_text(decoded))
            # 尝试从解码内容中寻找新的 URL
            new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))


    # 提取明文节点
    all_nodes.update(extract_nodes_from_text(plain_text))

    # 尝试解析 YAML 或 JSON
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 递归遍历字典查找节点或链接
            for key, value in data.items():
                if isinstance(value, str):
                    all_nodes.update(extract_nodes_from_text(value))
                    new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', value))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            all_nodes.update(extract_nodes_from_text(item))
                            new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    all_nodes.update(extract_nodes_from_text(item))
                    new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
    except (yaml.YAMLError, json.JSONDecodeError):
        pass # 不是 YAML 或 JSON，忽略

    # 提取页面中的其他链接进行深度抓取
    if current_depth < max_depth:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # 只考虑绝对 URL 或协议相对 URL
            if href.startswith('http://') or href.startswith('https://'):
                new_urls_to_fetch.add(href)

    return list(all_nodes), list(new_urls_to_fetch)

def is_valid_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_node(node: str) -> bool:
    """
    根据官方要求验证节点格式是否符合要求。
    这个函数需要根据不同协议的实际规范进行详细实现。
    以下是一些简化和示例性的验证逻辑。
    """
    if not node:
        return False

    # 检查基本长度，防止明显不全的节点
    if len(node) < 10: # 假设最短的节点长度
        return False

    # 根据协议类型进行初步判断
    if node.startswith("hysteria2://"):
        # 示例：Hysteria2 节点至少包含 host:port
        parts = node[len("hysteria2://"):].split('?')
        if not parts:
            return False
        host_port = parts[0]
        if ':' not in host_port:
            return False
        host, port = host_port.split(':')
        if not (host and port and port.isdigit()):
            return False
        # 可以添加更复杂的验证，如证书指纹、密码等
        return True
    elif node.startswith("vmess://"):
        # VMess 通常是 Base64 编码的 JSON
        try:
            encoded_str = node[len("vmess://"):]
            decoded_json = base64.b64decode(encoded_str).decode('utf-8')
            data = json.loads(decoded_json)
            # 检查必要字段，例如 v、ps、add、port、id
            if not all(k in data for k in ['v', 'ps', 'add', 'port', 'id']):
                return False
            if not is_valid_ip(data['add']) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data['add']):
                return False # 检查地址是否是有效IP或域名
            if not isinstance(data['port'], int) or not (1 <= data['port'] <= 65535):
                return False
            return True
        except Exception:
            return False
    elif node.startswith("trojan://"):
        # Trojan 节点通常是 password@host:port
        parts = node[len("trojan://"):].split('@')
        if len(parts) != 2:
            return False
        password = parts[0]
        host_port_path = parts[1].split('#')[0] # 忽略备注
        if ':' not in host_port_path:
            return False
        host, port_str = host_port_path.split(':')
        if not (password and host and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', host):
            return False
        if not (1 <= int(port_str) <= 65535):
            return False
        return True
    elif node.startswith("ss://"):
        # SS 通常是 base64(method:password@host:port) 或 method:password@host:port
        try:
            encoded_str = node[len("ss://"):]
            if '@' not in encoded_str: # 可能是 Base64 编码
                decoded_str = base64.urlsafe_b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8')
            else:
                decoded_str = encoded_str

            parts = decoded_str.split('@')
            if len(parts) != 2:
                return False
            method_password = parts[0]
            host_port = parts[1].split('#')[0] # 忽略备注

            if ':' not in method_password or ':' not in host_port:
                return False
            method, password = method_password.split(':', 1)
            host, port_str = host_port.split(':')

            if not (method and password and host and port_str.isdigit()):
                return False
            if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', host):
                return False
            if not (1 <= int(port_str) <= 65535):
                return False
            return True
        except Exception:
            return False
    elif node.startswith("ssr://"):
        # SSR 通常是 base64(host:port:protocol:method:obfs:password_base64/?params)
        try:
            encoded_str = node[len("ssr://"):]
            decoded_str = base64.urlsafe_b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8')
            parts = decoded_str.split(':')
            if len(parts) < 6: # 至少有 host, port, protocol, method, obfs, password
                return False
            host, port_str, protocol, method, obfs, password_b64 = parts[:6]
            if not (host and port_str.isdigit() and protocol and method and obfs and password_b64):
                return False
            if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', host):
                return False
            if not (1 <= int(port_str) <= 65535):
                return False
            return True
        except Exception:
            return False
    elif node.startswith("vless://"):
        # VLESS 类似于 VMess，通常是 UUID@host:port
        try:
            uuid_host_port = node[len("vless://"):].split('?')[0] # 忽略参数
            if '@' not in uuid_host_port or ':' not in uuid_host_port:
                return False
            uuid_part, host_port_part = uuid_host_port.split('@', 1)
            host, port_str = host_port_part.split(':', 1)
            
            # 简单的 UUID 格式检查
            if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid_part):
                return False

            if not (host and port_str.isdigit()):
                return False
            if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', host):
                return False
            if not (1 <= int(port_str) <= 65535):
                return False
            return True
        except Exception:
            return False

    # 对于明文节点，进行更宽松的判断或要求特定模式
    # 比如简单地检查是否包含冒号（用于 host:port）并且端口是数字
    if ':' in node:
        parts = node.split(':')
        if len(parts) >= 2 and parts[-1].isdigit():
            return True

    return False # 未知协议或不符合任何已知格式

async def process_url(url: str, client: httpx.AsyncClient, processed_urls: set, all_collected_nodes: dict):
    """处理单个 URL，获取内容，提取节点，并进行递归抓取。"""
    if url in processed_urls:
        return []

    processed_urls.add(url)
    print(f"开始处理 URL: {url}")
    content = await fetch_url_content(url, client)

    if not content:
        return []

    nodes, new_urls = parse_and_extract_nodes(content)
    validated_nodes = []
    for node in nodes:
        if validate_node(node):
            # 只保留节点名称前5位（如果节点有名称部分的话）
            # 这部分逻辑需要根据实际节点格式来调整，这里仅为示例
            processed_node = node
            match = re.search(r'#([^&\s]+)', node) # 查找备注
            if match:
                original_name = match.group(1)
                if len(original_name) > 5:
                    new_name = original_name[:5]
                    processed_node = node.replace(original_name, new_name)

            validated_nodes.append(processed_node)
        else:
            print(f"无效或不完整的节点被丢弃: {node[:50]}...") # 打印部分以便调试

    all_collected_nodes[url] = validated_nodes

    # 递归抓取新发现的链接
    tasks = []
    for new_url in new_urls:
        if new_url not in processed_urls:
            tasks.append(process_url(new_url, client, processed_urls, all_collected_nodes))
    if tasks:
        await asyncio.gather(*tasks)

    return validated_nodes

async def main():
    """主函数，协调抓取和保存过程。"""
    source_urls = await read_sources_list()
    if not source_urls:
        print("未找到任何要处理的 URL。请检查 sources.list 文件。")
        return

    all_collected_nodes = {}
    processed_urls = set()

    async with httpx.AsyncClient(http2=True, verify=False) as client:
        tasks = [process_url(url, client, processed_urls, all_collected_nodes) for url in source_urls]
        await asyncio.gather(*tasks)

    # 保存每个 URL 获取到的节点
    for url, nodes in all_collected_nodes.items():
        if nodes:
            safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
            output_file_path = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
            async with aiofiles.open(output_file_path, 'w') as f:
                await f.write('\n'.join(nodes))
            print(f"已保存 {url} 的节点到 {output_file_path}，共 {len(nodes)} 个节点。")

    # 统计节点数量并保存为 CSV
    csv_file_path = os.path.join(DATA_DIR, "node_counts.csv")
    async with aiofiles.open(csv_file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Node Count"])
        for url, nodes in all_collected_nodes.items():
            writer.writerow([url, len(nodes)])
    print(f"节点统计已保存到 {csv_file_path}")

if __name__ == "__main__":
    asyncio.run(main())
