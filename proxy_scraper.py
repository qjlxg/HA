import httpx
import asyncio
import re
import os
import csv
import hashlib
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import base64
import yaml
from urllib.parse import urlparse, unquote

# 配置
CACHE_DIR = "cache"
DATA_DIR = "data"
SOURCES_LIST = "sources.list"
CACHE_EXPIRATION_HOURS = 24  # 缓存有效期（小时）
CONCURRENT_REQUESTS_PER_URL = 5  # 每个URL并行请求数
REQUEST_TIMEOUT = 15  # 请求超时时间（秒）

# 确保目录存在
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# 请求头列表，包含多种设备类型
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]

# 代理协议正则表达式
NODE_PATTERNS = {
    "hysteria2": r"hysteria2://[\w\d\-\._~:/?#\[\]@!$&'()*+,;=]+",
    "vmess": r"vmess://[a-zA-Z0-9+/=]+",
    "trojan": r"trojan://[\w\d\-\._~:/?#\[\]@!$&'()*+,;=]+",
    "ss": r"ss://[a-zA-Z0-9+/=]+",
    "ssr": r"ssr://[a-zA-Z0-9+/=]+",
    "vless": r"vless://[\w\d\-\._~:/?#\[\]@!$&'()*+,;=]+"
}

# 已知代理协议的验证函数 (简化示例，实际验证需更复杂)
# 实际验证需要根据协议规范进行详细解析和字段检查
def validate_node(node_string, protocol_type):
    """
    验证代理节点字符串是否符合协议规范且信息完整。
    """
    try:
        if protocol_type == "vmess":
            # 尝试解码VMess，检查JSON结构
            decoded = base64.b64decode(node_string[len("vmess://"):])
            json.loads(decoded)
            return True
        elif protocol_type in ["trojan", "vless", "hysteria2"]:
            # 这些协议通常有明确的结构，这里简单检查是否包含必要的域名/IP和端口
            parts = node_string.split('@')
            if len(parts) < 2:
                return False
            addr_port = parts[1].split('#')[0]
            if ':' not in addr_port:
                return False
            host, port = addr_port.rsplit(':', 1)
            # 简单判断host是否非空，port是否为数字
            return bool(host) and port.isdigit()
        elif protocol_type == "ss":
            # SS协议的base64解码后通常是user:pass@server:port或加密方法:password@server:port
            decoded = base64.b64decode(node_string[len("ss://"):])
            # 这里可以进一步解析解码后的内容
            return True
        elif protocol_type == "ssr":
            # SSR协议有更复杂的参数，这里仅做初步检查
            decoded = base64.b64decode(node_string[len("ssr://"):])
            # 可以检查是否有足够的参数
            return True
        else:
            return False
    except Exception as e:
        # print(f"节点验证失败: {node_string}, 错误: {e}")
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> str:
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    """
    headers = {'User-Agent': USER_AGENTS[hash(url) % len(USER_AGENTS)]} # 根据URL随机选择请求头
    try:
        # 尝试 HTTPS
        response = await client.get(f"https://{url}", headers=headers, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        print(f"成功获取 HTTPS: {url}")
        return response.text
    except httpx.RequestError as exc:
        print(f"HTTPS 请求失败: {url} - {exc}")
        try:
            # 尝试 HTTP
            response = await client.get(f"http://{url}", headers=headers, timeout=REQUEST_TIMEOUT, follow_redirects=True)
            response.raise_for_status()
            print(f"成功获取 HTTP: {url}")
            return response.text
        except httpx.RequestError as exc_http:
            print(f"HTTP 请求失败: {url} - {exc_http}")
            return ""
    except Exception as e:
        print(f"获取 URL 过程中发生未知错误: {url} - {e}")
        return ""

def get_cache_path(url: str) -> str:
    """
    根据URL生成缓存文件路径。
    """
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    return os.path.join(CACHE_DIR, f"{url_hash}.json")

async def get_content_with_cache(client: httpx.AsyncClient, url: str) -> str:
    """
    从缓存中读取内容，如果缓存不存在或过期则从URL获取并更新缓存。
    """
    cache_path = get_cache_path(url)
    current_time = datetime.now()

    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            try:
                cache_data = json.load(f)
                cached_time = datetime.fromisoformat(cache_data['timestamp'])
                if current_time - cached_time < timedelta(hours=CACHE_EXPIRATION_HOURS):
                    print(f"从缓存读取: {url}")
                    return cache_data['content']
            except (json.JSONDecodeError, KeyError) as e:
                print(f"缓存文件损坏或格式不正确: {cache_path}, 错误: {e}")

    # 缓存无效或不存在，从网络获取
    content = await fetch_url(client, url)
    if content:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump({'timestamp': current_time.isoformat(), 'content': content}, f, ensure_ascii=False, indent=2)
    return content

def extract_urls_from_text(text: str, base_url: str) -> set:
    """
    从文本中提取符合条件的URL，并进行格式化。
    """
    found_urls = set()
    # 查找所有类似URL的字符串
    potential_urls = re.findall(r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s\"'<>]*)?", text)
    for p_url in potential_urls:
        parsed_url = urlparse(p_url)
        # 确保是有效的网络地址
        if parsed_url.netloc:
            # 移除http/https，只保留域名和路径
            normalized_url = parsed_url.netloc + parsed_url.path
            # 移除末尾的斜杠
            if normalized_url.endswith('/'):
                normalized_url = normalized_url[:-1]
            found_urls.add(normalized_url)
    return found_urls

def parse_and_extract_nodes(html_content: str) -> set:
    """
    解析HTML内容，优先从特定标签中提取节点，并处理多种节点格式。
    """
    nodes = set()
    soup = BeautifulSoup(html_content, 'html.parser')

    # 优先处理 <pre>, <code>, <textarea> 等可能包含节点内容的标签
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        content = tag.get_text()
        extracted_from_tag = extract_nodes_from_text(content)
        if extracted_from_tag:
            nodes.update(extracted_from_tag)

    # 如果特定标签没有提取到足够内容，或者需要从整个页面中提取
    # 提取所有文本内容（去除脚本、样式等）
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()
    text_content = soup.get_text()

    extracted_from_text = extract_nodes_from_text(text_content)
    if extracted_from_text:
        nodes.update(extracted_from_text)
    
    return nodes

def extract_nodes_from_text(text_content: str) -> set:
    """
    从纯文本内容中提取符合代理协议格式的节点，并处理base64和YAML/JSON。
    """
    found_nodes = set()

    # 尝试解码 Base64
    try:
        decoded_text = base64.b64decode(text_content).decode('utf-8', errors='ignore')
        for proto, pattern in NODE_PATTERNS.items():
            for match in re.finditer(pattern, decoded_text):
                node = match.group(0)
                if validate_node(node, proto):
                    found_nodes.add(node)
    except Exception as e:
        # print(f"Base64 解码失败: {e}")
        pass # 不是base64编码的内容

    # 尝试解析 YAML 或 JSON
    try:
        data = yaml.safe_load(text_content)
        if isinstance(data, dict):
            # 假设节点在某个键下，例如 'proxies', 'nodes'
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy_item in data['proxies']:
                    if isinstance(proxy_item, dict) and 'type' in proxy_item:
                        # 简单的将字典转换为字符串，然后尝试匹配
                        node_str = json.dumps(proxy_item) # 或者构建成协议字符串
                        for proto, pattern in NODE_PATTERNS.items():
                            if proto in node_str: # 简单匹配协议名
                                # 更高级的解析会在这里根据type构建具体的协议URL
                                # 目前，我们只是检查是否能从其中提取到已知格式
                                for match in re.finditer(pattern, node_str):
                                    node = match.group(0)
                                    if validate_node(node, proto):
                                        found_nodes.add(node)
            elif 'nodes' in data and isinstance(data['nodes'], list):
                for node_item in data['nodes']:
                    if isinstance(node_item, str):
                        for proto, pattern in NODE_PATTERNS.items():
                            if re.match(pattern, node_item):
                                if validate_node(node_item, proto):
                                    found_nodes.add(node_item)
    except Exception as e:
        # print(f"YAML/JSON 解析失败: {e}")
        pass # 不是YAML/JSON格式

    # 直接从文本中匹配协议格式
    for proto, pattern in NODE_PATTERNS.items():
        for match in re.finditer(pattern, text_content):
            node = match.group(0)
            if validate_node(node, proto):
                found_nodes.add(node)

    return found_nodes

def truncate_node_name(node_string: str) -> str:
    """
    只保留原始节点名称前5位，多余的全部删除。
    """
    # 提取节点名称部分，例如在 # 之后的部分
    match = re.search(r'#([^&\s]+)', node_string)
    if match:
        original_name = match.group(1)
        truncated_name = original_name[:5]
        # 替换回原字符串
        return node_string.replace(original_name, truncated_name)
    return node_string # 如果没有找到名称，则返回原字符串

def get_sanitized_filename(url: str) -> str:
    """
    生成一个基于URL的合法文件名，只保留中间域名。
    """
    parsed_url = urlparse(f"http://{url}") # 随意加上http://以便urlparse处理
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) >= 2:
        # 移除常见的顶级域名后缀和www
        domain_parts = [p for p in domain_parts if p not in ['www', 'com', 'net', 'org', 'cn', 'co', 'jp', 'uk', 'io', 'xyz', 'top', 'info', 'me', 'gov', 'edu']]
        if len(domain_parts) > 0:
            # 尝试保留核心部分，例如 google.com -> google
            # 或者 sub.domain.com -> domain
            if len(domain_parts) > 1:
                return domain_parts[-2].replace('.', '_').replace('-', '_') # 取倒数第二个作为主要域名
            else:
                return domain_parts[0].replace('.', '_').replace('-', '_')
    
    # 如果无法有效提取，则使用哈希值
    return hashlib.md5(url.encode('utf-8')).hexdigest()[:10]

async def scrape_url(client: httpx.AsyncClient, url: str, all_collected_nodes: set):
    """
    抓取单个URL及其内联链接，收集节点并统计。
    """
    print(f"开始处理 URL: {url}")
    visited_urls = set()
    urls_to_visit = [url]
    url_nodes_count = 0
    url_specific_nodes = set()

    while urls_to_visit:
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls:
            continue
        visited_urls.add(current_url)

        content = await get_content_with_cache(client, current_url)
        if not content:
            print(f"未能获取内容或内容为空: {current_url}")
            continue

        # 提取节点
        new_nodes = parse_and_extract_nodes(content)
        
        # 截断节点名称
        truncated_nodes = set()
        for node in new_nodes:
            truncated_nodes.add(truncate_node_name(node))

        # 筛选有效的节点
        valid_nodes = set()
        for node in truncated_nodes:
            for proto_type, pattern in NODE_PATTERNS.items():
                if re.match(pattern, node) and validate_node(node, proto_type):
                    valid_nodes.add(node)
                    break # 找到匹配项就跳出内部循环

        url_specific_nodes.update(valid_nodes)
        all_collected_nodes.update(valid_nodes)
        url_nodes_count += len(valid_nodes)

        # 提取新的链接继续抓取
        extracted_links = extract_urls_from_text(content, current_url)
        for link in extracted_links:
            # 避免循环引用和重复访问，并且只抓取当前域名的子路径或相关域名
            parsed_current = urlparse(f"http://{current_url}")
            parsed_link = urlparse(f"http://{link}")
            if parsed_link.netloc == parsed_current.netloc or parsed_link.netloc.endswith(f".{parsed_current.netloc}"):
                if link not in visited_urls:
                    urls_to_visit.append(link)
    
    # 保存该URL获取到的节点
    if url_specific_nodes:
        sanitized_filename = get_sanitized_filename(url)
        output_filepath = os.path.join(DATA_DIR, f"{sanitized_filename}.txt")
        with open(output_filepath, 'w', encoding='utf-8') as f:
            for node in sorted(list(url_specific_nodes)):
                f.write(node + '\n')
        print(f"已将 {len(url_specific_nodes)} 个节点保存到 {output_filepath}")

    return url, url_nodes_count

async def main():
    all_collected_nodes = set()
    node_counts = [] # (URL, 节点数量) 列表

    # 读取 sources.list
    if not os.path.exists(SOURCES_LIST):
        print(f"错误: {SOURCES_LIST} 文件不存在。请在项目根目录创建此文件并填入URL。")
        return

    with open(SOURCES_LIST, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    async with httpx.AsyncClient(http2=True) as client:
        tasks = [scrape_url(client, url, all_collected_nodes) for url in urls]
        results = await asyncio.gather(*tasks)
        for url, count in results:
            node_counts.append({'URL': url, '节点数量': count})
    
    # 保存总节点文件
    total_nodes_path = os.path.join(DATA_DIR, "all_proxies.txt")
    with open(total_nodes_path, 'w', encoding='utf-8') as f:
        for node in sorted(list(all_collected_nodes)):
            f.write(node + '\n')
    print(f"\n所有唯一节点已保存到 {total_nodes_path}，共 {len(all_collected_nodes)} 个节点。")

    # 保存节点数量统计到 CSV
    csv_path = os.path.join(DATA_DIR, "node_counts.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(node_counts)
    print(f"节点数量统计已保存到 {csv_path}")

if __name__ == "__main__":
    asyncio.run(main())
