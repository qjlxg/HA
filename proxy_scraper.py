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
from playwright.async_api import async_playwright
import logging # 引入 logging 模块

# --- 配置 ---
DATA_DIR = "data"
CACHE_DIR = "cache"
CACHE_EXPIRY_HOURS = 24  # 缓存有效期
MAX_DEPTH = 3            # 递归抓取最大深度
CONCURRENT_REQUEST_LIMIT = 2 # 限制同时进行的请求数量，推荐Playwright保持较低并发

# 配置日志
logging.basicConfig(
    level=logging.INFO, # 默认只显示 INFO 级别及以上的日志 (INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# 如果需要看详细的“丢弃节点”警告，可以改成 logging.DEBUG 或 logging.WARNING
# logging.getLogger().setLevel(logging.WARNING) 

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
                if line and not line.startswith('#'):
                    urls.append(line)
    except FileNotFoundError:
        logging.error(f"文件 {file_path} 未找到。")
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

# --- 核心抓取和解析逻辑 (使用 Playwright) ---

async def fetch_url_content(url: str, semaphore: asyncio.Semaphore):
    """
    安全地异步获取 URL 内容，加入信号量限制并发请求，使用 Playwright 模拟浏览器行为。
    """
    schemes = ["http://", "https://"]
    
    async with semaphore:
        await asyncio.sleep(random.uniform(1.0, 4.0))

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
                            # logging.info(f"从缓存读取: {full_url}") # 进一步减少日志
                            return cache_data['content']
                    except (json.JSONDecodeError, KeyError) as e:
                        logging.warning(f"缓存文件 {cache_path} 损坏或格式错误: {e}. 删除并重新获取。")
                        os.remove(cache_path)

            try:
                # logging.info(f"尝试使用 Playwright 获取: {full_url}") # 进一步减少日志
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(user_agent=random.choice(USER_AGENTS))
                    page = await context.new_page()

                    await page.goto(full_url, wait_until='domcontentloaded', timeout=30000)
                    await page.wait_for_load_state('networkidle', timeout=30000)

                    content = await page.content()
                    await browser.close()

                    cache_data = {
                        'timestamp': datetime.now().isoformat(),
                        'content_hash': get_url_content_hash(content),
                        'content': content
                    }
                    with open(cache_path, 'w') as f:
                        json.dump(cache_data, f)
                    logging.info(f"成功获取: {full_url}") # 只在成功时打印 INFO
                    return content
            except Exception as e:
                logging.error(f"获取 {full_url} 失败: {e}") # 失败时打印 ERROR
                continue
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

    soup = BeautifulSoup(content, 'html.parser')

    for script_or_style in soup(["script", "style"]):
        script_or_style.extract()

    plain_text = soup.get_text(separator='\n', strip=True)

    base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', plain_text)
    for b64_str in base64_matches:
        decoded = decode_base64_content(b64_str)
        if decoded:
            extracted_from_decoded = extract_nodes_from_text(decoded)
            if extracted_from_decoded:
                all_nodes.update(extracted_from_decoded)
                new_urls_to_fetch.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))

    all_nodes.update(extract_nodes_from_text(plain_text))

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
        pass

    if current_depth < MAX_DEPTH:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('http://') or href.startswith('https://'):
                new_urls_to_fetch.add(href)

    return list(all_nodes), list(new_urls_to_fetch)


def validate_node(node: str) -> bool:
    """
    根据官方要求验证节点格式是否符合要求。
    """
    if not node or len(node) < 10:
        return False

    def validate_host_port(host, port_str):
        if not (host and port_str and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$', host):
            return False
        if not (1 <= int(port_str) <= 65535):
            return False
        return True

    if node.startswith("hysteria2://"):
        parts = node[len("hysteria2://"):].split('?')
        host_port_str = parts[0]
        if ':' not in host_port_str: return False
        host, port = host_port_str.split(':', 1)
        return validate_host_port(host, port) and 'password' in node

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
        password = parts[0][len("trojan://"):] if "trojan://" in parts[0] else parts[0]
        host_port_path = parts[1].split('#')[0].split('?')[0]
        if ':' not in host_port_path: return False
        host, port_str = host_port_path.split(':', 1)
        return password and validate_host_port(host, port_str)

    elif node.startswith("ss://"):
        try:
            encoded_str_with_prefix = node[len("ss://"):]
            if '@' not in encoded_str_with_prefix:
                decoded_str = base64.urlsafe_b64decode(encoded_str_with_prefix + '=' * (-len(encoded_str_with_prefix) % 4)).decode('utf-8')
            else:
                decoded_str = encoded_str_with_prefix

            parts = decoded_str.split('@')
            if len(parts) < 2: return False
            method_password = parts[0]
            host_port = parts[1].split('#')[0].split('?')[0]

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
            if len(parts) < 6: return False
            host, port_str, protocol, method, obfs, password_b64 = parts[:6]
            return validate_host_port(host, port_str) and protocol and method and obfs and password_b64
        except Exception: return False

    elif node.startswith("vless://"):
        try:
            uuid_host_port_params = node[len("vless://"):].split('#')[0]
            if '@' not in uuid_host_port_params or ':' not in uuid_host_port_params: return False
            uuid_part, host_port_params = uuid_host_port_params.split('@', 1)
            host_part, port_part = host_port_params.split(':', 1)
            host = host_part.split('?')[0]
            port_str = port_part.split('?')[0]

            if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid_part):
                return False
            return validate_host_port(host, port_str)
        except Exception: return False

    if ':' in node and len(node.split(':')) >= 2:
        host, port_str = node.split(':', 1)
        if validate_host_port(host, port_str):
            return True

    return False

async def process_url(url: str, processed_urls: set, all_collected_nodes: dict, semaphore: asyncio.Semaphore, current_depth=0):
    """处理单个 URL，获取内容，提取节点，并进行递归抓取。"""
    if url in processed_urls:
        return

    processed_urls.add(url)
    # logging.info(f"开始处理 URL: {url}") # 减少日志输出
    
    content = await fetch_url_content(url, semaphore)

    if not content:
        return

    nodes, new_urls = parse_and_extract_nodes(content, current_depth)
    validated_nodes_for_url = []
    
    for node in nodes:
        if validate_node(node):
            processed_node = node
            match = re.search(r'#(.*?)(?:&|\s|$)', node)
            if match:
                original_name = match.group(1)
                if original_name:
                    new_name = original_name[:5]
                    processed_node = node.replace(f"#{original_name}", f"#{new_name}")
            
            validated_nodes_for_url.append(processed_node)
        else:
            # logging.warning(f"丢弃无效或不完整的节点: {node[:min(len(node), 100)]}...") # 调整为 DEBUG 级别，默认不显示
            logging.debug(f"丢弃无效或不完整的节点: {node[:min(len(node), 100)]}...") # 使用 debug 级别，默认不显示
            pass # 不打印此警告

    if url not in all_collected_nodes:
        all_collected_nodes[url] = set()
    all_collected_nodes[url].update(validated_nodes_for_url)

    if current_depth < MAX_DEPTH:
        tasks = []
        for new_url in new_urls:
            if new_url not in processed_urls:
                tasks.append(process_url(new_url, processed_urls, all_collected_nodes, semaphore, current_depth + 1))
        if tasks:
            await asyncio.gather(*tasks)

async def main():
    """主函数，协调抓取和保存过程。"""
    logging.info("开始执行代理抓取任务") # 任务开始时打印
    source_urls = await read_sources_list()
    if not source_urls:
        logging.error("未找到任何要处理的 URL。请检查 sources.list 文件。")
        return

    logging.info(f"从 sources.list 读取了 {len(source_urls)} 个 URL") # 打印读取数量

    all_collected_nodes_by_url = {} 
    processed_urls = set()

    semaphore = asyncio.Semaphore(CONCURRENT_REQUEST_LIMIT)
    
    # 开始处理所有源 URL
    logging.info("开始处理 URLs...")
    tasks = [process_url(url, processed_nodes, all_collected_nodes_by_url, semaphore) for url in source_urls]
    await asyncio.gather(*tasks)
    logging.info("所有 URL 处理完毕。")

    # 保存每个原始 URL 获取到的所有节点（包括递归抓取到的）
    logging.info(f"开始保存节点到 {DATA_DIR}/ 目录...")
    for url, nodes_set in all_collected_nodes_by_url.items():
        if nodes_set:
            safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
            output_file_path = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
            async with aiofiles.open(output_file_path, 'w') as f:
                await f.write('\n'.join(sorted(list(nodes_set))))
            logging.info(f"已保存 {len(nodes_set)} 个节点，来源: {url}")
        else:
            # logging.info(f"URL {url} 未解析到任何节点，未创建/清空独立节点文件。") # 调整为 DEBUG 级别，默认不显示
            logging.debug(f"URL {url} 未解析到任何节点，未创建/清空独立节点文件。") # 使用 debug 级别，默认不显示

    logging.info("节点保存完成。")

    # 统计节点数量并保存为 CSV
    csv_file_path = os.path.join(DATA_DIR, "node_counts.csv")
    async with aiofiles.open(csv_file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Node Count"])
        for url, nodes_set in all_collected_nodes_by_url.items():
            writer.writerow([url, len(nodes_set)])
    logging.info(f"节点统计已保存到 {csv_file_path}")

if __name__ == "__main__":
    asyncio.run(main())
