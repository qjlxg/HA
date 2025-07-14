import asyncio
import httpx
import re
import yaml
import json
import base64
from bs4 import BeautifulSoup
import aiofiles
import os
import csv
import hashlib
import time
from datetime import datetime, timedelta
import random
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

# 定义支持的节点协议前缀
SUPPORTED_PROTOCOLS = [
    "hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"
]

# 用户代理列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36"
]

# 缓存目录和过期时间（24小时）
CACHE_DIR = "cache"
CACHE_EXPIRATION_TIME = timedelta(hours=24)

# 确保data和cache目录存在
os.makedirs("data", exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

async def read_urls_from_file(file_path="sources.list"):
    """
    从指定文件中读取URL列表。
    """
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 忽略空行和注释行
                    urls.append(line)
        logging.info(f"成功从 {file_path} 读取 {len} 个URL。")
    except FileNotFoundError:
        logging.error(f"错误：文件 {file_path} 未找到。")
    return urls

def get_full_url(url):
    """
    补全URL，如果缺少http或https前缀。
    """
    if not (url.startswith("http://") or url.startswith("https://")):
        return f"http://{url}"  # 优先尝试HTTP
    return url

def validate_node(node_string):
    """
    验证节点字符串是否符合已知协议格式且信息完整。
    """
    for protocol in SUPPORTED_PROTOCOLS:
        if node_string.startswith(protocol):
            try:
                # 针对不同协议进行初步验证
                if protocol == "vmess://":
                    # VMess 节点是 Base64 编码的 JSON
                    decoded = base64.b64decode(node_string[len("vmess://"):].encode('utf-8')).decode('utf-8')
                    node_info = json.loads(decoded)
                    return all(k in node_info for k in ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type'])
                elif protocol == "vless://":
                    # VLESS 节点通常是 URL 格式，包含 UUID 和地址
                    parts = re.match(r"vless:\/\/([a-f0-9-]+)@([\d\w\.-]+):(\d+)", node_string)
                    return bool(parts)
                elif protocol == "trojan://":
                    # Trojan 节点通常是 password@address:port
                    parts = re.match(r"trojan:\/\/([^@]+)@([\d\w\.-]+):(\d+)", node_string)
                    return bool(parts)
                elif protocol == "ss://":
                    # SS 节点是 Base64 编码的 method:password@address:port
                    encoded_part = node_string[len("ss://"):].split('#')[0]
                    decoded = base64.b64decode(encoded_part.split('@')[0]).decode('utf-8')
                    return '@' in node_string and ':' in node_string
                elif protocol == "ssr://":
                    # SSR 节点是 Base64 编码的 URL
                    decoded = base64.b64decode(node_string[len("ssr://"):].encode('utf-8')).decode('utf-8')
                    return 'obfsparam=' in decoded and 'protoparam=' in decoded
                elif protocol == "hysteria2://":
                    # Hysteria2 节点格式
                    return re.match(r"hysteria2:\/\/([^@]+)@([\d\w\.-]+):(\d+)\?.*", node_string) is not None
            except Exception as e:
                logging.warning(f"节点 {node_string[:50]}... 验证失败: {e}")
                return False
    return False

def parse_and_extract_nodes(content):
    """
    解析网页内容，提取各种格式的节点，并进行初步过滤。
    优先处理 <pre>, <code>, <textarea> 等可能包含节点内容的标签。
    """
    nodes = set()
    soup = BeautifulSoup(content, 'html.parser')

    # 优先从 pre, code, textarea 标签中提取
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            # 查找所有支持的协议前缀
            for protocol in SUPPORTED_PROTOCOLS:
                # 改进的正则表达式，匹配协议开头，直到遇到空格或换行符
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s]+', text_content)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)

    # 查找 Base64 编码的字符串
    base64_patterns = [
        r'[A-Za-z0-9+/]{20,}=+', # 常见的 Base64 模式
        r'vmess:\/\/([A-Za-z0-9+/]+={0,2})', # 捕获 VMess Base64 部分
        r'ss:\/\/([A-Za-z0-9+/]+={0,2})' # 捕获 SS Base64 部分
    ]
    for pattern in base64_patterns:
        for match in re.findall(pattern, content):
            try:
                decoded_content = base64.b64decode(match).decode('utf-8')
                for protocol in SUPPORTED_PROTOCOLS:
                    # 再次在解码内容中查找节点
                    found_nodes = re.findall(rf'{re.escape(protocol)}[^\s]+', decoded_content)
                    for node in found_nodes:
                        if validate_node(node):
                            nodes.add(node)
            except Exception:
                pass # 忽略解码失败的情况

    # 查找 YAML 和 JSON 中的节点（假设节点是字符串值）
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) or isinstance(data, list):
            yaml_str = json.dumps(data) # 转换为字符串以便正则匹配
            for protocol in SUPPORTED_PROTOCOLS:
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s"\']+', yaml_str)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)
    except yaml.YAMLError:
        pass # 不是 YAML 格式

    try:
        data = json.loads(content)
        if isinstance(data, dict) or isinstance(data, list):
            json_str = json.dumps(data) # 转换为字符串以便正则匹配
            for protocol in SUPPORTED_PROTOCOLS:
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s"\']+', json_str)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)
    except json.JSONDecodeError:
        pass # 不是 JSON 格式

    # 查找明文节点
    for protocol in SUPPORTED_PROTOCOLS:
        # 在整个内容中查找，但避免匹配HTML标签属性等
        found_nodes = re.findall(rf'{re.escape(protocol)}[^\s<>"\'`]+', content)
        for node in found_nodes:
            if validate_node(node):
                nodes.add(node)

    return list(nodes)

def get_cache_path(url_hash):
    """
    获取缓存文件的路径。
    """
    return os.path.join(CACHE_DIR, f"{url_hash}.cache")

def get_cache_timestamp_path(url_hash):
    """
    获取缓存时间戳文件的路径。
    """
    return os.path.join(CACHE_DIR, f"{url_hash}.timestamp")

async def get_cached_content(url_hash):
    """
    从缓存中获取内容，如果缓存有效。
    """
    cache_file = get_cache_path(url_hash)
    timestamp_file = get_cache_timestamp_path(url_hash)

    if os.path.exists(cache_file) and os.path.exists(timestamp_file):
        try:
            async with aiofiles.open(timestamp_file, 'r', encoding='utf-8') as f:
                timestamp_str = await f.read()
            cached_time = datetime.fromisoformat(timestamp_str)
            if datetime.now() - cached_time < CACHE_EXPIRATION_TIME:
                async with aiofiles.open(cache_file, 'r', encoding='utf-8') as f:
                    logging.info(f"从缓存中读取 {url_hash}。")
                    return await f.read()
        except Exception as e:
            logging.warning(f"读取缓存失败 {url_hash}: {e}")
    return None

async def save_to_cache(url_hash, content):
    """
    将内容保存到缓存。
    """
    cache_file = get_cache_path(url_hash)
    timestamp_file = get_cache_timestamp_path(url_hash)
    try:
        async with aiofiles.open(cache_file, 'w', encoding='utf-8') as f:
            await f.write(content)
        async with aiofiles.open(timestamp_file, 'w', encoding='utf-8') as f:
            await f.write(datetime.now().isoformat())
        logging.info(f"内容已缓存 {url_hash}。")
    except Exception as e:
        logging.error(f"保存缓存失败 {url_hash}: {e}")

async def fetch_url_content(client, url, visited_urls, depth=0, max_depth=3):
    """
    异步安全地获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    支持多层读取和缓存机制。
    """
    full_url = get_full_url(url)
    if full_url in visited_urls:
        logging.debug(f"已访问URL，跳过：{full_url}")
        return []

    visited_urls.add(full_url)
    url_hash = hashlib.sha256(full_url.encode('utf-8')).hexdigest()

    # 尝试从缓存获取
    cached_content = await get_cached_content(url_hash)
    if cached_content:
        logging.info(f"从缓存获取 {full_url} 的内容。")
        nodes = parse_and_extract_nodes(cached_content)
        # 递归获取新链接
        if depth < max_depth:
            # 找到网页中的所有链接
            soup = BeautifulSoup(cached_content, 'html.parser')
            internal_links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                # 简单过滤，避免非HTTP/HTTPS链接和外部链接
                if href.startswith('http://') or href.startswith('https://'):
                    internal_links.add(href)
                elif href.startswith('/') and full_url.startswith('http'): # 相对路径
                    base_url_parsed = httpx.URL(full_url)
                    internal_links.add(str(base_url_parsed.join(href)))

            tasks = []
            for link in internal_links:
                if link not in visited_urls:
                    tasks.append(fetch_url_content(client, link, visited_urls, depth + 1, max_depth))
            if tasks:
                results = await asyncio.gather(*tasks)
                for res_nodes in results:
                    nodes.extend(res_nodes)
        return nodes

    content = None
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        response = await client.get(full_url, timeout=10, headers=headers)
        response.raise_for_status()  # 检查 HTTP 错误
        content = response.text
        logging.info(f"成功获取 {full_url} 的内容。")
    except httpx.RequestError as e:
        logging.warning(f"获取 {full_url} 失败: {e}。尝试 HTTPS...")
        # 如果 HTTP 失败，尝试 HTTPS
        if full_url.startswith("http://"):
            https_url = "https://" + full_url[len("http://"):]
            try:
                response = await client.get(https_url, timeout=10, headers=headers)
                response.raise_for_status()
                content = response.text
                logging.info(f"成功通过 HTTPS 获取 {https_url} 的内容。")
                full_url = https_url # 更新为实际获取成功的URL
            except httpx.RequestError as e_https:
                logging.error(f"通过 HTTPS 获取 {https_url} 再次失败: {e_https}。")
        else:
            logging.error(f"获取 {full_url} 失败: {e}。")

    if content:
        # 保存到缓存
        await save_to_cache(url_hash, content)

        # 保存原始网页内容到data目录，文件名为 URL 的哈希值，扩展名为 .html 或 .txt
        file_extension = "txt"
        if "html" in response.headers.get("Content-Type", "").lower():
            file_extension = "html"
        original_content_path = os.path.join("data", f"{url_hash}.{file_extension}")
        async with aiofiles.open(original_content_path, 'w', encoding='utf-8') as f:
            await f.write(content)
        logging.info(f"原始网页内容已保存到 {original_content_path}")

        nodes = parse_and_extract_nodes(content)

        # 递归获取新链接
        if depth < max_depth:
            # 找到网页中的所有链接
            soup = BeautifulSoup(content, 'html.parser')
            internal_links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http://') or href.startswith('https://'):
                    internal_links.add(href)
                elif href.startswith('/') and full_url.startswith('http'):
                    base_url_parsed = httpx.URL(full_url)
                    internal_links.add(str(base_url_parsed.join(href)))

            tasks = []
            for link in internal_links:
                if link not in visited_urls:
                    tasks.append(fetch_url_content(client, link, visited_urls, depth + 1, max_depth))
            if tasks:
                results = await asyncio.gather(*tasks)
                for res_nodes in results:
                    nodes.extend(res_nodes)
        return nodes
    return []

def shorten_node_name(node_string):
    """
    只保留原节点名称前5位，多余的全部删除。
    """
    for protocol in SUPPORTED_PROTOCOLS:
        if node_string.startswith(protocol):
            # 尝试找到 # 后面的名称部分
            match = re.search(r'#([^&]+)$', node_string)
            if match:
                original_name = match.group(1)
                shortened_name = original_name[:5]
                return node_string.replace(f"#{original_name}", f"#{shortened_name}")
            break
    return node_string # 如果没有找到名称或不匹配协议，返回原字符串

async def main():
    start_time = time.time()
    urls = await read_urls_from_file()
    all_nodes = set()
    url_node_counts = []
    visited_urls = set()

    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        for url in urls:
            tasks.append(fetch_url_content(client, url, visited_urls))
        
        results = await asyncio.gather(*tasks)

        for i, nodes_from_url in enumerate(results):
            original_url = urls[i]
            unique_nodes_from_url = set()
            for node in nodes_from_url:
                shortened_node = shorten_node_name(node)
                all_nodes.add(shortened_node)
                unique_nodes_from_url.add(shortened_node)
            
            url_node_counts.append({
                "url": original_url,
                "node_count": len(unique_nodes_from_url)
            })
            
            # 将每个URL获取到的节点单独保存
            url_hash = hashlib.sha256(get_full_url(original_url).encode('utf-8')).hexdigest()
            output_file = os.path.join("data", f"{url_hash}_nodes.txt")
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes_from_url:
                    await f.write(node + '\n')
            logging.info(f"URL: {original_url} 提取到 {len(unique_nodes_from_url)} 个节点，保存到 {output_file}。")

    # 保存节点数量统计到CSV
    csv_file_path = os.path.join("data", "node_counts.csv")
    async with aiofiles.open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["url", "node_count"])
        await f.write(','.join(writer.fieldnames) + '\n') # 写头部
        for row in url_node_counts:
            await f.write(f"{row['url']},{row['node_count']}\n")
    logging.info(f"节点数量统计已保存到 {csv_file_path}。")

    # 将所有收集到的唯一节点保存到combined_nodes.txt
    combined_nodes_path = os.path.join("data", "combined_nodes.txt")
    async with aiofiles.open(combined_nodes_path, 'w', encoding='utf-8') as f:
        for node in sorted(list(all_nodes)): # 排序以便每次生成一致的文件
            await f.write(node + '\n')
    logging.info(f"所有唯一节点已保存到 {combined_nodes_path}。总计 {len(all_nodes)} 个节点。")

    end_time = time.time()
    logging.info(f"脚本执行完毕，总耗时：{end_time - start_time:.2f} 秒。")

if __name__ == "__main__":
    asyncio.run(main())
