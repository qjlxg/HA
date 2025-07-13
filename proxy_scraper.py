import httpx
import asyncio
import re
import base64
import yaml
import json
import os
import csv
import random
import datetime # 导入 datetime 模块
from urllib.parse import urlparse, urlunparse # 导入 urlunparse
from collections import defaultdict
from bs4 import BeautifulSoup
import aiofiles
import logging
import aiodns
from tenacity import retry, stop_after_attempt, wait_exponential
from pathlib import Path

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 数据保存路径
DATA_DIR = Path("data")
ALL_NODES_FILE = DATA_DIR / "all.txt"
NODE_COUNTS_CSV = DATA_DIR / "node_counts.csv"
RAW_FETCHED_NODES_TEMP_FILE = DATA_DIR / "raw_fetched_nodes_temp.txt"
CACHE_FILE = DATA_DIR / "cache.json"

# 确保数据目录存在
DATA_DIR.mkdir(exist_ok=True)

# 缓存机制：存储已处理的 URL 及其内容哈希和时间戳
PROCESSED_URLS_CACHE = {} # {url: {"hash": content_hash, "timestamp": datetime}}

# 预定义的请求头
USER_AGENTS = {
    "desktop": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    ],
    "mobile": [
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
    ],
    "pad": [
        "Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
    ],
    "harmonyos": [
        "Mozilla/5.0 (Linux; HarmonyOS; HMA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 HuaweiBrowser/12.0.0.301 Mobile Safari/537.36",
    ]
}

def get_random_headers():
    """随机获取一个请求头"""
    category = random.choice(list(USER_AGENTS.keys()))
    user_agent = random.choice(USER_AGENTS[category])
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }

async def load_cache():
    """加载缓存"""
    try:
        if CACHE_FILE.exists():
            async with aiofiles.open(CACHE_FILE, 'r', encoding='utf-8') as f:
                PROCESSED_URLS_CACHE.update(json.loads(await f.read()))
    except Exception as e:
        logger.error(f"加载缓存失败: {e}")

async def save_cache():
    """保存缓存"""
    try:
        async with aiofiles.open(CACHE_FILE, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(PROCESSED_URLS_CACHE))
    except Exception as e:
        logger.error(f"保存缓存失败: {e}")

async def read_urls_from_file(file_path):
    """从文件中读取 URL 列表，并补全 http/https 前缀"""
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not (line.startswith('http://') or line.startswith('https://')):
                        urls.append(f'http://{line}')
                    else:
                        urls.append(line)
        logger.info(f"从 {file_path} 读取了 {len(urls)} 个 URL。")
    except FileNotFoundError:
        logger.error(f"文件未找到: {file_path}")
    return urls

def decode_base64(data):
    """安全地进行 Base64 解码"""
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        logger.warning(f"Base64 解码失败: {e}")
        return None

def parse_nodes_from_content(content):
    """从网页内容中解析各种节点"""
    nodes = []
    if not content:
        return nodes

    node_patterns = {
        "hysteria2": r"hysteria2:\/\/[^\s]+",
        "vmess": r"vmess:\/\/[^\s]+",
        "trojan": r"trojan:\/\/[^\s]+",
        "ss": r"ss:\/\/[^\s]+",
        "ssr": r"ssr:\/\/[^\s]+",
        "vless": r"vless:\/\/[^\s]+",
    }

    # 直接正则匹配
    for proto, pattern in node_patterns.items():
        nodes.extend(re.findall(pattern, content, re.IGNORECASE))

    # Base64 解码
    decoded_content = decode_base64(content)
    if decoded_content:
        for proto, pattern in node_patterns.items():
            nodes.extend(re.findall(pattern, decoded_content, re.IGNORECASE))

    # YAML 解析
    try:
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and "proxies" in parsed_yaml:
            for proxy in parsed_yaml["proxies"]:
                if isinstance(proxy, str):
                    for proto, pattern in node_patterns.items():
                        if re.match(pattern, proxy, re.IGNORECASE):
                            nodes.append(proxy)
                elif isinstance(proxy, dict) and "type" in proxy:
                    for k, v in proxy.items():
                        if isinstance(v, str):
                            for proto, pattern in node_patterns.items():
                                if re.match(pattern, v, re.IGNORECASE):
                                    nodes.append(v)
    except yaml.YAMLError:
        logger.debug("内容不是有效的 YAML 格式。")

    # JSON 解析
    try:
        parsed_json = json.loads(content)
        def find_nodes_in_json(obj):
            found_nodes = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        for proto, pattern in node_patterns.items():
                            if re.match(pattern, v, re.IGNORECASE):
                                found_nodes.append(v)
                    elif isinstance(v, (dict, list)):
                        found_nodes.extend(find_nodes_in_json(v))
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str):
                        for proto, pattern in node_patterns.items():
                            if re.match(pattern, item, re.IGNORECASE):
                                found_nodes.append(item)
                    elif isinstance(item, (dict, list)):
                        found_nodes.extend(find_nodes_in_json(item))
            return found_nodes
        nodes.extend(find_nodes_in_json(parsed_json))
    except json.JSONDecodeError:
        logger.debug("内容不是有效的 JSON 格式。")

    # HTML 解析
    if any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html']):
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text()
        for proto, pattern in node_patterns.items():
            nodes.extend(re.findall(pattern, text_content, re.IGNORECASE))
        for tag in soup.find_all(['pre', 'code', 'textarea', 'div', 'p']): # 增加更多标签以全面解析
            block_content = tag.get_text()
            for proto, pattern in node_patterns.items():
                nodes.extend(re.findall(pattern, block_content, re.IGNORECASE))

    return list(set(nodes))

async def validate_node(node, resolver):
    """验证节点格式和连通性"""
    if not node:
        return False

    try:
        node_type = node.split('://')[0].lower()
        parsed = urlparse(node)
        hostname = parsed.hostname
        port = parsed.port

        if not (hostname and port):
            logger.debug(f"节点缺少主机或端口: {node}")
            return False

        # DNS 解析
        try:
            result = await resolver.query(hostname, 'A')
            if not result:
                logger.debug(f"DNS 解析失败: {node}")
                return False
        except Exception as e:
            logger.debug(f"DNS 解析失败: {e}")
            return False

        # 协议特定验证
        if node_type == "hysteria2":
            if not re.match(r"hysteria2:\/\/[^\/:]+:\d+", node):
                return False
        elif node_type == "vmess":
            encoded_part = node[len("vmess://"):]
            decoded_json_str = decode_base64(encoded_part)
            if not decoded_json_str:
                return False
            vmess_config = json.loads(decoded_json_str)
            if not all(k in vmess_config for k in ["add", "port", "id", "aid", "net", "type"]):
                return False
        elif node_type == "trojan":
            if not re.match(r"trojan:\/\/[^@]+@[\w\.-]+:\d+", node):
                return False
        elif node_type == "ss":
            encoded_part = node[len("ss://"):]
            decoded_str = decode_base64(encoded_part)
            if not decoded_str or '@' not in decoded_str or ':' not in decoded_str:
                return False
        elif node_type == "ssr":
            encoded_part = node[len("ssr://"):]
            decoded_str = decode_base64(encoded_part)
            if not decoded_str or len(decoded_str.split(':')) < 6: # 简化判断，实际应更严格
                return False
        elif node_type == "vless":
            if not re.match(r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+", node):
                return False
        else:
            return False

        return True
    except Exception as e:
        logger.debug(f"节点验证失败: {e}")
        return False

def rename_node(node):
    """只保留节点名称前5位"""
    parsed_url = urlparse(node)
    if node.startswith("vmess://"):
        try:
            encoded_part = node[len("vmess://"):]
            decoded_json_str = decode_base64(encoded_part)
            if decoded_json_str:
                vmess_config = json.loads(decoded_json_str)
                name = vmess_config.get("ps", "")
                if len(name) > 5:
                    vmess_config["ps"] = name[:5]
                    new_encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode()
                    return f"vmess://{new_encoded}"
        except:
            pass # 忽略解析错误，返回原始节点
    elif parsed_url.fragment and len(parsed_url.fragment) > 5:
        new_parsed_url = parsed_url._replace(fragment=parsed_url.fragment[:5])
        return urlunparse(new_parsed_url)
    return node

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def fetch_url_content(client, url):
    """安全地异步获取 URL 内容"""
    if url in PROCESSED_URLS_CACHE:
        cache_entry = PROCESSED_URLS_CACHE[url]
        # 缓存有效期 24 小时
        if (datetime.datetime.now().timestamp() - cache_entry["timestamp"]) < 24 * 3600:
            logger.info(f"URL {url} 在缓存中，跳过抓取。")
            return None

    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url_to_fetch = f"http://{url}"
    else:
        url_to_fetch = url

    headers = get_random_headers()
    try:
        response = await client.get(url_to_fetch, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.text
        PROCESSED_URLS_CACHE[url] = {"hash": hash(content), "timestamp": datetime.datetime.now().timestamp()}
        return content
    except httpx.RequestError:
        if url_to_fetch.startswith("http://"):
            https_url = url_to_fetch.replace("http://", "https://", 1)
            response = await client.get(https_url, headers=headers, timeout=10)
            response.raise_for_status()
            content = response.text
            PROCESSED_URLS_CACHE[url] = {"hash": hash(content), "timestamp": datetime.datetime.now().timestamp()}
            return content
        raise # 如果不是http错误，或者https也失败，则再次抛出

async def process_url(client, url, semaphore, resolver):
    """处理单个 URL"""
    async with semaphore:
        logger.info(f"开始处理 URL: {url}")
        content = await fetch_url_content(client, url)
        if content is None:
            return url, 0, []

        # 保存原始内容
        safe_filename = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
        url_content_file = DATA_DIR / f"{safe_filename}.txt"
        async with aiofiles.open(url_content_file, 'w', encoding='utf-8') as f:
            await f.write(content)

        # 解析节点
        raw_nodes = parse_nodes_from_content(content)
        async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'a', encoding='utf-8') as f:
            for node in raw_nodes:
                await f.write(node + '\n')

        return url, len(raw_nodes), []

async def validate_and_save_nodes(resolver):
    """从临时文件读取并验证节点"""
    validated_nodes = []
    if not RAW_FETCHED_NODES_TEMP_FILE.exists():
        logger.warning(f"临时节点文件 {RAW_FETCHED_NODES_TEMP_FILE} 不存在，跳过验证。")
        return []

    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'r', encoding='utf-8') as f:
        async for node_line in f: # 将变量名改为 node_line 避免与函数参数 node 混淆
            node = node_line.strip()
            if await validate_node(node, resolver):
                validated_nodes.append(rename_node(node))

    unique_nodes = list(set(validated_nodes))
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(node + '\n')
    return unique_nodes

async def main():
    logger.info("开始执行代理抓取任务。")
    await load_cache()

    urls = await read_urls_from_file('sources.list')
    if not urls:
        logger.warning("未找到任何 URL，程序退出。")
        return

    # 清空之前的 all.txt 和 temp 文件
    if ALL_NODES_FILE.exists():
        ALL_NODES_FILE.unlink()
    if RAW_FETCHED_NODES_TEMP_FILE.exists():
        RAW_FETCHED_NODES_TEMP_FILE.unlink()

    node_counts_data = []
    resolver = aiodns.DNSResolver()
    semaphore = asyncio.Semaphore(50) # 限制并发数量

    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        tasks = [process_url(client, url, semaphore, resolver) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                url, node_count, _ = result # 忽略第三个元素，因为它在 process_url 中已经没有意义了
                node_counts_data.append({"url": url, "node_count": node_count})
            else:
                logger.error(f"处理 URL 时发生异常: {result}")

    unique_nodes = await validate_and_save_nodes(resolver)
    logger.info(f"所有 {len(unique_nodes)} 个唯一节点已保存到 {ALL_NODES_FILE}")

    with open(NODE_COUNTS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url', 'node_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(node_counts_data)
    logger.info(f"节点统计已保存到 {NODE_COUNTS_CSV}")

    await save_cache()
    logger.info("代理抓取任务完成。")

if __name__ == "__main__":
    asyncio.run(main())
