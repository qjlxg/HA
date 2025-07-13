import httpx
import asyncio
import re
import base64
import yaml
import json
import os
import csv
import random
import datetime
import hashlib
from urllib.parse import urlparse, urlunparse
from collections import Counter
from bs4 import BeautifulSoup
import aiofiles
import logging
import aiodns
# from tenacity import retry, stop_after_attempt, wait_exponential # Removed tenacity import
from pathlib import Path

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 数据保存路径
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(exist_ok=True)
ALL_NODES_FILE = DATA_DIR / "all.txt"
NODE_COUNTS_CSV = DATA_DIR / "node_counts.csv"
PROTOCOL_STATS_CSV = DATA_DIR / "protocol_stats.csv"
RAW_FETCHED_NODES_TEMP_FILE = DATA_DIR / "raw_fetched_nodes_temp.txt"
CACHE_FILE = DATA_DIR / "cache.json"
DNS_CACHE_FILE = DATA_DIR / "dns_cache.json"

# 缓存有效期（小时）
CACHE_EXPIRY_HOURS = 24

# 并发限制
CONCURRENCY_LIMIT = int(os.getenv("CONCURRENCY_LIMIT", 50))
# 新增：节点验证的并发限制，可以与 URL 抓取并发限制不同
NODE_VALIDATION_CONCURRENCY_LIMIT = int(os.getenv("NODE_VALIDATION_CONCURRENCY_LIMIT", 100))


# 用户代理
USER_AGENTS = {
    "desktop": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    ],
    "mobile": [
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
    ],
    "pad": [
        "Mozilla/5.0 (iPad; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
    ],
    "harmonyos": [
        "Mozilla/5.0 (Linux; HarmonyOS; HMA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 HuaweiBrowser/12.0.0.301 Mobile Safari/537.36",
    ]
}

# 缓存
PROCESSED_URLS_CACHE = {}   # {url: {"hash": content_hash, "timestamp": float}}
DNS_CACHE = {}  # {hostname: {"ips": [ip_address], "timestamp": float, "ttl": int}}

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
    """加载 URL 和 DNS 缓存并清理过期记录"""
    try:
        now = datetime.datetime.now().timestamp()
        # 加载 URL 缓存
        if CACHE_FILE.exists():
            async with aiofiles.open(CACHE_FILE, 'r', encoding='utf-8') as f:
                content = await f.read()
                if content:
                    cache = json.loads(content)
                    PROCESSED_URLS_CACHE.update({
                        k: v for k, v in cache.items()
                        if (now - v["timestamp"]) < CACHE_EXPIRY_HOURS * 3600
                    })
                    logger.info(f"加载了 {len(PROCESSED_URLS_CACHE)} 个 URL 缓存记录")
        # 加载 DNS 缓存
        if DNS_CACHE_FILE.exists():
            async with aiofiles.open(DNS_CACHE_FILE, 'r', encoding='utf-8') as f:
                content = await f.read()
                if content:
                    cache = json.loads(content)
                    DNS_CACHE.update({
                        k: v for k, v in cache.items()
                        if (now - v["timestamp"]) < CACHE_EXPIRY_HOURS * 3600
                    })
                    logger.info(f"加载了 {len(DNS_CACHE)} 个 DNS 缓存记录")
    except Exception as e:
        logger.error(f"加载缓存失败: {e}")

async def save_cache():
    """保存 URL 和 DNS 缓存（原子性写入）"""
    try:
        # 保存 URL 缓存
        temp_file = CACHE_FILE.with_suffix('.tmp')
        async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(PROCESSED_URLS_CACHE))
        temp_file.rename(CACHE_FILE)
        logger.info(f"URL 缓存已保存到 {CACHE_FILE}")
        # 保存 DNS 缓存
        temp_dns_file = DNS_CACHE_FILE.with_suffix('.tmp')
        async with aiofiles.open(temp_dns_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(DNS_CACHE))
        temp_dns_file.rename(DNS_CACHE_FILE)
        logger.info(f"DNS 缓存已保存到 {DNS_CACHE_FILE}")
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
        logger.info(f"从 {file_path} 读取了 {len(urls)} 个 URL")
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
        "hysteria2": r"hysteria2:\/\/[\w\-\.]+:\d+[^ \t\n\r]*",
        "vmess": r"vmess:\/\/[a-zA-Z0-9=+/]+",
        "trojan": r"trojan:\/\/[^@]+@[\w\.-]+:\d+[^ \t\n\r]*",
        "ss": r"ss:\/\/[a-zA-Z0-9=+/]+",
        "ssr": r"ssr:\/\/[a-zA-Z0-9=+/]+",
        "vless": r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+[^ \t\n\r]*",
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
        logger.debug("内容不是有效的 YAML 格式")

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
        logger.debug("内容不是有效的 JSON 格式")

    # HTML 解析
    if any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html']):
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text()
        for proto, pattern in node_patterns.items():
            nodes.extend(re.findall(pattern, text_content, re.IGNORECASE))
        for tag in soup.find_all(['pre', 'code', 'textarea', 'div', 'p']):
            block_content = tag.get_text()
            for proto, pattern in node_patterns.items():
                nodes.extend(re.findall(pattern, block_content, re.IGNORECASE))

    return list(set(nodes))

async def validate_hysteria2(node):
    """验证 Hysteria2 节点"""
    return bool(re.match(r"hysteria2:\/\/[\w\-\.]+:\d+[^ \t\n\r]*", node))

async def validate_vmess(node):
    """验证 VMess 节点"""
    try:
        encoded_part = node[len("vmess://"):]
        decoded_json_str = decode_base64(encoded_part)
        if not decoded_json_str:
            return False
        vmess_config = json.loads(decoded_json_str)
        return all(k in vmess_config for k in ["add", "port", "id", "aid", "net", "type"])
    except Exception:
        return False

async def validate_trojan(node):
    """验证 Trojan 节点"""
    return bool(re.match(r"trojan:\/\/[^@]+@[\w\.-]+:\d+[^ \t\n\r]*", node))

async def validate_ss(node):
    """验证 Shadowsocks 节点"""
    try:
        encoded_part = node[len("ss://"):]
        decoded_str = decode_base64(encoded_part)
        return decoded_str and '@' in decoded_str and ':' in decoded_str
    except Exception:
        return False

async def validate_ssr(node):
    """验证 ShadowsocksR 节点"""
    try:
        encoded_part = node[len("ssr://"):]
        decoded_str = decode_base64(encoded_part)
        return decoded_str and len(decoded_str.split(':')) >= 6
    except Exception:
        return False

async def validate_vless(node):
    """验证 VLESS 节点"""
    return bool(re.match(r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+[^ \t\n\r]*", node))

# Wrap validate_node for concurrent processing
async def _validate_node_concurrent(node, resolver, semaphore):
    async with semaphore:
        return await validate_node(node, resolver)

async def validate_node(node, resolver):
    """验证节点格式和 DNS 可达性"""
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

        # DNS 缓存检查
        now = datetime.datetime.now().timestamp()
        if hostname in DNS_CACHE and (now - DNS_CACHE[hostname]["timestamp"]) < CACHE_EXPIRY_HOURS * 3600:
            logger.debug(f"DNS 缓存命中: {hostname} -> {DNS_CACHE[hostname]['ips']}")
            return bool(DNS_CACHE[hostname]["ips"])

        # DNS 解析
        try:
            result = await resolver.query(hostname, 'A')
            if not result:
                logger.debug(f"DNS 解析失败 for {hostname} in node {node}")
                return False
            ips = [r.host for r in result]
            DNS_CACHE[hostname] = {
                "ips": ips,
                "timestamp": now,
                "ttl": result[0].ttl if result else 3600
            }
            logger.debug(f"DNS 解析成功: {hostname} -> {ips}")
        except Exception as e:
            logger.debug(f"DNS 解析失败 for {hostname} in node {node}: {e}")
            return False

        # 协议验证
        validators = {
            "hysteria2": validate_hysteria2,
            "vmess": validate_vmess,
            "trojan": validate_trojan,
            "ss": validate_ss,
            "ssr": validate_ssr,
            "vless": validate_vless,
        }
        validator = validators.get(node_type)
        if not validator:
            logger.debug(f"不支持的协议: {node_type} in node {node}")
            return False
        return await validator(node)
    except Exception as e:
        logger.debug(f"节点验证失败 for {node}: {e}")
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
            pass
    elif parsed_url.fragment and len(parsed_url.fragment) > 5:
        new_parsed_url = parsed_url._replace(fragment=parsed_url.fragment[:5])
        return urlunparse(new_parsed_url)
    return node

# Removed @retry decorator
async def fetch_url_content(client, url):
    """安全地异步获取 URL 内容"""
    if url in PROCESSED_URLS_CACHE:
        cache_entry = PROCESSED_URLS_CACHE[url]
        if (datetime.datetime.now().timestamp() - cache_entry["timestamp"]) < CACHE_EXPIRY_HOURS * 3600:
            logger.info(f"URL {url} 在缓存中，跳过抓取")
            return None

    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url_to_fetch = f"http://{url}"
    else:
        url_to_fetch = url

    headers = get_random_headers()
    try:
        response = await client.get(url_to_fetch, headers=headers, timeout=7) # Modified timeout
        response.raise_for_status()
        content = response.text
        PROCESSED_URLS_CACHE[url] = {
            "hash": hashlib.sha256(content.encode('utf-8')).hexdigest(),
            "timestamp": datetime.datetime.now().timestamp()
        }
        return content
    except httpx.RequestError as e:
        logger.warning(f"初次请求 URL 时发生错误: {url_to_fetch} - {e}")
        if url_to_fetch.startswith("http://"):
            https_url = url_to_fetch.replace("http://", "https://", 1)
            try:
                logger.info(f"尝试使用 HTTPS 重试: {https_url}")
                response = await client.get(https_url, headers=headers, timeout=7) # Modified timeout
                response.raise_for_status()
                content = response.text
                PROCESSED_URLS_CACHE[url] = {
                    "hash": hashlib.sha256(content.encode('utf-8')).hexdigest(),
                    "timestamp": datetime.datetime.now().timestamp()
                }
                return content
            except httpx.RequestError as https_e:
                logger.error(f"HTTP 和 HTTPS 尝试 URL 时均发生错误: {url} - {https_e}")
                raise # Re-raise if both attempts fail
        raise # Re-raise if http fails and not an http URL

async def process_url(client, url, semaphore, resolver):
    """处理单个 URL：抓取内容，解析节点，并保存到临时文件"""
    node_count = 0
    error_message = None
    async with semaphore:
        try:
            logger.info(f"开始处理 URL: {url}")
            content = await fetch_url_content(client, url)
            if content:
                # Save content to a file named after the URL
                safe_filename = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
                url_content_file = DATA_DIR / f"{safe_filename}.txt"
                async with aiofiles.open(url_content_file, 'w', encoding='utf-8') as f:
                    await f.write(content)
                logger.info(f"URL {url} 的内容已保存到 {url_content_file}")

                nodes = parse_nodes_from_content(content)
                node_count = len(nodes)
                if nodes:
                    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'a', encoding='utf-8') as f:
                        for node in nodes:
                            await f.write(node + '\n')
                logger.info(f"URL {url} 解析到 {node_count} 个节点")
            else:
                logger.info(f"URL {url} 未返回内容或从缓存加载")
        except Exception as e:
            logger.error(f"处理 URL {url} 时发生错误: {e}")
            error_message = str(e)
    return url, node_count, error_message

async def validate_and_save_nodes(resolver):
    """从临时文件读取并验证节点，保存协议统计"""
    raw_nodes_to_validate = []
    if not RAW_FETCHED_NODES_TEMP_FILE.exists():
        logger.warning(f"临时节点文件 {RAW_FETCHED_NODES_TEMP_FILE} 不存在，跳过验证")
        return []

    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'r', encoding='utf-8') as f:
        async for node_line in f:
            raw_nodes_to_validate.append(node_line.strip())
    
    # Parallelize node validation
    validation_semaphore = asyncio.Semaphore(NODE_VALIDATION_CONCURRENCY_LIMIT)
    validation_tasks = []
    for node in raw_nodes_to_validate:
        validation_tasks.append(_validate_node_concurrent(node, resolver, validation_semaphore))
    
    validated_results = await asyncio.gather(*validation_tasks)

    validated_nodes_with_protocols = []
    protocol_counts = Counter()
    valid_protocol_counts = Counter()

    for i, is_valid in enumerate(validated_results):
        node = raw_nodes_to_validate[i]
        protocol = node.split('://')[0].lower() if '://' in node else 'unknown'
        protocol_counts[protocol] += 1
        if is_valid:
            validated_nodes_with_protocols.append(rename_node(node))
            valid_protocol_counts[protocol] += 1

    unique_nodes = list(set(validated_nodes_with_protocols))

    # 保存节点
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(node + '\n')

    # 保存协议统计
    with open(PROTOCOL_STATS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Protocol', 'Total Count', 'Valid Count'])
        for proto in protocol_counts:
            writer.writerow([proto, protocol_counts[proto], valid_protocol_counts.get(proto, 0)])
    logger.info(f"协议统计已保存到 {PROTOCOL_STATS_CSV}")

    return unique_nodes

async def main():
    logger.info("开始执行代理抓取任务")
    await load_cache()
    urls = await read_urls_from_file('sources.list')
    if not urls:
        logger.warning("未找到任何 URL，程序退出")
        return

    # 清空之前的 all.txt 和 temp 文件
    if ALL_NODES_FILE.exists():
        ALL_NODES_FILE.unlink()
    if RAW_FETCHED_NODES_TEMP_FILE.exists():
        RAW_FETCHED_NODES_TEMP_FILE.unlink()

    node_counts_data = []
    url_fetch_semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) # Renamed for clarity

    resolver = aiodns.DNSResolver(timeout=5, nameservers=['8.8.8.8', '1.1.1.1']) # Initialize resolver once

    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        tasks = [process_url(client, url, url_fetch_semaphore, resolver) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                url, node_count, _ = result
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
    logger.info("代理抓取任务完成")

if __name__ == "__main__":
    asyncio.run(main())
