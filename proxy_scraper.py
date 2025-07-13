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
from pathlib import Path

# --- 日志配置 ---
# 配置日志输出，包括时间、级别、消息
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 文件路径配置 ---
# 定义数据保存的主目录，默认是脚本同级的 'data' 文件夹
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(exist_ok=True) # 如果目录不存在则创建

ALL_NODES_FILE = DATA_DIR / "all.txt" # 所有去重后的有效节点保存文件
NODE_COUNTS_CSV = DATA_DIR / "node_counts.csv" # 每个 URL 抓取到的节点数量统计文件
PROTOCOL_STATS_CSV = DATA_DIR / "protocol_stats.csv" # 各协议节点统计文件
RAW_FETCHED_NODES_TEMP_FILE = DATA_DIR / "raw_fetched_nodes_temp.txt" # 临时保存所有抓取到的原始节点，待后续验证
CACHE_FILE = DATA_DIR / "cache.json" # URL 内容的哈希和时间戳缓存文件
DNS_CACHE_FILE = DATA_DIR / "dns_cache.json" # DNS 解析结果缓存文件

# --- 全局配置 ---
CACHE_EXPIRY_HOURS = 24 # 缓存有效期（小时），用于 URL 内容和 DNS 缓存的默认过期时间

# 并发限制：同时处理的 URL 抓取任务数量
CONCURRENCY_LIMIT = int(os.getenv("CONCURRENCY_LIMIT", 50))
# 节点验证的并发限制：同时进行的 DNS 查询和节点格式验证任务数量
NODE_VALIDATION_CONCURRENCY_LIMIT = int(os.getenv("NODE_VALIDATION_CONCURRENCY_LIMIT", 100))

# 用户代理列表，用于模拟不同设备类型的浏览器访问
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

# --- 缓存数据结构 ---
# 存储已处理 URL 的缓存：{url: {"hash": 内容哈希值, "timestamp": 抓取时间戳}}
PROCESSED_URLS_CACHE = {}
# 存储 DNS 解析结果的缓存：{hostname: {"ips": [IP地址列表], "timestamp": 解析时间戳, "ttl": DNS记录的TTL}}
DNS_CACHE = {}

# --- 辅助函数 ---

def get_random_headers():
    """
    随机获取一个请求头，用于模拟不同的浏览器访问，防止被目标网站识别为爬虫。
    """
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
    """
    加载 URL 内容缓存和 DNS 解析缓存，并清理过期记录。
    确保在程序启动时加载现有缓存以提高效率。
    """
    try:
        now = datetime.datetime.now().timestamp()
        
        # 加载 URL 缓存
        if CACHE_FILE.exists():
            async with aiofiles.open(CACHE_FILE, 'r', encoding='utf-8') as f:
                content = await f.read()
                if content:
                    cache = json.loads(content)
                    # 只加载未过期的缓存记录
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
                    # 只加载未过期的缓存记录（DNS 缓存使用默认过期时间或实际TTL）
                    DNS_CACHE.update({
                        k: v for k, v in cache.items()
                        # 使用 min 函数确保DNS缓存至少在 CACHE_EXPIRY_HOURS 内有效，或者使用其更短的 TTL
                        if (now - v["timestamp"]) < min(CACHE_EXPIRY_HOURS * 3600, v.get("ttl", CACHE_EXPIRY_HOURS * 3600))
                    })
                    logger.info(f"加载了 {len(DNS_CACHE)} 个 DNS 缓存记录")
    except Exception as e:
        logger.error(f"加载缓存失败: {e}")

async def save_cache():
    """
    保存 URL 内容缓存和 DNS 解析缓存到文件（使用临时文件进行原子性写入，防止数据损坏）。
    在程序结束时调用。
    """
    try:
        # 保存 URL 缓存
        temp_file = CACHE_FILE.with_suffix('.tmp')
        async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(PROCESSED_URLS_CACHE))
        temp_file.rename(CACHE_FILE) # 重命名临时文件，完成原子写入
        logger.info(f"URL 缓存已保存到 {CACHE_FILE}")
        
        # 保存 DNS 缓存
        temp_dns_file = DNS_CACHE_FILE.with_suffix('.tmp')
        async with aiofiles.open(temp_dns_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(DNS_CACHE))
        temp_dns_file.rename(DNS_CACHE_FILE) # 重命名临时文件，完成原子写入
        logger.info(f"DNS 缓存已保存到 {DNS_CACHE_FILE}")
    except Exception as e:
        logger.error(f"保存缓存失败: {e}")

async def read_urls_from_file(file_path):
    """
    从指定文件中读取 URL 列表，并对没有 http:// 或 https:// 前缀的 URL 自动补全 http://。
    """
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'): # 忽略空行和注释行
                    if not (line.startswith('http://') or line.startswith('https://')):
                        urls.append(f'http://{line}') # 补全 http://
                    else:
                        urls.append(line)
        logger.info(f"从 {file_path} 读取了 {len(urls)} 个 URL")
    except FileNotFoundError:
        logger.error(f"文件未找到: {file_path}")
    return urls

def decode_base64(data):
    """
    安全地进行 Base64 解码。
    处理可能存在的填充问题和解码错误。
    """
    try:
        # 补齐 Base64 字符串的填充字符 '='
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        logger.warning(f"Base64 解码失败: {e}")
        return None

def parse_nodes_from_content(content):
    """
    从网页内容中解析各种代理节点链接（如 hysteria2, vmess, trojan, ss, ssr, vless）。
    尝试从原始内容、Base64 解码后的内容、YAML、JSON 和 HTML 中提取。
    """
    nodes = []
    if not content:
        return nodes

    # 定义各种代理协议的正则表达式模式
    node_patterns = {
        "hysteria2": r"hysteria2:\/\/[\w\-\.]+:\d+[^ \t\n\r]*",
        "vmess": r"vmess:\/\/[a-zA-Z0-9=+/]+",
        "trojan": r"trojan:\/\/[^@]+@[\w\.-]+:\d+[^ \t\n\r]*",
        "ss": r"ss:\/\/[a-zA-Z0-9=+/]+",
        "ssr": r"ssr:\/\/[a-zA-Z0-9=+/]+",
        "vless": r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+[^ \t\n\r]*",
    }

    # 1. 直接从原始内容中查找节点
    for proto, pattern in node_patterns.items():
        nodes.extend(re.findall(pattern, content, re.IGNORECASE))

    # 2. 尝试 Base64 解码后查找节点（常见于订阅链接的 Base64 编码）
    decoded_content = decode_base64(content)
    if decoded_content:
        for proto, pattern in node_patterns.items():
            nodes.extend(re.findall(pattern, decoded_content, re.IGNORECASE))

    # 3. 尝试 YAML 解析（常见于 Clash 配置文件）
    try:
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and "proxies" in parsed_yaml:
            for proxy in parsed_yaml["proxies"]:
                if isinstance(proxy, str): # 如果代理是字符串形式
                    for proto, pattern in node_patterns.items():
                        if re.match(pattern, proxy, re.IGNORECASE):
                            nodes.append(proxy)
                elif isinstance(proxy, dict) and "type" in proxy: # 如果代理是字典形式
                    # 检查字典中所有字符串值，看是否有匹配的节点
                    for k, v in proxy.items():
                        if isinstance(v, str):
                            for proto, pattern in node_patterns.items():
                                if re.match(pattern, v, re.IGNORECASE):
                                    nodes.append(v)
    except yaml.YAMLError:
        logger.debug("内容不是有效的 YAML 格式")

    # 4. 尝试 JSON 解析
    try:
        parsed_json = json.loads(content)
        # 递归查找 JSON 对象或数组中的所有字符串值
        def find_nodes_in_json(obj):
            found_nodes = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        for proto, pattern in node_patterns.items():
                            if re.match(pattern, v, re.IGNORECASE):
                                found_nodes.append(v)
                    elif isinstance(v, (dict, list)): # 递归处理嵌套结构
                        found_nodes.extend(find_nodes_in_json(v))
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str):
                        for proto, pattern in node_patterns.items():
                            if re.match(pattern, item, re.IGNORECASE):
                                found_nodes.append(item)
                    elif isinstance(item, (dict, list)): # 递归处理嵌套结构
                        found_nodes.extend(find_nodes_in_json(item))
            return found_nodes
        nodes.extend(find_nodes_in_json(parsed_json))
    except json.JSONDecodeError:
        logger.debug("内容不是有效的 JSON 格式")

    # 5. 尝试 HTML 解析（从文本内容和特定标签中查找）
    if any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html']):
        soup = BeautifulSoup(content, 'html.parser')
        # 从整个文本内容中查找
        text_content = soup.get_text()
        for proto, pattern in node_patterns.items():
            nodes.extend(re.findall(pattern, text_content, re.IGNORECASE))
        # 从特定标签（如 <pre>, <code>, <textarea>）中查找，这些标签常用于存放代码或纯文本
        for tag in soup.find_all(['pre', 'code', 'textarea', 'div', 'p']):
            block_content = tag.get_text()
            for proto, pattern in node_patterns.items():
                nodes.extend(re.findall(pattern, block_content, re.IGNORECASE))

    return list(set(nodes)) # 返回去重后的节点列表

# --- 节点协议格式验证函数 ---
# 这些函数仅检查节点字符串是否符合对应协议的基本格式要求。

async def validate_hysteria2(node):
    """验证 Hysteria2 节点格式。"""
    return bool(re.match(r"hysteria2:\/\/[\w\-\.]+:\d+[^ \t\n\r]*", node))

async def validate_vmess(node):
    """验证 VMess 节点格式（包括 Base64 解码和 JSON 结构）。"""
    try:
        encoded_part = node[len("vmess://"):]
        decoded_json_str = decode_base64(encoded_part)
        if not decoded_json_str:
            return False
        vmess_config = json.loads(decoded_json_str)
        # 检查 VMess 配置中必须存在的关键字段
        return all(k in vmess_config for k in ["add", "port", "id", "aid", "net", "type"])
    except Exception:
        return False

async def validate_trojan(node):
    """验证 Trojan 节点格式。"""
    return bool(re.match(r"trojan:\/\/[^@]+@[\w\.-]+:\d+[^ \t\n\r]*", node))

async def validate_ss(node):
    """验证 Shadowsocks (SS) 节点格式。"""
    try:
        encoded_part = node[len("ss://"):]
        decoded_str = decode_base64(encoded_part)
        # SS 节点通常是 base64(method:password@server:port) 或 base64(user:pass@server:port)
        return decoded_str and '@' in decoded_str and ':' in decoded_str
    except Exception:
        return False

async def validate_ssr(node):
    """验证 ShadowsocksR (SSR) 节点格式。"""
    try:
        encoded_part = node[len("ssr://"):]
        decoded_str = decode_base64(encoded_part)
        # SSR 节点有多个字段，通常用冒号分隔
        return decoded_str and len(decoded_str.split(':')) >= 6
    except Exception:
        return False

async def validate_vless(node):
    """验证 VLESS 节点格式（UUID 和地址部分）。"""
    return bool(re.match(r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+[^ \t\n\r]*", node))

# --- 节点验证和处理 ---

async def _validate_node_concurrent(node, resolver, semaphore):
    """
    并发控制下的节点验证包装器，用于限制同时进行的验证任务。
    """
    async with semaphore: # 获取信号量，限制并发
        return await validate_node(node, resolver)

async def validate_node(node, resolver):
    """
    验证单个节点的有效性，包括格式检查和 DNS 可达性。
    DNS 查询会使用缓存，并根据 TTL 或默认过期时间判断是否重新查询。
    """
    if not node:
        return False
    try:
        # 提取协议类型、主机名和端口
        node_type = node.split('://')[0].lower()
        parsed = urlparse(node)
        hostname = parsed.hostname
        port = parsed.port
        if not (hostname and port):
            logger.debug(f"节点缺少主机或端口: {node}")
            return False

        # DNS 缓存检查
        now = datetime.datetime.now().timestamp()
        if hostname in DNS_CACHE:
            # 计算缓存有效期（使用实际 TTL 或默认缓存时间，取最小值）
            cached_ttl = DNS_CACHE[hostname].get("ttl", CACHE_EXPIRY_HOURS * 3600)
            cache_expiry_threshold = DNS_CACHE[hostname]["timestamp"] + min(cached_ttl, CACHE_EXPIRY_HOURS * 3600)

            if now < cache_expiry_threshold:
                logger.debug(f"DNS 缓存命中: {hostname} -> {DNS_CACHE[hostname]['ips']} (有效期至: {datetime.datetime.fromtimestamp(cache_expiry_threshold)})")
                return bool(DNS_CACHE[hostname]["ips"]) # 如果有IP地址，则认为可达

        # DNS 解析（如果缓存未命中或已过期）
        try:
            # 使用 aiodns 进行异步 DNS A 记录查询
            result = await resolver.query(hostname, 'A')
            if not result:
                logger.debug(f"DNS 解析失败 for {hostname} in node {node}")
                # 即使解析失败，也缓存一个空结果，避免短时间内重复查询失败的主机
                DNS_CACHE[hostname] = {
                    "ips": [],
                    "timestamp": now,
                    "ttl": result[0].ttl if result else 300 # 失败记录给一个较短的TTL，以便尽快重试
                }
                return False
            
            ips = [r.host for r in result]
            # 缓存 DNS 解析结果，包括时间戳和 TTL
            DNS_CACHE[hostname] = {
                "ips": ips,
                "timestamp": now,
                "ttl": result[0].ttl if result else 3600 # 默认给一个 TTL，如果DNS响应没有提供
            }
            logger.debug(f"DNS 解析成功: {hostname} -> {ips}")
        except Exception as e:
            logger.debug(f"DNS 解析失败 for {hostname} in node {node}: {e}")
            # 记录 DNS 解析失败
            DNS_CACHE[hostname] = {
                "ips": [],
                "timestamp": now,
                "ttl": 300 # 失败记录给一个较短的TTL，以便尽快重试
            }
            return False

        # 协议格式验证
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
        return await validator(node) # 调用对应协议的验证函数
    except Exception as e:
        logger.debug(f"节点验证失败 for {node}: {e}")
        return False

def rename_node(node):
    """
    对节点名称进行简化，只保留前5个字符，以保护隐私或使名称更简洁。
    目前主要针对 VMess 和 URL 片段（#后面的名称）进行处理。
    """
    parsed_url = urlparse(node)
    if node.startswith("vmess://"):
        try:
            encoded_part = node[len("vmess://"):]
            decoded_json_str = decode_base64(encoded_part)
            if decoded_json_str:
                vmess_config = json.loads(decoded_json_str)
                name = vmess_config.get("ps", "") # 获取 VMess 的备注/名称
                if len(name) > 5:
                    vmess_config["ps"] = name[:5] # 截断名称
                    new_encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode()
                    return f"vmess://{new_encoded}"
        except:
            pass # 解码或解析失败则不处理
    elif parsed_url.fragment and len(parsed_url.fragment) > 5:
        # 如果 URL 的片段部分（#号后的内容，常作为节点名称）长度超过5，则截断
        new_parsed_url = parsed_url._replace(fragment=parsed_url.fragment[:5])
        return urlunparse(new_parsed_url)
    return node # 如果不符合上述条件，返回原节点

async def fetch_url_content(client, url):
    """
    安全地异步获取 URL 的内容。
    包括缓存检查、HTTP/HTTPS 自动重试机制（仅一次）。
    """
    # 检查 URL 是否在缓存中且未过期
    if url in PROCESSED_URLS_CACHE:
        cache_entry = PROCESSED_URLS_CACHE[url]
        if (datetime.datetime.now().timestamp() - cache_entry["timestamp"]) < CACHE_EXPIRY_HOURS * 3600:
            logger.info(f"URL {url} 在缓存中，跳过抓取")
            return None # 从缓存中加载则不返回内容，表示无需重新处理

    # 确保 URL 有协议头
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url_to_fetch = f"http://{url}"
    else:
        url_to_fetch = url

    headers = get_random_headers() # 获取随机请求头
    try:
        # 第一次请求
        response = await client.get(url_to_fetch, headers=headers, timeout=15) # 设置超时为 15 秒
        response.raise_for_status() # 检查 HTTP 状态码，非 2xx 会抛出异常
        content = response.text
        # 将抓取到的内容及其哈希、时间戳存入缓存
        PROCESSED_URLS_CACHE[url] = {
            "hash": hashlib.sha256(content.encode('utf-8')).hexdigest(),
            "timestamp": datetime.datetime.now().timestamp()
        }
        return content
    except httpx.RequestError as e:
        logger.warning(f"初次请求 URL 时发生错误: {url_to_fetch} - {e}")
        # 如果是 HTTP 请求失败，尝试用 HTTPS 重试一次
        if url_to_fetch.startswith("http://"):
            https_url = url_to_fetch.replace("http://", "https://", 1)
            try:
                logger.info(f"尝试使用 HTTPS 重试: {https_url}")
                response = await client.get(https_url, headers=headers, timeout=15) # 设置超时为 15 秒
                response.raise_for_status()
                content = response.text
                PROCESSED_URLS_CACHE[url] = {
                    "hash": hashlib.sha256(content.encode('utf-8')).hexdigest(),
                    "timestamp": datetime.datetime.now().timestamp()
                }
                return content
            except httpx.RequestError as https_e:
                logger.error(f"HTTP 和 HTTPS 尝试 URL 时均发生错误: {url} - {https_e}")
                raise # 两次尝试都失败，则向上抛出异常
        raise # 如果不是 http URL 失败，或者 HTTPS 也失败，则抛出异常

async def process_url(client, url, semaphore, resolver):
    """
    处理单个 URL 的完整流程：抓取内容，解析节点，并保存解析到的节点到独立文件和临时文件。
    该函数在并发限制下运行。
    """
    node_count = 0
    error_message = None
    async with semaphore: # 获取信号量，限制并发数
        try:
            logger.info(f"开始处理 URL: {url}")
            content = await fetch_url_content(client, url) # 抓取 URL 内容
            if content:
                nodes = parse_nodes_from_content(content) # 从内容中解析节点
                node_count = len(nodes)
                
                # 获取域名作为文件名
                parsed_url = urlparse(url)
                domain_name = parsed_url.hostname if parsed_url.hostname else re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
                url_nodes_file = DATA_DIR / f"{domain_name}.txt"
                
                if nodes:
                    async with aiofiles.open(url_nodes_file, 'w', encoding='utf-8') as f:
                        for node in nodes:
                            await f.write(node + '\n')
                    logger.info(f"URL {url} 解析到的 {node_count} 个节点已保存到 {url_nodes_file}")
                    
                    # 将解析到的原始节点追加写入临时文件，供后续统一验证
                    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'a', encoding='utf-8') as f:
                        for node in nodes:
                            await f.write(node + '\n')
                else:
                    # 如果没有解析到节点，也创建空文件或删除旧文件，表示该URL无节点
                    if url_nodes_file.exists():
                        url_nodes_file.unlink()
                    logger.info(f"URL {url} 未解析到任何节点，未创建/清空独立节点文件。")

            else:
                logger.info(f"URL {url} 未返回内容或从缓存加载 (无需重新解析)")
        except Exception as e:
            logger.error(f"处理 URL {url} 时发生错误: {e}")
            error_message = str(e)
    return url, node_count, error_message # 返回 URL、节点数量和错误信息

async def validate_and_save_nodes(resolver):
    """
    从临时文件中读取所有原始节点，并行验证其有效性（格式和DNS可达性），
    然后保存去重后的有效节点到最终文件，并统计各协议的节点数量。
    """
    raw_nodes_to_validate = []
    if not RAW_FETCHED_NODES_TEMP_FILE.exists():
        logger.warning(f"临时节点文件 {RAW_FETCHED_NODES_TEMP_FILE} 不存在，跳过验证")
        return []

    # 从临时文件中读取所有待验证的原始节点
    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'r', encoding='utf-8') as f:
        async for node_line in f:
            raw_nodes_to_validate.append(node_line.strip())
    
    # 并行验证所有节点
    validation_semaphore = asyncio.Semaphore(NODE_VALIDATION_CONCURRENCY_LIMIT) # 节点验证并发信号量
    validation_tasks = []
    for node in raw_nodes_to_validate:
        # 为每个节点创建验证任务
        validation_tasks.append(_validate_node_concurrent(node, resolver, validation_semaphore))
    
    # 等待所有验证任务完成
    validated_results = await asyncio.gather(*validation_tasks)

    validated_nodes_with_protocols = [] # 存储通过验证的节点（可能已重命名）
    protocol_counts = Counter() # 统计所有原始节点的协议类型
    valid_protocol_counts = Counter() # 统计有效节点的协议类型

    # 遍历验证结果，进行统计和处理
    for i, is_valid in enumerate(validated_results):
        node = raw_nodes_to_validate[i]
        protocol = node.split('://')[0].lower() if '://' in node else 'unknown'
        protocol_counts[protocol] += 1 # 统计原始协议数量
        if is_valid:
            validated_nodes_with_protocols.append(rename_node(node)) # 如果有效，则重命名并添加
            valid_protocol_counts[protocol] += 1 # 统计有效协议数量

    unique_nodes = list(set(validated_nodes_with_protocols)) # 对有效节点进行最终去重

    # 保存最终的有效节点到 all.txt
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(node + '\n')

    # 保存协议统计到 CSV 文件
    with open(PROTOCOL_STATS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Protocol', 'Total Count', 'Valid Count'])
        for proto in protocol_counts:
            writer.writerow([proto, protocol_counts[proto], valid_protocol_counts.get(proto, 0)])
    logger.info(f"协议统计已保存到 {PROTOCOL_STATS_CSV}")

    return unique_nodes # 返回最终的有效节点列表

# --- 主执行函数 ---

async def main():
    """
    脚本的主入口点， orchestrates 整个抓取和验证流程。
    """
    logger.info("开始执行代理抓取任务")
    await load_cache() # 加载历史缓存数据

    urls = await read_urls_from_file('sources.list') # 从 sources.list 读取所有待抓取 URL
    if not urls:
        logger.warning("未找到任何 URL，程序退出")
        return

    # 清空之前的输出文件和临时文件，确保每次运行都是新的结果
    if ALL_NODES_FILE.exists():
        ALL_NODES_FILE.unlink()
    if RAW_FETCHED_NODES_TEMP_FILE.exists():
        RAW_FETCHED_NODES_TEMP_FILE.unlink()
    # 注意：这里不再清空每个 URL 对应的 .txt 文件，因为它们现在包含的是处理后的节点而非原始网页内容。
    # 如果需要完全清空，可以在这里增加删除 DATA_DIR 中所有 .txt 文件的逻辑，但请谨慎。

    node_counts_data = [] # 存储每个 URL 的节点抓取数量
    url_fetch_semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) # URL 抓取并发信号量

    # 初始化 DNS 解析器，指定超时和公共 DNS 服务器
    resolver = aiodns.DNSResolver(timeout=5, nameservers=['8.8.8.8', '1.1.1.1'])

    # 使用 httpx.AsyncClient 创建异步 HTTP 客户端
    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        # 为每个 URL 创建处理任务
        tasks = [process_url(client, url, url_fetch_semaphore, resolver) for url in urls]
        # 并行运行所有 URL 处理任务，并捕获异常
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理每个 URL 任务的结果
        for result in results:
            if isinstance(result, tuple):
                url, node_count, _ = result
                node_counts_data.append({"url": url, "node_count": node_count})
            else:
                logger.error(f"处理 URL 时发生异常 (任务级别): {result}")

    # 验证并保存所有抓取到的节点
    unique_nodes = await validate_and_save_nodes(resolver)
    logger.info(f"所有 {len(unique_nodes)} 个唯一有效节点已保存到 {ALL_NODES_FILE}")

    # 将每个 URL 的节点数量统计保存到 CSV 文件
    with open(NODE_COUNTS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url', 'node_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader() # 写入 CSV 头
        writer.writerows(node_counts_data) # 写入数据行
    logger.info(f"节点统计已保存到 {NODE_COUNTS_CSV}")

    await save_cache() # 保存所有缓存数据
    logger.info("代理抓取任务完成")

# --- 脚本入口点 ---
if __name__ == "__main__":
    asyncio.run(main()) # 运行主异步函数
