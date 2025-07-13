import httpx
import asyncio
import re
import os
import aiofiles
import aiofiles.threadpool.text
import json
import yaml
import base64
from collections import defaultdict
import datetime
import hashlib
from bs4 import BeautifulSoup
import logging
import typing
import uuid

# 配置日志，同时输出到控制台和文件
# 设置日志级别为 INFO，格式包含时间、级别和消息
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        # 将日志输出到 data/proxy_scraper.log 文件
        logging.FileHandler(os.path.join('data', 'proxy_scraper.log')),
        # 将日志输出到控制台
        logging.StreamHandler()
    ]
)

# 定义数据和缓存目录
DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt") # 所有提取到的节点将写入此文件
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv") # 统计每个源的节点数量
CACHE_DIR = os.path.join(DATA_DIR, "cache") # 缓存目录，用于存储已抓取内容的哈希值
CACHE_EXPIRATION_HOURS = 48  # 缓存过期时间（小时），超过此时间将重新抓取
CLEANUP_THRESHOLD_HOURS = 72  # 缓存清理阈值（小时），超过此时间的文件将被删除

# HTTPX 客户端的并发连接限制和超时设置
CONCURRENCY_LIMIT = 50  # 同时进行的并发请求数量
# 更细致的 httpx 超时设置：连接超时5秒，读取超时10秒
HTTPX_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# 确保数据目录和缓存目录存在，如果不存在则创建
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的协议和正则表达式
PROTOCOL_PATTERNS = {
    # VLESS 协议匹配
    "vless": r"(vless://[^\"'#\s]+)",
    # Trojan 协议匹配
    "trojan": r"(trojan://[^\"'#\s]+)",
    # Shadowsocks 协议匹配
    "ss": r"(ss://[^\"'#\s]+)",
    # VMess 协议匹配 (base64 编码)
    "vmess": r"(vmess://[a-zA-Z0-9+/=]+)",
    # Clash 配置中的 proxy 节点匹配
    "clash_proxies": r"(proxies:\s*-\s*(?:name:[^\n]+\s*type:[^\n]+\s*server:[^\n]+\s*port:[^\n]+(?:\s*uuid:[^\n]+)?(?:\s*password:[^\n]+)?(?:\s*cipher:[^\n]+)?(?:\s*tls:[^\n]+)?(?:\s*udp:[^\n]+)?(?:\s*skip-cert-verify:[^\n]+)?(?:\s*network:[^\n]+)?(?:\s*ws-opts:[^\n]+)?(?:\s*grpc-opts:[^\n]+)?\s*)*)"
}

# 忽略的 URL 关键词，用于过滤掉不相关的 URL
IGNORE_URL_KEYWORDS = [
    "example.com", "your-site.com", "cdn-cgi/trace",
    "http://www.cloudflare.com/cdn-cgi/trace",
    "http://test.com/v1/api",
    "https://test.com/v1/api",
    "127.0.0.1", "localhost", "0.0.0.0",
    "http://ip.sb/json", # 特定IP查询服务，不包含代理节点
    "http://ip-api.com/json", # 同上
    "http://ipv4.icanhazip.com", # 同上
    "http://myexternalip.com/raw", # 同上
    "http://ipecho.net/plain", # 同上
    "https://api.ipify.org?format=json" # 同上
]

# 用于生成唯一 ID 的字典，避免重复的文件名
uuid_map = {}

# region 辅助函数

def generate_unique_id(content):
    """
    根据内容生成一个唯一的哈希 ID。
    用于文件名和缓存键。
    """
    # 使用 SHA256 算法计算内容的哈希值
    hash_object = hashlib.sha256(content.encode('utf-8'))
    unique_id = hash_object.hexdigest()
    return unique_id

def get_file_path(unique_id):
    """
    根据唯一 ID 获取缓存文件的完整路径。
    """
    return os.path.join(CACHE_DIR, f"{unique_id}.json")

async def read_cache(unique_id):
    """
    从缓存文件中读取数据，如果缓存过期则返回 None。
    """
    file_path = get_file_path(unique_id)
    if os.path.exists(file_path):
        # 检查文件修改时间是否过期
        mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
        if datetime.datetime.now() - mod_time < datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                return json.loads(content)
    return None

async def write_cache(unique_id, data):
    """
    将数据写入缓存文件。
    """
    file_path = get_file_path(unique_id)
    async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(data))

def cleanup_old_cache_files():
    """
    清理过期的缓存文件。
    """
    logging.info("开始清理旧的缓存文件...")
    now = datetime.datetime.now()
    # 遍历缓存目录中的所有文件
    for filename in os.listdir(CACHE_DIR):
        file_path = os.path.join(CACHE_DIR, filename)
        if os.path.isfile(file_path):
            mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
            # 如果文件修改时间超过清理阈值，则删除
            if now - mod_time > datetime.timedelta(hours=CLEANUP_THRESHOLD_HOURS):
                try:
                    os.remove(file_path)
                    logging.info(f"已清理旧的缓存文件: {filename}")
                except OSError as e:
                    logging.error(f"清理缓存文件失败 {filename}: {e}")
    logging.info("旧的缓存文件清理完成。")

# endregion

# region 网络请求函数

async def _fetch_url_with_retry(client: httpx.AsyncClient, url: str, original_protocol_url: typing.Optional[str] = None, attempt_ssl_verify_false: bool = False):
    """
    尝试抓取 URL，处理 SSL 错误并尝试 HTTP 到 HTTPS 的回退。
    Args:
        client: httpx.AsyncClient 实例，用于发送 HTTP 请求。
        url: 当前要抓取的 URL。
        original_protocol_url: 原始请求的 URL（用于 HTTP 到 HTTPS 回退的判断）。
        attempt_ssl_verify_false: 是否尝试禁用 SSL 验证。
    Returns:
        httpx.Response 对象或 None。
    """
    try:
        if attempt_ssl_verify_false:
            logging.info(f"正在尝试禁用 SSL 验证获取: {url}")
            return await client.get(url, follow_redirects=True, verify=False)
        else:
            return await client.get(url, follow_redirects=True)
    except httpx.RequestError as e:
        # 如果是 SSL 连接错误，且未尝试禁用 SSL 验证，则进行重试
        if isinstance(e, httpx.ConnectError) and "SSL" in str(e):
            if not attempt_ssl_verify_false:
                logging.warning(f"SSL 连接错误，尝试禁用 SSL 验证: {url}")
                return await _fetch_url_with_retry(client, url, original_protocol_url, attempt_ssl_verify_false=True)
            else:
                logging.error(f"禁用 SSL 验证后仍无法连接到 {url}: {type(e).__name__} - {e}")
                return None
        # 如果是 HTTP 请求失败，且原始请求也是 HTTP，则尝试 HTTPS
        elif url.startswith("http://") and (original_protocol_url is None or original_protocol_url.startswith("http://")):
            https_url = "https://" + url[len("http://"):]
            logging.warning(f"HTTP 请求失败 ({url})，尝试 HTTPS: {https_url}")
            # 递归调用，尝试 HTTPS，并保持原始 HTTP URL 作为原始协议URL
            return await _fetch_url_with_retry(client, https_url, url)
        else:
            # 记录其他类型的请求失败
            logging.error(f"请求 {url} 失败: {type(e).__name__} - {e}")
            return None

async def fetch_url_content(client: httpx.AsyncClient, url: str):
    """
    抓取 URL 内容，并处理一些常见的编码问题。
    Args:
        client: httpx.AsyncClient 实例。
        url: 要抓取的 URL。
    Returns:
        抓取到的文本内容，如果失败则返回 None。
    """
    if any(keyword in url for keyword in IGNORE_URL_KEYWORDS):
        logging.info(f"URL 包含忽略关键词，跳过: {url}")
        return None

    try:
        response = await _fetch_url_with_retry(client, url)
        if response and response.status_code == 200:
            # 尝试根据响应头判断编码，否则使用 utf-8 或 latin-1
            content_type = response.headers.get("Content-Type", "")
            if "charset=" in content_type:
                charset = content_type.split("charset=")[-1].strip()
                try:
                    return response.content.decode(charset)
                except UnicodeDecodeError:
                    logging.warning(f"使用 {charset} 解码失败，尝试 utf-8 或 latin-1: {url}")
            
            try:
                return response.content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return response.content.decode('latin-1')
                except UnicodeDecodeError:
                    logging.error(f"无法解码 URL {url} 的内容。")
                    return None
        else:
            status_code = response.status_code if response else '无响应'
            logging.warning(f"无法获取 URL 内容 {url}: 状态码 {status_code}")
            return None
    except Exception as e:
        logging.error(f"抓取 URL {url} 时发生意外错误: {type(e).__name__} - {e}")
        return None

# endregion

# region 节点解析函数

def extract_nodes_from_content(content):
    """
    从内容中提取各种协议的节点。
    Args:
        content: 抓取到的文本内容。
    Returns:
        包含所有提取到的节点的列表。
    """
    nodes = []
    # 尝试解析为 YAML (Clash 配置)
    try:
        # 尝试使用 BeautifulSoup 解析 HTML，提取 pre 或 code 标签内的文本
        soup = BeautifulSoup(content, 'html.parser')
        # 查找 pre 或 code 标签内的文本
        pre_tags = soup.find_all(['pre', 'code'])
        if pre_tags:
            content_from_html = '\n'.join([tag.get_text() for tag in pre_tags])
            # 尝试再次解析这个提取出的文本
            return extract_nodes_from_content(content_from_html)
            
        # 如果不是 HTML，尝试解析为 YAML
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and "proxies" in parsed_yaml:
            for proxy in parsed_yaml["proxies"]:
                # 将 Clash 代理字典转换为 JSON 字符串格式以便存储
                nodes.append(f"clash_proxy://{json.dumps(proxy)}")
            logging.info(f"从 Clash YAML 中提取了 {len(parsed_yaml['proxies'])} 个代理节点。")
            return nodes
    except yaml.YAMLError:
        pass # 不是有效的 YAML，继续尝试其他解析方式

    # 如果是 Base64 编码的内容，尝试解码
    try:
        decoded_content = base64.b64decode(content).decode('utf-8')
        # 递归调用自身，处理解码后的内容
        return extract_nodes_from_content(decoded_content)
    except (base64.binascii.Error, UnicodeDecodeError):
        pass # 不是有效的 Base64，继续

    # 遍历所有已定义的协议模式进行匹配
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        if protocol == "clash_proxies":
            # 对于 clash_proxies，我们已经尝试通过 yaml.safe_load 处理了，
            # 这里是备用方案，可能不完美，但可以捕获文本形式的 proxies 块
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                try:
                    # 尝试再次解析提取出的 YAML 片段
                    proxy_block = yaml.safe_load(match)
                    if isinstance(proxy_block, dict) and "proxies" in proxy_block:
                        for proxy in proxy_block["proxies"]:
                            nodes.append(f"clash_proxy://{json.dumps(proxy)}")
                    elif isinstance(proxy_block, list): # 有些可能是直接的代理列表
                        for proxy in proxy_block:
                            if isinstance(proxy, dict) and "name" in proxy: # 简单判断是否为代理节点
                                nodes.append(f"clash_proxy://{json.dumps(proxy)}")
                except yaml.YAMLError:
                    pass # 非法 YAML 片段，跳过
        else:
            # 对于其他协议，直接使用正则表达式匹配
            matches = re.findall(pattern, content)
            nodes.extend(matches)

    return nodes

# endregion

# region 主要处理逻辑

async def process_url(url: str, all_nodes_writer: aiofiles.threadpool.text.AsyncTextIOWrapper, semaphore: asyncio.Semaphore, client: httpx.AsyncClient):
    """
    处理单个 URL，包括缓存检查、内容抓取、节点提取和写入文件。
    Args:
        url: 待处理的 URL。
        all_nodes_writer: 写入所有节点的异步文件对象。
        semaphore: 信号量，用于控制并发。
        client: httpx.AsyncClient 实例，用于发送请求。
    Returns:
        元组 (url, 节点数量) 或异常对象。
    """
    async with semaphore: # 获取信号量，控制并发
        logging.info(f"正在处理 URL: {url}")
        content_hash = generate_unique_id(url) # 根据 URL 生成哈希值作为缓存键
        cached_data = await read_cache(content_hash) # 尝试从缓存读取数据

        if cached_data:
            logging.info(f"从缓存加载: {url}")
            # 如果从缓存加载成功，直接写入节点并返回数量
            nodes = cached_data.get("nodes", [])
            for node in nodes:
                await all_nodes_writer.write(node + '\n')
            return (url, len(nodes))
        else:
            logging.info(f"缓存未命中或已过期，抓取: {url}")
            # 抓取 URL 内容
            content = await fetch_url_content(client, url)

            if content:
                # 提取节点
                nodes = extract_nodes_from_content(content)
                nodes_count = len(nodes)
                logging.info(f"从 {url} 提取了 {nodes_count} 个节点。")

                # 将提取到的节点写入缓存
                await write_cache(content_hash, {"nodes": nodes})

                # 将节点写入 all.txt 文件
                for node in nodes:
                    await all_nodes_writer.write(node + '\n')
                return (url, nodes_count)
            else:
                return (url, 0) # 未抓取到内容或无节点

async def load_sources_from_file(file_path):
    """
    从 sources.list.txt 文件加载 URL。
    Args:
        file_path: sources.list.txt 的路径。
    Returns:
        包含处理过的 URL 的列表。
    """
    logging.info(f"从 {file_path} 加载源...")
    urls = []
    # 使用 set 来自动处理 URL 去重
    processed_urls_set = set()
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue # 跳过空行和注释行

                url = line
                # 检查 URL 是否包含协议，如果没有则尝试添加 http 和 https
                if not re.match(r"^[a-zA-Z]+://", url):
                    logging.info(f"URL '{url}' 没有指定协议，尝试添加 http:// 和 https://")
                    processed_urls_set.add(f"http://{url}")
                    processed_urls_set.add(f"https://{url}")
                else:
                    processed_urls_set.add(url)
        logging.info(f"从 {file_path} 加载了 {len(processed_urls_set)} 个源 URL。")
        return list(processed_urls_set) # 转换为列表以便后续迭代

    except FileNotFoundError:
        logging.error(f"错误: 找不到 sources.list 文件在 {file_path}")
        return []
    except Exception as e:
        logging.error(f"加载 sources.list 文件时发生错误: {type(e).__name__} - {e}")
        return []

async def main():
    """
    主函数，协调整个抓取和处理流程。
    """
    logging.info("代理节点抓取脚本启动。")

    # 清理旧的缓存文件
    cleanup_old_cache_files()

    # 从 sources.list.txt 加载 URL 列表
    sources_file_path = "sources.list.txt"
    processed_urls = await load_sources_from_file(sources_file_path)

    if not processed_urls:
        logging.warning("sources.list 中没有找到有效的 URL，脚本结束。")
        return

    node_counts = defaultdict(int) # 用于统计每个源抓取到的节点数量
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) # 创建信号量，控制并发请求数量

    # 确保 all.txt 在开始处理前是空的，如果文件存在则清空
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        await f.truncate(0) # 清空文件内容

    # 在这里创建并复用 httpx.AsyncClient 实例，它将处理所有并发请求
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        # 为每个 URL 创建异步任务
        tasks = [process_url(url, all_nodes_writer, semaphore, client) for url in processed_urls]
        # 使用 aiofiles.open 上下文管理器确保文件在所有任务完成后被正确关闭
        async with aiofiles.open(ALL_NODES_FILE, 'a', encoding='utf-8') as all_nodes_writer:
            # 并发执行所有任务，并收集结果或异常
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, tuple):
                    url, count = result
                    node_counts[url] = count
                else:
                    # 记录处理 URL 时发生的异常
                    logging.error(f"处理 URL 任务时发生未知异常: {result}")

    try:
        # 将每个源抓取到的节点数量写入 CSV 文件
        async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8', newline='') as f:
            await f.write("URL,NodeCount\n") # 写入 CSV 头
            for url, count in node_counts.items():
                await f.write(f"{url},{count}\n") # 写入每行的 URL 和节点数量
        logging.info(f"节点统计信息已写入 {NODE_COUNT_CSV}")
    except Exception as e:
        logging.error(f"写入节点统计 CSV 文件失败: {type(e).__name__} - {e}")

    logging.info("代理节点抓取脚本执行完毕。")

if __name__ == "__main__":
    # 运行主异步函数
    asyncio.run(main())
