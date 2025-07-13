import httpx
import asyncio
import re
import base64
import yaml
import json
import os
import csv
import random
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from collections import defaultdict
from bs4 import BeautifulSoup
import aiofiles
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 数据保存路径
DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNTS_CSV = os.path.join(DATA_DIR, "node_counts.csv")
RAW_FETCHED_NODES_TEMP_FILE = os.path.join(DATA_DIR, "raw_fetched_nodes_temp.txt")

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 缓存机制：存储已处理的 URL 及其内容哈希，避免重复抓取
PROCESSED_URLS_CACHE = {} # {url: content_hash}

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
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }

async def read_urls_from_file(file_path):
    """从文件中读取 URL 列表，并补全 http/https 前缀"""
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not (line.startswith('http://') or line.startswith('https://')):
                        # 优先尝试 http
                        urls.append(f'http://{line}')
                        # 也添加 https 作为备用，在抓取时处理优先级
                        #urls.append(f'https://{line}')
                    else:
                        urls.append(line)
        logger.info(f"从 {file_path} 读取了 {len(urls)} 个 URL。")
    except FileNotFoundError:
        logger.error(f"文件未找到: {file_path}")
    return urls

def decode_base64(data):
    """安全地进行 Base64 解码"""
    try:
        # 尝试标准 Base64 解码
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        try:
            # 尝试 URL 安全的 Base64 解码
            return base64.urlsafe_b64decode(data).decode('utf-8')
        except Exception as e:
            logger.warning(f"Base64 解码失败: {e}")
            return None

def parse_nodes_from_content(content):
    """从网页内容中解析各种节点"""
    nodes = []
    if not content:
        return nodes

    # 1. 常见协议节点 (hysteria2, vmess, trojan, ss, ssr, vless)
    # 增加更多匹配模式以确保捕获所有可能的变体
    # 例如，对于vmess，可能有vmess://{base64_encoded_json} 或 vmess://{uuid}@{host}:{port}
    # 但根据用户要求，vmess通常是base64编码的json
    node_patterns = {
        "hysteria2": r"hysteria2:\/\/[^\s]+",
        "vmess": r"vmess:\/\/[^\s]+",
        "trojan": r"trojan:\/\/[^\s]+",
        "ss": r"ss:\/\/[^\s]+",
        "ssr": r"ssr:\/\/[^\s]+",
        "vless": r"vless:\/\/[^\s]+",
    }

    for proto, pattern in node_patterns.items():
        found = re.findall(pattern, content, re.IGNORECASE)
        nodes.extend(found)

    # 2. Base64 解码内容
    try:
        decoded_content = decode_base64(content)
        if decoded_content:
            for proto, pattern in node_patterns.items():
                found = re.findall(pattern, decoded_content, re.IGNORECASE)
                nodes.extend(found)
    except Exception as e:
        logger.debug(f"尝试 Base64 解码内容失败: {e}")

    # 3. YAML 或 JSON 格式
    try:
        # 尝试解析 YAML
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and "proxies" in parsed_yaml:
            for proxy in parsed_yaml["proxies"]:
                if isinstance(proxy, str):
                    # 检查是否是直接的节点字符串
                    for proto, pattern in node_patterns.items():
                        if re.match(pattern, proxy, re.IGNORECASE):
                            nodes.append(proxy)
                elif isinstance(proxy, dict) and "type" in proxy:
                    # 尝试从字典中构建节点，这需要更复杂的逻辑，取决于具体字段
                    # 简化处理：如果字段直接包含协议前缀，则添加
                    for k, v in proxy.items():
                        if isinstance(v, str):
                            for proto, pattern in node_patterns.items():
                                if re.match(pattern, v, re.IGNORECASE):
                                    nodes.append(v)
        logger.debug("尝试 YAML 解析成功。")
    except yaml.YAMLError:
        logger.debug("内容不是有效的 YAML 格式。")
    except Exception as e:
        logger.debug(f"YAML 解析时发生其他错误: {e}")

    try:
        # 尝试解析 JSON
        parsed_json = json.loads(content)
        # 这是一个示例，实际可能需要根据 JSON 结构递归查找
        if isinstance(parsed_json, list):
            for item in parsed_json:
                if isinstance(item, str):
                    for proto, pattern in node_patterns.items():
                        if re.match(pattern, item, re.IGNORECASE):
                            nodes.append(item)
                elif isinstance(item, dict):
                    for k, v in item.items():
                        if isinstance(v, str):
                            for proto, pattern in node_patterns.items():
                                if re.match(pattern, v, re.IGNORECASE):
                                    nodes.append(v)
        elif isinstance(parsed_json, dict):
            # 递归查找所有字符串值
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
        logger.debug("尝试 JSON 解析成功。")
    except json.JSONDecodeError:
        logger.debug("内容不是有效的 JSON 格式。")
    except Exception as e:
        logger.debug(f"JSON 解析时发生其他错误: {e}")

    # 4. 明文节点（如果有特定格式，可能需要更多规则）
    # 目前已通过通用协议匹配处理。

    # 5. HTML 内容解析 (模拟浏览器获取，去除其它元素)
    if any(tag in content for tag in ['<html', '<body', '<!DOCTYPE html']): # 粗略判断是否是HTML
        try:
            soup = BeautifulSoup(content, 'html.parser')
            # 提取所有文本内容，然后再次尝试解析节点
            text_content = soup.get_text()
            for proto, pattern in node_patterns.items():
                found = re.findall(pattern, text_content, re.IGNORECASE)
                nodes.extend(found)
            # 尝试查找 <pre> <code> 等标签内的内容
            for code_block in soup.find_all(['pre', 'code', 'textarea']):
                block_content = code_block.get_text()
                for proto, pattern in node_patterns.items():
                    found = re.findall(pattern, block_content, re.IGNORECASE)
                    nodes.extend(found)
            logger.debug("尝试 HTML 解析成功。")
        except Exception as e:
            logger.debug(f"HTML 解析失败: {e}")

    # 去重
    return list(set(nodes))

async def fetch_url_content(client, url, attempts=2):
    """安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS"""
    # 检查缓存
    if url in PROCESSED_URLS_CACHE:
        logger.info(f"URL {url} 已在缓存中，跳过抓取。")
        return None # 返回None表示不需要重新处理

    # 确保 URL 有协议头
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # 如果是 http://example.com 这种形式，但 parsed_url.scheme 为空，说明是解析错误或不完整
        # 尝试默认 http
        url_to_fetch = f"http://{url}"
    else:
        url_to_fetch = url

    # 尝试 HTTP
    current_headers = get_random_headers()
    try:
        logger.info(f"尝试通过 HTTP 获取: {url_to_fetch}")
        response = await client.get(url_to_fetch, headers=current_headers, timeout=10)
        response.raise_for_status()
        content = response.text
        # 更新缓存
        PROCESSED_URLS_CACHE[url] = hash(content)
        return content
    except httpx.RequestError as e:
        logger.warning(f"HTTP 获取 {url_to_fetch} 失败: {e}")
        # 如果是 http 请求失败，尝试 https
        if url_to_fetch.startswith("http://"):
            https_url = url_to_fetch.replace("http://", "https://", 1)
            try:
                logger.info(f"尝试通过 HTTPS 获取: {https_url}")
                response = await client.get(https_url, headers=current_headers, timeout=10)
                response.raise_for_status()
                content = response.text
                # 更新缓存
                PROCESSED_URLS_CACHE[url] = hash(content)
                return content
            except httpx.RequestError as e_https:
                logger.error(f"HTTPS 获取 {https_url} 失败: {e_https}")
                return None
    except Exception as e:
        logger.error(f"获取 {url_to_fetch} 时发生未知错误: {e}")
        return None

def validate_node(node):
    """
    验证节点是否符合官方或常见格式要求。
    这是一个简化的验证示例，实际可能需要更复杂的协议特定解析库。
    """
    if node.startswith("hysteria2://"):
        # 简化验证：确保包含必要的参数，如 hostname 和 port
        if not re.match(r"hysteria2:\/\/[^\/:]+:\d+", node):
            logger.debug(f"Hysteria2 节点格式不符或缺少信息: {node}")
            return False
        # 进一步可以解析并验证 auth, obfs 等
    elif node.startswith("vmess://"):
        # vmess 通常是 base64(json)
        try:
            encoded_part = node[len("vmess://"):]
            decoded_json_str = decode_base64(encoded_part)
            if not decoded_json_str:
                logger.debug(f"VMess 节点 Base64 解码失败: {node}")
                return False
            vmess_config = json.loads(decoded_json_str)
            # 检查关键字段
            if not all(k in vmess_config for k in ["add", "port", "id", "aid", "net", "type"]):
                logger.debug(f"VMess 节点缺少关键字段: {node}")
                return False
        except Exception as e:
            logger.debug(f"VMess 节点解析或验证失败: {e}")
            return False
    elif node.startswith("trojan://"):
        # 简化验证：确保包含密码和地址
        if not re.match(r"trojan:\/\/[^@]+@[\w\.-]+:\d+", node):
            logger.debug(f"Trojan 节点格式不符或缺少信息: {node}")
            return False
    elif node.startswith("ss://"):
        # ss 通常是 base64(method:password@host:port)
        try:
            encoded_part = node[len("ss://"):]
            decoded_str = decode_base64(encoded_part)
            if not decoded_str or '@' not in decoded_str or ':' not in decoded_str:
                logger.debug(f"SS 节点 Base64 解码或格式不符: {node}")
                return False
            # 进一步可以验证 method
        except Exception as e:
            logger.debug(f"SS 节点解析或验证失败: {e}")
            return False
    elif node.startswith("ssr://"):
        # ssr 格式更复杂，通常是 base64(host:port:protocol:method:obfs:password_base64/?params)
        try:
            encoded_part = node[len("ssr://"):]
            decoded_str = decode_base64(encoded_part)
            if not decoded_str:
                logger.debug(f"SSR 节点 Base64 解码失败: {node}")
                return False
            parts = decoded_str.split(':')
            if len(parts) < 6: # host, port, protocol, method, obfs, password
                logger.debug(f"SSR 节点缺少关键部分: {node}")
                return False
            # 进一步可以验证各个字段
        except Exception as e:
            logger.debug(f"SSR 节点解析或验证失败: {e}")
            return False
    elif node.startswith("vless://"):
        # vless 格式通常是 uuid@host:port?params#name
        if not re.match(r"vless:\/\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})@[\w\.-]+:\d+", node):
            logger.debug(f"VLESS 节点格式不符或缺少 UUID/地址/端口: {node}")
            return False
        # 进一步可以解析并验证 params
    else:
        # 未知协议或明文节点，如果未明确指定格式，则默认不验证或需要更通用的验证
        logger.debug(f"未知或不支持的节点协议，跳过严格验证: {node}")
        return True # 对于不明确的协议，暂时通过验证

    return True

def rename_node(node):
    """
    只保留原节点名称前5位，多余的全部删除。
    这里假设节点名称在 # 后面。
    """
    parsed_url = urlparse(node)
    if parsed_url.fragment: # fragment 通常是节点名称
        name = parsed_url.fragment
        if len(name) > 5:
            new_name = name[:5]
            # 重新构建 URL
            new_parsed_url = parsed_url._replace(fragment=new_name)
            return urlunparse(new_parsed_url)
    return node

async def process_url(client, url):
    """处理单个 URL：抓取内容，解析节点，保存结果"""
    logger.info(f"开始处理 URL: {url}")
    content = await fetch_url_content(client, url)

    if content is None:
        logger.warning(f"未能获取 {url} 的内容，跳过处理。")
        return url, 0, []

    # 将每个 URL 获取到的内容单独保存
    safe_filename = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url) # 将非法字符替换为下划线
    url_content_file = os.path.join(DATA_DIR, f"{safe_filename}.txt")
    try:
        async with aiofiles.open(url_content_file, 'w', encoding='utf-8') as f:
            await f.write(content)
        logger.info(f"URL {url} 的内容已保存到 {url_content_file}")
    except Exception as e:
        logger.error(f"保存 {url} 内容到文件失败: {e}")

    # 解析节点
    raw_nodes = parse_nodes_from_content(content)
    logger.info(f"从 {url} 中解析出 {len(raw_nodes)} 个原始节点。")

    # 将原始节点先保存到临时文件
    async with aiofiles.open(RAW_FETCHED_NODES_TEMP_FILE, 'a', encoding='utf-8') as f:
        for node in raw_nodes:
            await f.write(node + '\n')

    # 从临时文件读取并进行验证和重命名
    # 注意：这里为了简化示例，直接使用 raw_nodes，但在实际中，可能需要一个单独的步骤来读取和处理大文件
    validated_and_renamed_nodes = []
    for node in raw_nodes: # 理论上这里应该从文件读取，但为了流程连贯性，直接用内存中的
        if validate_node(node):
            renamed_node = rename_node(node)
            validated_and_renamed_nodes.append(renamed_node)
        else:
            logger.info(f"节点不符合要求，已丢弃: {node}")

    node_count = len(validated_and_renamed_nodes)
    logger.info(f"从 {url} 中验证并保留了 {node_count} 个节点。")

    return url, node_count, validated_and_renamed_nodes

async def main():
    logger.info("开始执行代理抓取任务。")
    # 修正文件名为 'sources.list'
    urls = await read_urls_from_file('sources.list')

    if not urls:
        logger.warning("未找到任何 URL，程序退出。")
        return

    # 清空之前的 all.txt 和 temp 文件
    if os.path.exists(ALL_NODES_FILE):
        os.remove(ALL_NODES_FILE)
    if os.path.exists(RAW_FETCHED_NODES_TEMP_FILE):
        os.remove(RAW_FETCHED_NODES_TEMP_FILE)

    node_counts_data = []
    all_collected_nodes = []

    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        tasks = [process_url(client, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, node_count, nodes in results:
            if isinstance(url, str): # 确保不是异常对象
                node_counts_data.append({"url": url, "node_count": node_count})
                all_collected_nodes.extend(nodes)
            else:
                logger.error(f"处理 URL 时发生异常: {url}") # url 实际上是异常对象

    # 将所有收集到的节点保存到 all.txt
    unique_all_collected_nodes = list(set(all_collected_nodes)) # 去重
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in unique_all_collected_nodes:
            await f.write(node + '\n')
    logger.info(f"所有 {len(unique_all_collected_nodes)} 个唯一节点已保存到 {ALL_NODES_FILE}")

    # 将节点数量统计保存为 CSV
    with open(NODE_COUNTS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url', 'node_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(node_counts_data)
    logger.info(f"节点统计已保存到 {NODE_COUNTS_CSV}")

    logger.info("代理抓取任务完成。")

if __name__ == "__main__":
    asyncio.run(main())
