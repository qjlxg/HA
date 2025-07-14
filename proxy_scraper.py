import asyncio
import httpx
import re
import os
import yaml
import base64
import json
import csv
from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse, urljoin
import hashlib
import time

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

# 定义支持的节点协议正则
NODE_PROTOCOLS = {
    "hysteria2": r"hysteria2://",
    "vmess": r"vmess://",
    "trojan": r"trojan://",
    "ss": r"ss://",
    "ssr": r"ssr://",
    "vless": r"vless://",
}

# 缓存目录
CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_EXPIRATION_TIME = 3600  # 缓存过期时间，单位秒 (1小时)

# 请求头列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# 节点验证函数 (示例，需根据实际协议规范补充完整)
def validate_node(node_url: str) -> bool:
    """
    验证节点是否符合协议规范且信息完整。
    实际应用中需要根据不同的协议（vmess, trojan, ss等）补充详细的验证逻辑。
    目前仅做基础的URL格式和协议头校验。
    """
    if not any(node_url.startswith(p) for p in NODE_PROTOCOLS.values()):
        logging.debug(f"节点 {node_url[:50]}... 协议头不匹配，丢弃。")
        return False

    # 简单的验证逻辑，实际应用中需要更严谨的校验
    if "://" not in node_url:
        logging.debug(f"节点 {node_url[:50]}... 缺少协议分隔符，丢弃。")
        return False

    parts = node_url.split("://", 1)
    if len(parts) < 2:
        logging.debug(f"节点 {node_url[:50]}... 格式不正确，丢弃。")
        return False

    protocol = parts[0]
    content = parts[1]

    if protocol == "vmess":
        try:
            # vmess 节点内容通常是 base64 编码的 JSON
            decoded_content = base64.b64decode(content).decode('utf-8')
            node_data = json.loads(decoded_content)
            # 检查关键字段是否存在
            if not all(k in node_data for k in ['add', 'port', 'id', 'net', 'type']):
                logging.debug(f"VMess 节点 {node_url[:50]}... 缺少关键字段，丢弃。")
                return False
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            logging.debug(f"VMess 节点 {node_url[:50]}... 解码或解析失败: {e}，丢弃。")
            return False
    elif protocol == "trojan":
        # trojan://password@host:port
        if not re.match(r"[^@]+@[^:]+:\d+", content):
            logging.debug(f"Trojan 节点 {node_url[:50]}... 格式不正确，丢弃。")
            return False
    elif protocol == "ss":
        # ss://base64(method:password@host:port)
        try:
            decoded_content = base64.b64decode(content.split("#")[0]).decode('utf-8') # 忽略注释部分
            if ":" not in decoded_content or "@" not in decoded_content:
                logging.debug(f"SS 节点 {node_url[:50]}... 解码后格式不正确，丢弃。")
                return False
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logging.debug(f"SS 节点 {node_url[:50]}... 解码失败: {e}，丢弃。")
            return False
    elif protocol == "ssr":
        # ssr://base64(...)
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            # 简单的检查，ssr协议通常包含多个字段，用:或/分隔
            if len(decoded_content.split(':')) < 6: # 基础字段数量
                logging.debug(f"SSR 节点 {node_url[:50]}... 解码后字段不全，丢弃。")
                return False
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logging.debug(f"SSR 节点 {node_url[:50]}... 解码失败: {e}，丢弃。")
            return False
    elif protocol == "vless":
        # vless://uuid@host:port?params
        if not re.match(r"[0-9a-fA-F-]+@[^:]+:\d+", content):
            logging.debug(f"VLESS 节点 {node_url[:50]}... 格式不正确，丢弃。")
            return False
    elif protocol == "hysteria2":
        # hysteria2://host:port?params
        if not re.match(r"[^:]+:\d+", content):
            logging.debug(f"Hysteria2 节点 {node_url[:50]}... 格式不正确，丢弃。")
            return False

    return True

def clean_node_name(node_url: str) -> str:
    """
    只保留原节点名称前5位，多余的全部删除。
    """
    try:
        # 尝试从URL中提取节点名称部分（通常在#后面）
        if "#" in node_url:
            name_part = node_url.split("#", 1)[1]
            return node_url.replace(name_part, name_part[:5])
        return node_url # 如果没有名称部分，则不处理
    except Exception as e:
        logging.warning(f"清洗节点名称失败: {e}, 原始URL: {node_url}")
        return node_url

def extract_domain_from_url(url: str) -> str:
    """
    从URL中提取中间域名，去除http,https,和后缀如com.net,等
    """
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        # 移除端口号
        if ':' in netloc:
            netloc = netloc.split(':')[0]

        # 移除 www. 前缀
        if netloc.startswith("www."):
            netloc = netloc[4:]

        # 移除顶级域名后缀，这里只是一个简单示例，更精确的需要使用公共后缀列表
        parts = netloc.split('.')
        if len(parts) > 2:
            # 假设倒数第二个是主要域名
            return ".".join(parts[-2:])
        return netloc
    except Exception as e:
        logging.error(f"提取域名失败: {url} - {e}")
        return hashlib.md5(url.encode()).hexdigest()[:10] # 失败时返回URL的MD5前10位

def get_cache_path(url: str) -> str:
    """根据URL生成缓存文件路径"""
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    return os.path.join(CACHE_DIR, f"{url_hash}.cache")

async def get_cached_content(url: str) -> str | None:
    """尝试从缓存中读取内容，如果缓存有效则返回"""
    cache_path = get_cache_path(url)
    if os.path.exists(cache_path):
        mod_time = os.path.getmtime(cache_path)
        if (time.time() - mod_time) < CACHE_EXPIRATION_TIME:
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                logging.info(f"从缓存中读取: {url}")
                return content
    return None

async def save_content_to_cache(url: str, content: str):
    """将内容保存到缓存"""
    cache_path = get_cache_path(url)
    async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
        await f.write(content)
        logging.info(f"内容保存到缓存: {url}")

async def fetch_url_content(client: httpx.AsyncClient, url: str) -> str | None:
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    随机使用一个请求头。
    """
    if not url.startswith(('http://', 'https://')):
        logging.warning(f"URL格式不正确，自动添加http://: {url}")
        url = "http://" + url # 尝试添加http://

    cached_content = await get_cached_content(url)
    if cached_content:
        return cached_content

    headers = {"User-Agent": USER_AGENTS[hash(url) % len(USER_AGENTS)]} # 根据URL哈希值随机选择请求头

    async def _fetch(full_url: str):
        try:
            logging.info(f"尝试获取内容: {full_url}")
            response = await client.get(full_url, headers=headers, follow_redirects=True, timeout=15)
            response.raise_for_status()  # 检查 HTTP 状态码
            await save_content_to_cache(full_url, response.text)
            return response.text
        except httpx.RequestError as e:
            logging.warning(f"请求 {full_url} 失败: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logging.warning(f"请求 {full_url} 返回非成功状态码: {e.response.status_code}")
            return None

    # 优先尝试原始URL (可能已在外面添加http/https)
    content = await _fetch(url)
    if content:
        return content

    # 如果原始URL失败，尝试 http 和 https
    if not url.startswith('http://') and not url.startswith('https://'):
        for scheme in ['http://', 'https://']:
            full_url = scheme + url
            content = await _fetch(full_url)
            if content:
                return content
    else: # 如果原始URL已经带协议，但仍失败，则尝试切换协议
        if url.startswith('http://'):
            content = await _fetch('https://' + url[7:])
            if content: return content
        elif url.startswith('https://'):
            content = await _fetch('http://' + url[8:])
            if content: return content

    logging.error(f"无法获取任何形式的URL内容: {url}")
    return None

def parse_and_extract_nodes(html_content: str, base_url: str) -> tuple[list[str], list[str]]:
    """
    解析 HTML 内容，提取节点和嵌套链接。
    优先处理 <pre>、<code>、<textarea> 等可能包含节点内容的标签。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_nodes = []
    nested_urls = []

    # 优先从 pre, code, textarea 标签中提取文本
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        text_content = tag.get_text()
        extracted_nodes.extend(re.findall(r'(' + '|'.join(NODE_PROTOCOLS.values()) + r')[^\s"\']+', text_content))
        # 尝试解析YAML或JSON中的节点
        if tag.name == 'pre' or tag.name == 'code':
            try:
                # 尝试解析 YAML
                data = yaml.safe_load(text_content)
                if isinstance(data, dict):
                    # 递归查找可能的节点列表
                    def find_nodes_in_dict(d):
                        nodes = []
                        for k, v in d.items():
                            if isinstance(v, str) and any(v.startswith(p) for p in NODE_PROTOCOLS.values()):
                                nodes.append(v)
                            elif isinstance(v, list):
                                for item in v:
                                    if isinstance(item, str) and any(item.startswith(p) for p in NODE_PROTOCOLS.values()):
                                        nodes.append(item)
                                    elif isinstance(item, dict):
                                        nodes.extend(find_nodes_in_dict(item))
                            elif isinstance(v, dict):
                                nodes.extend(find_nodes_in_dict(v))
                        return nodes
                    extracted_nodes.extend(find_nodes_in_dict(data))
            except yaml.YAMLError:
                pass
            try:
                # 尝试解析 JSON
                data = json.loads(text_content)
                if isinstance(data, dict):
                    def find_nodes_in_json_dict(d):
                        nodes = []
                        for k, v in d.items():
                            if isinstance(v, str) and any(v.startswith(p) for p in NODE_PROTOCOLS.values()):
                                nodes.append(v)
                            elif isinstance(v, list):
                                for item in v:
                                    if isinstance(item, str) and any(item.startswith(p) for p in NODE_PROTOCOLS.values()):
                                        nodes.append(item)
                                    elif isinstance(item, dict):
                                        nodes.extend(find_nodes_in_json_dict(item))
                            elif isinstance(v, dict):
                                nodes.extend(find_nodes_in_json_dict(v))
                        return nodes
                    extracted_nodes.extend(find_nodes_in_json_dict(data))
            except json.JSONDecodeError:
                pass

    # 从所有文本中提取明文节点
    text_content = soup.get_text()
    all_potential_nodes = re.findall(r'(' + '|'.join(NODE_PROTOCOLS.values()) + r')[^\s"\']+', text_content)
    extracted_nodes.extend(all_potential_nodes)

    # 尝试解码 Base64 字符串并提取节点
    for match in re.findall(r'[a-zA-Z0-9+/=]{20,}', text_content): # 查找可能的Base64字符串
        try:
            decoded_text = base64.b64decode(match).decode('utf-8')
            extracted_nodes.extend(re.findall(r'(' + '|'.join(NODE_PROTOCOLS.values()) + r')[^\s"\']+', decoded_text))
        except (base64.binascii.Error, UnicodeDecodeError):
            pass # 不是有效的Base64或解码失败

    # 提取所有链接
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        # 过滤掉非http/https链接，以及可能不是有效链接的
        if full_url.startswith(('http://', 'https://')):
            # 避免重复抓取主域名
            if urlparse(full_url).netloc != urlparse(base_url).netloc:
                nested_urls.append(full_url)
    
    # 移除重复和无效的节点
    unique_nodes = [node for node in set(extracted_nodes) if validate_node(node)]
    
    return unique_nodes, list(set(nested_urls)) # 返回去重后的节点和链接

async def scrape_url(client: httpx.AsyncClient, url: str, visited_urls: set, all_nodes: dict, depth: int = 0, max_depth: int = 3):
    """
    抓取单个URL及其嵌套链接，并提取节点。
    """
    if url in visited_urls or depth > max_depth:
        return
    
    visited_urls.add(url)
    logging.info(f"正在抓取 (深度 {depth}): {url}")

    content = await fetch_url_content(client, url)
    if not content:
        return

    nodes, nested_urls = parse_and_extract_nodes(content, url)
    
    # 清洗节点名称
    cleaned_nodes = [clean_node_name(node) for node in nodes]
    
    domain_name = extract_domain_from_url(url)
    
    # 将节点添加到总集合中，以原始 URL 的域名作为键
    if domain_name not in all_nodes:
        all_nodes[domain_name] = []
    all_nodes[domain_name].extend(cleaned_nodes)

    # 保存当前URL的节点到单独的文件
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"{domain_name}.txt")
    
    # 去重并保存
    unique_nodes_for_file = list(set(cleaned_nodes))
    if unique_nodes_for_file:
        async with aiofiles.open(filename, 'a', encoding='utf-8') as f:
            for node in unique_nodes_for_file:
                await f.write(node + "\n")
        logging.info(f"从 {url} 获取到 {len(unique_nodes_for_file)} 个有效节点，保存到 {filename}")
    else:
        logging.info(f"从 {url} 未获取到有效节点。")

    # 并行抓取嵌套链接
    tasks = [scrape_url(client, u, visited_urls, all_nodes, depth + 1, max_depth) for u in nested_urls]
    await asyncio.gather(*tasks)

async def main():
    sources_list_path = "sources.list"
    output_data_dir = "data"
    output_csv_path = os.path.join(output_data_dir, "node_counts.csv")

    os.makedirs(output_data_dir, exist_ok=True)

    urls_to_scrape = []
    if os.path.exists(sources_list_path):
        async with aiofiles.open(sources_list_path, 'r', encoding='utf-8') as f:
            async for line in f:
                url = line.strip()
                if url:
                    urls_to_scrape.append(url)
    else:
        logging.error(f"文件 '{sources_list_path}' 不存在。请确保该文件在根目录下。")
        return

    all_scraped_nodes = {}  # 存储所有 URL 获取到的节点，键为URL的域名
    visited_urls = set()    # 存储已访问的URL，避免重复抓取

    # 使用 httpx 的异步客户端进行请求
    async with httpx.AsyncClient(http2=True, verify=False) as client: # verify=False 忽略SSL证书错误
        tasks = [scrape_url(client, url, visited_urls, all_scraped_nodes) for url in urls_to_scrape]
        await asyncio.gather(*tasks)

    # 统计节点数量并保存为 CSV
    node_counts = []
    for domain, nodes in all_scraped_nodes.items():
        node_counts.append({'URL_Domain': domain, 'Node_Count': len(set(nodes))}) # 使用 set 去重后计数

    if node_counts:
        async with aiofiles.open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['URL_Domain', 'Node_Count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            await writer.writeheader()
            for row in node_counts:
                await writer.writerow(row)
        logging.info(f"节点数量统计已保存到: {output_csv_path}")
    else:
        logging.info("未获取到任何节点。")

if __name__ == "__main__":
    asyncio.run(main())
