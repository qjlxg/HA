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
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
import logging
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple

# --- 配置 ---
@dataclass
class Config:
    DATA_DIR: str = "data"
    CACHE_DIR: str = "cache"
    CACHE_EXPIRY_HOURS: int = 24
    MAX_DEPTH: int = 3
    CONCURRENT_REQUEST_LIMIT: int = 2
    REQUEST_TIMEOUT: int = 45000  # 增加超时时间，毫秒
    MAX_RETRIES: int = 3 # 增加重试次数
    USER_AGENTS: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.39",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 OPR/86.0.4363.32",
    ])
    NODE_PATTERNS: Dict[str, str] = field(default_factory=lambda: {
        "hysteria2": r"hysteria2://[^\"'\s]+",
        "vmess": r"vmess://[a-zA-Z0-9+/=]+",
        "trojan": r"trojan://[^\"'\s]+",
        "ss": r"ss://[a-zA-Z0-9+/=@:\.-]+",
        "ssr": r"ssr://[a-zA-Z0-9+/=@:\.-]+",
        "vless": r"vless://[^\"'\s]+",
    })
    # 新增：可能包含敏感信息的HTML标签，这些标签通常包含原始订阅链接或Base64编码内容
    CONTENT_TAGS: List[str] = field(default_factory=lambda: ['pre', 'code', 'textarea', 'div', 'p', 'body'])


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- 辅助函数 ---
def ensure_directories(config: Config) -> None:
    """确保数据和缓存目录存在。"""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.CACHE_DIR, exist_ok=True)

async def read_sources_list(file_path: str = "sources.list") -> List[str]:
    """从文件中读取URL列表。"""
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
    except FileNotFoundError:
        logger.error(f"文件 {file_path} 未找到")
    return urls

def get_cache_path(url: str, config: Config) -> str:
    """生成缓存文件路径。"""
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    return os.path.join(config.CACHE_DIR, f"{url_hash}.cache")

def get_url_content_hash(content: str) -> str:
    """生成内容的哈希值。"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def decode_base64_content(content: str, max_recursion: int = 5) -> Optional[str]:
    """
    尝试解码Base64内容，支持多层解码。
    max_recursion: 限制递归深度，防止无限循环
    """
    if max_recursion <= 0:
        return None
    try:
        decoded_bytes = base64.b64decode(content + '=' * (-len(content) % 4))
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

        # 检查是否可能是嵌套的Base64
        # 更严格的检查：解码后的字符串是否仍然是符合Base64特征的（排除普通文本）
        if re.fullmatch(r'^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', decoded_str.strip()):
            logger.debug(f"发现嵌套Base64，尝试进一步解码...")
            nested_decoded = decode_base64_content(decoded_str, max_recursion - 1)
            return nested_decoded if nested_decoded else decoded_str
        return decoded_str
    except Exception:
        return None

def is_valid_ip(ip_string: str) -> bool:
    """检查字符串是否是有效的IP地址。"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

# --- 核心抓取和解析逻辑 ---
async def fetch_url_content(url: str, semaphore: asyncio.Semaphore, config: Config) -> Optional[str]:
    """使用Playwright异步获取URL内容，支持动态内容加载。"""
    full_url = url if url.startswith(("http://", "https://")) else f"https://{url}" # 默认尝试HTTPS

    # 检查缓存
    cache_path = get_cache_path(full_url, config)
    if os.path.exists(cache_path):
        try:
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.loads(await f.read())
                cached_timestamp = datetime.fromisoformat(cache_data['timestamp'])
                if datetime.now() - cached_timestamp < timedelta(hours=config.CACHE_EXPIRY_HOURS):
                    logger.debug(f"使用缓存内容: {full_url}")
                    return cache_data['content']
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"缓存文件 {cache_path} 损坏或格式错误: {e}，删除并重新获取。")
            os.remove(cache_path)
        except Exception as e: # 捕获其他文件操作错误
            logger.error(f"读取缓存文件 {cache_path} 时发生未知错误: {e}，删除并重新获取。")
            os.remove(cache_path)


    # Playwright请求
    async with semaphore:
        for attempt in range(config.MAX_RETRIES + 1):
            try:
                # 随机延迟，模拟人类行为，避免被封禁
                await asyncio.sleep(random.uniform(0.5, 2.5)) 

                async with async_playwright() as p:
                    # 尝试启动浏览器
                    try:
                        browser = await p.chromium.launch(headless=True)
                    except Exception as e:
                        logger.error(f"无法启动 Chromium 浏览器: {e}. 请确保已安装 Playwright 浏览器二进制文件。")
                        return None # 如果无法启动浏览器，则直接返回None

                    # --- 修改点：添加 ignore_https_errors=True ---
                    context = await browser.new_context(
                        user_agent=random.choice(config.USER_AGENTS),
                        ignore_https_errors=True # 忽略 HTTPS 证书错误
                    )
                    # --- 修改点结束 ---
                    
                    page = await context.new_page()

                    try:
                        await page.goto(full_url, wait_until='domcontentloaded', timeout=config.REQUEST_TIMEOUT)
                        # 等待网络空闲和额外的JS加载
                        await page.wait_for_load_state('networkidle', timeout=config.REQUEST_TIMEOUT)
                        await page.wait_for_timeout(2000) # 等待2秒，确保动态内容加载

                        content = await page.content()
                        await browser.close()

                        # 缓存内容
                        cache_data = {
                            'timestamp': datetime.now().isoformat(),
                            'content_hash': get_url_content_hash(content),
                            'content': content
                        }
                        async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                            await f.write(json.dumps(cache_data))
                        logger.info(f"成功获取: {full_url}")
                        return content
                    except PlaywrightTimeoutError:
                        logger.warning(f"获取 {full_url} 超时 (尝试 {attempt + 1}/{config.MAX_RETRIES + 1})")
                        await browser.close() # 确保浏览器关闭
                        if attempt < config.MAX_RETRIES:
                            await asyncio.sleep(random.uniform(2.0, 5.0)) # 等待更长时间再重试
                        continue # 进入下一次重试循环
                    except Exception as e:
                        logger.error(f"Playwright 获取 {full_url} 失败: {e} (尝试 {attempt + 1}/{config.MAX_RETRIES + 1})")
                        await browser.close() # 确保浏览器关闭
                        if attempt < config.MAX_RETRIES:
                            await asyncio.sleep(random.uniform(2.0, 5.0))
                        continue # 进入下一次重试循环
            except Exception as e: # 捕获 Playwright 启动等更高层级错误
                logger.error(f"Playwright 环境错误或启动失败: {e}. (尝试 {attempt + 1}/{config.MAX_RETRIES + 1})")
                if attempt < config.MAX_RETRIES:
                    await asyncio.sleep(random.uniform(2.0, 5.0))
                continue

    logger.error(f"获取 {full_url} 失败，已达最大重试次数")
    return None


def extract_nodes_from_text(text: str, config: Config) -> Set[str]:
    """从文本中提取代理节点。"""
    nodes = set()
    for pattern in config.NODE_PATTERNS.values():
        nodes.update(re.findall(pattern, text))
    return nodes

def parse_and_extract_nodes(content: str, current_depth: int, config: Config) -> Tuple[Set[str], Set[str]]:
    """解析网页内容，提取节点和嵌套链接，优化复杂HTML处理。"""
    all_nodes = set()
    new_urls = set()

    soup = BeautifulSoup(content, 'html.parser')
    # 移除脚本和样式，清理HTML以获得更纯净的文本
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()

    # 优先从可能包含订阅链接的特定标签中提取内容
    for tag_name in config.CONTENT_TAGS:
        for tag in soup.find_all(tag_name):
            text = tag.get_text(separator='\n', strip=True)
            # 提取节点
            all_nodes.update(extract_nodes_from_text(text, config))
            
            # 提取Base64编码内容并递归解码
            base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text)
            for b64_str in base64_matches:
                decoded = decode_base64_content(b64_str)
                if decoded:
                    all_nodes.update(extract_nodes_from_text(decoded, config))
                    # 从解码后的内容中提取新的URL
                    new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))

    # 尝试解析YAML/JSON，这通常是纯文本文件或API响应
    try:
        # 尝试 YAML 解析，如果失败则尝试 JSON
        data = None
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            pass # 可能是JSON，继续尝试

        if data is None: # 如果 YAML 解析失败，尝试 JSON
            data = json.loads(content)

        if isinstance(data, (dict, list)):
            def walk_data(item):
                if isinstance(item, str):
                    all_nodes.update(extract_nodes_from_text(item, config))
                    new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
                elif isinstance(item, (dict, list)):
                    for sub_item in (item.values() if isinstance(item, dict) else item):
                        walk_data(sub_item)
            walk_data(data)
    except (yaml.YAMLError, json.JSONDecodeError):
        # 如果不是有效的 YAML 或 JSON，则忽略
        pass

    # 提取HTML页面中的链接
    if current_depth < config.MAX_DEPTH:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # 确保链接是完整的URL
            if href.startswith(('http://', 'https://')):
                new_urls.add(href)
            # 处理相对路径链接 (需要一个 base_url，这里暂时忽略，因为主要关注绝对URL)
            # 可以添加urljoin来处理相对链接

    return all_nodes, new_urls

def clean_node(node: str) -> str:
    """清洗节点字符串，移除多余的空格和换行符。"""
    node = node.strip()
    node = re.sub(r'\s+', '', node)  # 移除多余空格
    node = re.sub(r'[\n\r]+', '', node)  # 移除换行符
    return node

def validate_and_fix_node(node: str) -> Tuple[Optional[str], str]:
    """验证节点并尝试修复部分无效节点，返回(修复后的节点, 状态)。"""
    node = clean_node(node)
    if not node or len(node) < 10:
        logger.debug(f"节点过短或为空，丢弃: {node[:50]}")
        return None, "invalid_length"

    def validate_host_port(host: str, port_str: str) -> bool:
        if not (host and port_str and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$', host): # 改进域名匹配
            return False
        port = int(port_str)
        return 1 <= port <= 65535

    try:
        if node.startswith("hysteria2://"):
            parts = node[len("hysteria2://"):].split('?')
            host_port = parts[0].split(':')
            if len(host_port) != 2: return None, "invalid_format"
            if validate_host_port(host_port[0], host_port[1]) and 'password' in node: return node, "valid"
            return None, "invalid_host_or_password"

        elif node.startswith("vmess://"):
            decoded = decode_base64_content(node[len("vmess://"):])
            if not decoded: return None, "invalid_base64"
            try:
                data = json.loads(decoded)
                if all(k in data for k in ['v', 'ps', 'add', 'port', 'id']) and validate_host_port(data['add'], str(data['port'])):
                    return node, "valid"
                return None, "invalid_vmess_data"
            except json.JSONDecodeError:
                # 尝试修复JSON (例如单引号转双引号)
                try:
                    fixed_decoded = decoded.replace("'", '"')
                    data = json.loads(fixed_decoded)
                    if all(k in data for k in ['v', 'ps', 'add', 'port', 'id']) and validate_host_port(data['add'], str(data['port'])):
                        # 重新编码以保持一致性
                        fixed_node = f"vmess://{base64.b64encode(fixed_decoded.encode('utf-8')).decode('utf-8')}"
                        return fixed_node, "fixed"
                    return None, "invalid_vmess_data"
                except json.JSONDecodeError:
                    return None, "invalid_json_format"

        elif node.startswith("trojan://"):
            parts = node[len("trojan://"):].split('@')
            if len(parts) < 2: return None, "invalid_format"
            host_port_path = parts[1].split('#')[0].split('?')[0] # 移除#和?后面的内容
            host_port = host_port_path.split(':')
            if len(host_port) != 2: return None, "invalid_host_port"
            if parts[0] and validate_host_port(host_port[0], host_port[1]): return node, "valid"
            return None, "invalid_host_or_password"

        elif node.startswith("ss://"):
            encoded_str_with_prefix = node[len("ss://"):]
            if '@' not in encoded_str_with_prefix: # 如果没有@，尝试整个字符串Base64解码
                decoded = decode_base64_content(encoded_str_with_prefix)
                if not decoded: return None, "invalid_base64"
                method_password_host_port = decoded # 解码后可能是 method:password@host:port
            else:
                method_password_host_port = encoded_str_with_prefix

            parts = method_password_host_port.split('@')
            if len(parts) < 2: return None, "invalid_format"
            method_password, host_port_str = parts[0], parts[1].split('#')[0].split('?')[0] # 移除#和?后面的内容

            if ':' not in method_password or ':' not in host_port_str: return None, "invalid_format"
            method, password = method_password.split(':', 1)
            host, port = host_port_str.split(':', 1)

            if method and password and validate_host_port(host, port): return node, "valid"
            return None, "invalid_method_or_host"

        elif node.startswith("ssr://"):
            decoded = decode_base64_content(node[len("ssr://"):])
            if not decoded: return None, "invalid_base64"
            parts = decoded.split(':')
            if len(parts) < 6: return None, "invalid_format"
            host, port_str, protocol, method, obfs, password_b64 = parts[:6]
            if validate_host_port(host, port_str) and protocol and method and obfs and password_b64: return node, "valid"
            return None, "invalid_ssr_data"

        elif node.startswith("vless://"):
            uuid_host_port_params = node[len("vless://"):].split('#')[0] # 移除#后面的内容
            if '@' not in uuid_host_port_params or ':' not in uuid_host_port_params: return None, "invalid_format"
            uuid_part, host_port_params = uuid_host_port_params.split('@', 1)
            host_part, port_part = host_port_params.split(':', 1)
            host = host_part.split('?')[0] # 移除?后面的内容
            port_str = port_part.split('?')[0] # 移除?后面的内容

            if re.match(r'^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', uuid_part) and validate_host_port(host, port_str):
                return node, "valid"
            return None, "invalid_uuid_or_host"

        # 捕获裸IP:端口格式
        if ':' in node:
            host_port = node.split(':', 1)
            if len(host_port) == 2 and validate_host_port(host_port[0], host_port[1]):
                # 可以尝试添加一个默认协议，但通常裸IP:端口不是一个完整的订阅协议
                # 暂时不尝试修复为特定协议，只返回其有效性
                return node, "valid_bare_ip_port" # 新增一个状态
        
        logger.debug(f"未知或无法验证的节点格式: {node[:min(len(node), 100)]}")
        return None, "unknown_format"

    except Exception as e:
        logger.debug(f"节点验证失败: {node[:min(len(node), 50)]}... 错误: {e}")
        return None, "exception"

async def process_url(url: str, processed_urls: Set[str], all_nodes: Dict[str, Dict[str, Set[str]]], semaphore: asyncio.Semaphore, config: Config, depth: int = 0) -> None:
    """递归处理URL，获取内容，提取和验证节点，并处理嵌套链接。"""
    if url in processed_urls:
        logger.debug(f"URL 已处理或正在处理中，跳过: {url}")
        return
    
    # 规范化 URL，移除可能的锚点或查询参数，以便更准确地进行去重
    base_url = url.split('#')[0].split('?')[0] 
    if base_url in processed_urls:
        logger.debug(f"规范化后的 URL 已处理或正在处理中，跳过: {url} -> {base_url}")
        return

    processed_urls.add(base_url) # 将规范化后的 URL 加入已处理集合

    logger.info(f"开始处理 URL (深度 {depth}): {url}")
    content = await fetch_url_content(url, semaphore, config)
    if not content:
        logger.warning(f"无法获取内容或内容为空，跳过处理: {url}")
        return

    nodes_from_current_url, new_urls_found = parse_and_extract_nodes(content, depth, config)
    
    # 初始化当前 URL 的节点存储
    if url not in all_nodes: # 注意这里还是用原始URL作为key，因为保存文件时会用到
        all_nodes[url] = {"valid": set(), "fixed": set(), "invalid": set()}

    current_url_valid_count = 0
    current_url_fixed_count = 0
    current_url_invalid_count = 0

    for node in nodes_from_current_url:
        fixed_node, status = validate_and_fix_node(node)
        if fixed_node:
            if status == "valid":
                all_nodes[url]["valid"].add(fixed_node)
                current_url_valid_count += 1
            elif status == "fixed" or status == "valid_bare_ip_port": # 包含裸IP端口也算修复或有效
                all_nodes[url]["fixed"].add(fixed_node)
                current_url_fixed_count += 1
        else:
            all_nodes[url]["invalid"].add(node)
            current_url_invalid_count += 1

    logger.debug(f"URL {url}: 发现节点 (原始): {len(nodes_from_current_url)}, 有效: {current_url_valid_count}, 修复: {current_url_fixed_count}, 无效: {current_url_invalid_count}")

    # 递归处理新发现的URL
    if depth < config.MAX_DEPTH:
        tasks = []
        for new_link in new_urls_found:
            # 同样规范化新发现的链接，避免重复处理
            normalized_new_link = new_link.split('#')[0].split('?')[0]
            if normalized_new_link not in processed_urls:
                tasks.append(process_url(new_link, processed_urls, all_nodes, semaphore, config, depth + 1))
        
        if tasks:
            logger.info(f"URL {url}: 发现 {len(tasks)} 个新链接，将继续处理 (深度 {depth+1})")
            await asyncio.gather(*tasks)
    else:
        logger.debug(f"达到最大抓取深度 ({config.MAX_DEPTH})，停止从 {url} 提取新链接。")

async def main():
    """主函数，协调抓取和保存过程。"""
    config = Config()
    ensure_directories(config)
    logger.info("开始执行代理抓取任务")

    source_urls = await read_sources_list()
    if not source_urls:
        logger.error("未找到任何URL，请检查sources.list文件")
        return

    logger.info(f"读取到 {len(source_urls)} 个URL")
    all_nodes: Dict[str, Dict[str, Set[str]]] = {} # 存储所有URL的节点
    processed_urls: Set[str] = set() # 追踪所有已处理的URL (包括递归的)
    semaphore = asyncio.Semaphore(config.CONCURRENT_REQUEST_LIMIT)

    # 并发处理所有初始URL
    initial_tasks = [
        process_url(url, processed_urls, all_nodes, semaphore, config)
        for url in source_urls
    ]
    await asyncio.gather(*initial_tasks)

    logger.info("所有URL处理完毕，开始保存节点。")
    
    # 保存节点计数到 CSV
    csv_file_path = os.path.join(config.DATA_DIR, "node_counts.csv")
    async with aiofiles.open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Valid Nodes", "Fixed Nodes", "Invalid Nodes"])
        
        for url, nodes_data in all_nodes.items():
            valid_count = len(nodes_data["valid"])
            fixed_count = len(nodes_data["fixed"])
            invalid_count = len(nodes_data["invalid"])
            
            # 只有当有有效或修复的节点时才创建独立文件
            if valid_count + fixed_count > 0:
                safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url.replace("http://", "").replace("https://", "")) # 进一步清理文件名
                output_file_path = os.path.join(config.DATA_DIR, f"{safe_url_name}.txt")
                
                combined_nodes = sorted(list(nodes_data["valid"] | nodes_data["fixed"]))
                async with aiofiles.open(output_file_path, 'w', encoding='utf-8') as node_file:
                    await node_file.write('\n'.join(combined_nodes))
                logger.info(f"保存 {valid_count + fixed_count} 个节点到 {output_file_path}，来源: {url}")
            else:
                logger.debug(f"URL {url} 未解析到任何有效或修复节点，未创建独立节点文件。")
            
            writer.writerow([url, valid_count, fixed_count, invalid_count])

    logger.info(f"所有节点和统计信息已保存到 {config.DATA_DIR}/。任务完成。")

if __name__ == "__main__":
    asyncio.run(main())
