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
from urllib.parse import urlparse, urljoin

# --- 配置 ---
@dataclass
class Config:
    DATA_DIR: str = "data"
    CACHE_DIR: str = "cache"
    CACHE_EXPIRY_HOURS: int = 24
    MAX_DEPTH: int = 3
    CONCURRENT_REQUEST_LIMIT: int = 2
    # 移除了 REQUEST_TIMEOUT 和 MAX_RETRIES，因为不再进行重试
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
    CONTENT_TAGS: List[str] = field(default_factory=lambda: ['pre', 'code', 'textarea', 'div', 'p', 'body', 'span', 'a'])
    CONTENT_ATTRIBUTES: List[str] = field(default_factory=lambda: ['value', 'data', 'href', 'content'])

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%(Y-%m-%d %H:%M:%S)'
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
    """尝试解码Base64内容，支持多层解码。"""
    if max_recursion <= 0:
        return None
    try:
        # 添加填充以确保Base64字符串长度是4的倍数
        decoded_bytes = base64.b64decode(content + '=' * (-len(content) % 4))
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        # 检查解码后的字符串是否仍是有效的Base64编码，如果是则继续解码
        if re.fullmatch(r'^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', decoded_str.strip()):
            logger.debug(f"发现嵌套Base64，尝试进一步解码: {decoded_str[:50]}...")
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
    """使用Playwright异步获取URL内容，不支持重试。"""
    full_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
    cache_path = get_cache_path(full_url, config)

    # 检查缓存
    if os.path.exists(cache_path):
        try:
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.loads(await f.read())
                cached_timestamp = datetime.fromisoformat(cache_data['timestamp'])
                if datetime.now() - cached_timestamp < timedelta(hours=config.CACHE_EXPIRY_HOURS):
                    logger.debug(f"使用缓存内容: {full_url}")
                    return cache_data['content']
        except (json.JSONDecodeError, KeyError, Exception) as e:
            logger.warning(f"缓存文件 {cache_path} 损坏或格式错误: {e}，删除并重新获取")
            os.remove(cache_path)

    async with semaphore:
        try:
            await asyncio.sleep(random.uniform(0.5, 2.5)) # 随机等待
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=True)
                except Exception as e:
                    logger.error(f"无法启动 Chromium 浏览器: {e}. 请确保已安装 Playwright 浏览器二进制文件。")
                    return None

                context = await browser.new_context(
                    user_agent=random.choice(config.USER_AGENTS),
                    ignore_https_errors=True
                )
                page = await context.new_page()
                try:
                    # 使用一个默认的超时时间，不再从 config 中读取 REQUEST_TIMEOUT
                    await page.goto(full_url, wait_until='domcontentloaded', timeout=45000)
                    await page.wait_for_load_state('networkidle', timeout=45000)
                    await page.wait_for_timeout(3000) # 增加等待时间，确保页面加载完成
                    content = await page.content()
                    
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
                    logger.warning(f"获取 {full_url} 超时，已跳过。")
                    return None
                except Exception as e:
                    logger.error(f"获取 {full_url} 失败: {e}，已跳过。")
                    return None
                finally:
                    await browser.close()
        except Exception as e:
            logger.error(f"Playwright 环境或启动失败: {e}，已跳过。")
            return None

def extract_nodes_from_text(text: str, config: Config) -> Set[str]:
    """从文本中提取代理节点。"""
    nodes = set()
    for pattern in config.NODE_PATTERNS.values():
        nodes.update(re.findall(pattern, text))
    return nodes

def parse_and_extract_nodes(content: str, current_depth: int, config: Config, base_url: str) -> Tuple[Set[str], Set[str]]:
    """解析网页内容，提取节点和嵌套链接。"""
    all_nodes = set()
    new_urls = set()

    soup = BeautifulSoup(content, 'html.parser', from_encoding='utf-8')
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()

    # 提取标签内容和属性
    for tag_name in config.CONTENT_TAGS:
        for tag in soup.find_all(tag_name):
            text = tag.get_text(separator='\n', strip=True)
            all_nodes.update(extract_nodes_from_text(text, config))
            base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text)
            for b64_str in base64_matches:
                decoded = decode_base64_content(b64_str)
                if decoded:
                    all_nodes.update(extract_nodes_from_text(decoded, config))
                    new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))
            for attr in config.CONTENT_ATTRIBUTES:
                if attr in tag.attrs:
                    attr_value = tag[attr]
                    if isinstance(attr_value, list):
                        attr_value = ' '.join(attr_value)
                    all_nodes.update(extract_nodes_from_text(attr_value, config))
                    base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', attr_value)
                    for b64_str in base64_matches:
                        decoded = decode_base64_content(b64_str)
                        if decoded:
                            all_nodes.update(extract_nodes_from_text(decoded, config))
                            new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', decoded))

    # 解析YAML/JSON
    try:
        data = None
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                pass
        if isinstance(data, (dict, list)):
            def walk_data(item):
                if isinstance(item, str):
                    all_nodes.update(extract_nodes_from_text(item, config))
                    new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
                elif isinstance(item, (dict, list)):
                    for sub_item in (item.values() if isinstance(item, dict) else item):
                        walk_data(sub_item)
            walk_data(data)
    except Exception:
        pass

    # 提取链接
    if current_depth < config.MAX_DEPTH:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith(('http://', 'https://')):
                new_urls.add(href)
            elif href.startswith('/'):
                new_urls.add(urljoin(base_url, href))

    return all_nodes, new_urls

def clean_node(node: str) -> str:
    """清洗节点字符串，移除多余字符。"""
    node = node.strip()
    node = re.sub(r'\s+', '', node)
    node = re.sub(r'[\n\r]+', '', node)
    return node

def validate_node(node: str) -> Optional[str]:
    """
    验证节点，不进行修复。只有完全符合协议格式和信息要求的节点才返回。
    """
    node = clean_node(node)
    if not node or len(node) < 10:
        logger.debug(f"节点过短或为空，已弃用: {node[:50]}...")
        return None

    def validate_host_port(host: str, port_str: str) -> bool:
        """内部函数，检查主机和端口的有效性。"""
        if not (host and port_str and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$', host):
            return False
        port = int(port_str)
        return 1 <= port <= 65535

    try:
        if node.startswith("hysteria2://"):
            parts = node[len("hysteria2://"):].split('?')
            if len(parts) < 1: return None # 至少要有地址部分
            host_port = parts[0].split(':')
            if len(host_port) != 2: return None
            if validate_host_port(host_port[0], host_port[1]) and 'password' in node: # Hysteria2通常需要密码
                return node
            return None

        elif node.startswith("vmess://"):
            decoded = decode_base64_content(node[len("vmess://"):])
            if not decoded: return None
            try:
                data = json.loads(decoded)
                # 检查VMess节点所需的基本字段
                if all(k in data for k in ['v', 'ps', 'add', 'port', 'id']) and validate_host_port(data['add'], str(data['port'])):
                    return node
                return None
            except json.JSONDecodeError:
                return None

        elif node.startswith("trojan://"):
            parts = node[len("trojan://"):].split('@')
            if len(parts) < 2: return None # 至少要有密码和地址
            password_part = parts[0]
            host_port_part = parts[1].split('#')[0].split('?')[0] # 剥离别名和参数
            host_port = host_port_part.split(':')
            if len(host_port) != 2: return None
            if password_part and validate_host_port(host_port[0], host_port[1]):
                return node
            return None

        elif node.startswith("ss://"):
            encoded_str = node[len("ss://"):].split('#')[0].split('?')[0]
            if '@' not in encoded_str: # 如果没有@符号，尝试整体Base64解码
                decoded = decode_base64_content(encoded_str)
                if not decoded: return None
                parts = decoded.split('@')
            else:
                parts = encoded_str.split('@')
            
            if len(parts) < 2: return None # 至少要有加密方式:密码 和 地址
            method_password_part, host_port_part = parts[0], parts[1]
            try:
                method, password = method_password_part.split(':', 1)
                host, port = host_port_part.split(':', 1)
                if method and password and validate_host_port(host, port):
                    return node
                return None
            except ValueError: # 解析失败，例如缺少冒号
                return None

        elif node.startswith("ssr://"):
            decoded = decode_base64_content(node[len("ssr://"):])
            if not decoded: return None
            parts = decoded.split(':')
            # SSR协议通常有至少6个部分: host:port:protocol:method:obfs:password_base64
            if len(parts) < 6: return None
            host, port, protocol, method, obfs, password_b64 = parts[:6]
            if validate_host_port(host, port) and protocol and method and obfs and password_b64:
                return node
            return None

        elif node.startswith("vless://"):
            parts = node[len("vless://"):].split('@')
            if len(parts) < 2: return None # 至少有UUID和地址
            uuid_part = parts[0]
            host_port_params_part = parts[1]
            host, port = host_port_params_part.split('?')[0].split(':', 1) # 剥离参数
            
            # VLESS需要一个有效的UUID
            if re.match(r'^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', uuid_part) and validate_host_port(host, port):
                return node
            return None
        
        # 不再尝试修复裸节点或Base64编码的字符串，直接弃用
        logger.debug(f"未知或信息不全的节点格式，已弃用: {node[:100]}...")
        return None
    except Exception as e:
        logger.debug(f"节点验证过程中出现异常，已弃用: {node[:50]}... 错误: {e}")
        return None

async def process_url(url: str, processed_urls: Set[str], all_nodes: Dict[str, Set[str]], semaphore: asyncio.Semaphore, config: Config, depth: int = 0) -> None:
    """递归处理URL，提取和验证节点。"""
    base_url = url.split('#')[0].split('?')[0] # 规范化URL以便跟踪已处理链接
    if base_url in processed_urls:
        logger.debug(f"规范化后的URL已处理: {url} -> {base_url}")
        return
    processed_urls.add(base_url)

    logger.info(f"处理URL (深度 {depth}): {url}")
    content = await fetch_url_content(url, semaphore, config)
    if not content:
        logger.warning(f"无法获取内容: {url}，跳过节点提取。")
        return

    extracted_nodes, new_urls = parse_and_extract_nodes(content, depth, config, base_url)
    
    # 初始化当前URL的节点集合
    if url not in all_nodes:
        all_nodes[url] = set()

    for node in extracted_nodes:
        valid_node = validate_node(node) # 调用新的验证函数，不修复
        if valid_node:
            # 简化节点别名，如果太长，只保留前5个字符
            # match = re.search(r'#(.*?)(?:&|\s|$)', valid_node)
            # if match and len(match.group(1)) > 5:
            #     valid_node = valid_node.replace(f"#{match.group(1)}", f"#{match.group(1)[:5]}")
            all_nodes[url].add(valid_node)
        else:
            logger.debug(f"节点 '{node[:50]}...' 因不符合要求被弃用。")

    logger.debug(f"URL {url}: 发现 {len(all_nodes[url])} 个有效节点。")

    if depth < config.MAX_DEPTH:
        tasks = []
        for new_url in new_urls:
            normalized_new_url = new_url.split('#')[0].split('?')[0]
            if normalized_new_url not in processed_urls:
                tasks.append(process_url(new_url, processed_urls, all_nodes, semaphore, config, depth + 1))
        
        if tasks:
            logger.info(f"发现 {len(tasks)} 个新链接 (深度 {depth + 1})")
            await asyncio.gather(*tasks)

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
    # all_nodes 现在只包含有效节点
    all_nodes: Dict[str, Set[str]] = {}
    processed_urls: Set[str] = set()
    semaphore = asyncio.Semaphore(config.CONCURRENT_REQUEST_LIMIT)

    await asyncio.gather(*[
        process_url(url, processed_urls, all_nodes, semaphore, config)
        for url in source_urls
    ])

    logger.info("所有URL处理完毕，开始保存节点")
    async with aiofiles.open(os.path.join(config.DATA_DIR, "node_counts.csv"), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Valid Nodes"]) # 只记录有效节点数量
        total_valid_nodes = 0
        for url, nodes in all_nodes.items():
            valid_count = len(nodes)
            if valid_count > 0:
                # 生成安全的文件名，结合网络位置和URL哈希
                url_hash = hashlib.md5(url.encode()).hexdigest()[:10]
                parsed_url_netloc = urlparse(url).netloc.replace('.', '_').replace(':', '_') # 替换冒号
                safe_url_name = f"{parsed_url_netloc}_{url_hash}"
                
                output_path = os.path.join(config.DATA_DIR, f"{safe_url_name}.txt")
                
                async with aiofiles.open(output_path, 'w', encoding='utf-8') as node_file:
                    await node_file.write('\n'.join(sorted(nodes))) # 保存排序后的有效节点
                logger.info(f"保存 {valid_count} 个节点到 {output_path}")
            writer.writerow([url, valid_count])
            total_valid_nodes += valid_count

    logger.info(f"任务完成。共发现 {total_valid_nodes} 个有效节点。统计信息已保存。")

if __name__ == "__main__":
    asyncio.run(main())
