
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
    DATA_DIR: str = "data"  # 数据存储目录
    CACHE_DIR: str = "cache"  # 缓存目录
    CACHE_EXPIRY_HOURS: int = 108  # 缓存有效期（小时）
    MAX_DEPTH: int = 1  # 最大递归深度
    CONCURRENT_REQUEST_LIMIT: int = 2  # 并发请求限制
    REQUEST_TIMEOUT: int = 60000  # 请求超时时间（毫秒，60秒）
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
    CONTENT_TAGS: List[str] = field(default_factory=lambda: ['pre', 'code', 'textarea', 'div', 'p', 'body', 'span', 'a', 'script', 'input'])
    CONTENT_ATTRIBUTES: List[str] = field(default_factory=lambda: ['value', 'data', 'href', 'content', 'src', 'data-config', 'data-nodes'])

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
    """尝试解码Base64内容，支持多层解码。"""
    if max_recursion <= 0:
        logger.debug("达到Base64解码最大递归深度，停止解码")
        return None
    try:
        decoded_bytes = base64.b64decode(content + '=' * (-len(content) % 4), validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        if re.fullmatch(r'^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', decoded_str.strip()):
            logger.debug(f"发现嵌套Base64，尝试进一步解码: {decoded_str[:50]}...")
            nested_decoded = decode_base64_content(decoded_str, max_recursion - 1)
            return nested_decoded if nested_decoded else decoded_str
        return decoded_str
    except Exception as e:
        logger.debug(f"Base64解码失败: {content[:50]}... 错误: {e}")
        return None

def is_valid_ip(ip_string: str) -> bool:
    """检查字符串是否是有效的IP地址。"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def get_safe_filename(url: str) -> str:
    """从URL提取域名作为文件名，清理特殊字符。"""
    parsed_url = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    netloc = parsed_url.netloc or url
    # 清理域名中的特殊字符，保留字母、数字、连字符和点号
    safe_netloc = re.sub(r'[^a-zA-Z0-9\-\.]', '_', netloc)
    # 移除多余的点号和下划线
    safe_netloc = re.sub(r'\.+', '.', safe_netloc)
    safe_netloc = re.sub(r'_+', '_', safe_netloc).strip('_')
    return f"{safe_netloc}.txt"

# --- 核心抓取和解析逻辑 ---
async def fetch_url_content(url: str, semaphore: asyncio.Semaphore, config: Config) -> Optional[Tuple[str, str]]:
    """使用Playwright异步获取URL内容，自动处理无协议头的URL，无重试。"""
    if not url.startswith(("http://", "https://")):
        https_url = f"https://{url}"
        http_url = f"http://{url}"
    else:
        https_url = url
        http_url = url.replace("https://", "http://") if url.startswith("https://") else url.replace("http://", "https://")

    for full_url in [https_url, http_url]:
        cache_path = get_cache_path(full_url, config)

        if os.path.exists(cache_path):
            try:
                async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                    cache_data = json.loads(await f.read())
                    cached_timestamp = datetime.fromisoformat(cache_data['timestamp'])
                    if datetime.now() - cached_timestamp < timedelta(hours=config.CACHE_EXPIRY_HOURS):
                        logger.debug(f"使用缓存内容: {full_url}")
                        return cache_data['content'], full_url
            except (json.JSONDecodeError, KeyError, Exception) as e:
                logger.warning(f"缓存文件 {cache_path} 损坏或格式错误: {e}，删除并重新获取")
                os.remove(cache_path)

        async with semaphore:
            try:
                await asyncio.sleep(random.uniform(0.5, 2.5))
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(
                        user_agent=random.choice(config.USER_AGENTS),
                        ignore_https_errors=True
                    )
                    page = await context.new_page()
                    try:
                        await page.goto(full_url, wait_until='load', timeout=config.REQUEST_TIMEOUT)
                        await page.wait_for_timeout(5000)
                        content = await page.content()
                        cache_data = {
                            'timestamp': datetime.now().isoformat(),
                            'content_hash': get_url_content_hash(content),
                            'content': content
                        }
                        async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                            await f.write(json.dumps(cache_data))
                        logger.info(f"成功获取: {full_url}")
                        return content, full_url
                    except PlaywrightTimeoutError:
                        logger.warning(f"获取 {full_url} 超时，尝试获取部分内容")
                        content = await page.content()
                        if content:
                            logger.info(f"成功获取部分内容: {full_url}")
                            cache_data = {
                                'timestamp': datetime.now().isoformat(),
                                'content_hash': get_url_content_hash(content),
                                'content': content
                            }
                            async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                                await f.write(json.dumps(cache_data))
                            return content, full_url
                        logger.warning(f"无法获取任何内容: {full_url}")
                        continue
                    except Exception as e:
                        logger.error(f"获取 {full_url} 失败: {e}，尝试下一个协议")
                        continue
                    finally:
                        await context.close()
                        await browser.close()
            except Exception as e:
                logger.error(f"Playwright 环境或启动失败: {e}，尝试下一个协议")
                continue
    logger.error(f"所有协议尝试失败: {url}")
    return None, url

def extract_nodes_from_text(text: str, config: Config) -> Set[str]:
    """从文本中提取代理节点。"""
    nodes = set()
    for protocol, pattern in config.NODE_PATTERNS.items():
        matches = re.findall(pattern, text)
        nodes.update(matches)
        if matches:
            logger.debug(f"从文本提取到 {len(matches)} 个 {protocol} 节点")
    return nodes

def parse_and_extract_nodes(content: str, current_depth: int, config: Config, base_url: str) -> Tuple[Set[str], Set[str]]:
    """解析网页内容，提取节点和嵌套链接。"""
    all_nodes = set()
    new_urls = set()

    soup = BeautifulSoup(content, 'html.parser', from_encoding='utf-8')
    for style_tag in soup(["style"]):
        style_tag.decompose()

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

    for script_tag in soup.find_all('script'):
        script_content = script_tag.get_text(strip=True)
        try:
            json_data = json.loads(script_content)
            def walk_data(item):
                if isinstance(item, str):
                    all_nodes.update(extract_nodes_from_text(item, config))
                    new_urls.update(re.findall(r'(?:http|https)://[^\s"\']+', item))
                elif isinstance(item, (dict, list)):
                    for sub_item in (item.values() if isinstance(item, dict) else item):
                        walk_data(sub_item)
            walk_data(json_data)
        except json.JSONDecodeError:
            all_nodes.update(extract_nodes_from_text(script_content, config))

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

    if current_depth < config.MAX_DEPTH:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith(('http://', 'https://')):
                new_urls.add(href)
            elif href.startswith('/'):
                new_urls.add(urljoin(base_url, href))
            elif not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                new_urls.add(urljoin(base_url, f"https://{href}"))

    logger.debug(f"从 {base_url} 提取到 {len(all_nodes)} 个潜在节点，{len(new_urls)} 个新链接")
    return all_nodes, new_urls

def clean_node(node: str) -> str:
    """清洗节点字符串，移除多余字符。"""
    node = clean_node(node)
    if not node or len(node) < 10:
        logger.debug(f"节点过短或为空，已弃用: {node[:50]}...")
        return None

    def validate_host_port(host: str, port_str: str) -> bool:
        if not (host and port_str and port_str.isdigit()):
            return False
        if not is_valid_ip(host) and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$', host):
            return False
        port = int(port_str)
        return 1 <= port <= 65535

    try:
        if node.startswith("hysteria2://"):
            parts = node[len("hysteria2://"):].split('?')
            if len(parts) < 1:
                logger.debug(f"Hysteria2节点缺少地址部分，已弃用: {node[:50]}...")
                return None
            host_port = parts[0].split(':')
            if len(host_port) != 2:
                logger.debug(f"Hysteria2节点地址格式错误，已弃用: {node[:50]}...")
                return None
            if validate_host_port(host_port[0], host_port[1]) and 'password' in node:
                return node
            logger.debug(f"Hysteria2节点缺少密码或主机无效，已弃用: {node[:50]}...")
            return None

        elif node.startswith("vmess://"):
            decoded = decode_base64_content(node[len("vmess://"):])
            if not decoded:
                logger.debug(f"VMess节点Base64解码失败，已弃用: {node[:50]}...")
                return None
            try:
                data = json.loads(decoded)
                if all(k in data for k in ['v', 'ps', 'add', 'port', 'id']) and validate_host_port(data['add'], str(data['port'])):
                    return node
                logger.debug(f"VMess节点缺少必要字段或主机无效，已弃用: {node[:50]}...")
                return None
            except json.JSONDecodeError:
                logger.debug(f"VMess节点JSON解析失败，已弃用: {node[:50]}...")
                return None

        elif node.startswith("trojan://"):
            parts = node[len("trojan://"):].split('@')
            if len(parts) < 2:
                logger.debug(f"Trojan节点缺少密码或地址，已弃用: {node[:50]}...")
                return None
            password_part = parts[0]
            host_port_part = parts[1].split('#')[0].split('?')[0]
            host_port = host_port_part.split(':')
            if len(host_port) != 2:
                logger.debug(f"Trojan节点地址格式错误，已弃用: {node[:50]}...")
                return None
            if password_part and validate_host_port(host_port[0], host_port[1]):
                return node
            logger.debug(f"Trojan节点密码或主机无效，已弃用: {node[:50]}...")
            return None

        elif node.startswith("ss://"):
            encoded_str = node[len("ss://"):].split('#')[0].split('?')[0]
            if '@' not in encoded_str:
                decoded = decode_base64_content(encoded_str)
                if not decoded:
                    logger.debug(f"SS节点Base64解码失败，已弃用: {node[:50]}...")
                    return None
                parts = decoded.split('@')
            else:
                parts = encoded_str.split('@')
            if len(parts) < 2:
                logger.debug(f"SS节点格式错误，缺少加密或地址，已弃用: {node[:50]}...")
                return None
            method_password_part, host_port_part = parts
            try:
                method, password = method_password_part.split(':', 1)
                host, port = host_port_part.split(':', 1)
                if method and password and validate_host_port(host, port):
                    return node
                logger.debug(f"SS节点加密方式、密码或主机无效，已弃用: {node[:50]}...")
                return None
            except ValueError:
                logger.debug(f"SS节点格式解析错误，已弃用: {node[:50]}...")
                return None

        elif node.startswith("ssr://"):
            decoded = decode_base64_content(node[len("ssr://"):])
            if not decoded:
                logger.debug(f"SSR节点Base64解码失败，已弃用: {node[:50]}...")
                return None
            parts = decoded.split(':')
            if len(parts) < 6:
                logger.debug(f"SSR节点缺少必要部分，已弃用: {node[:50]}...")
                return None
            host, port, protocol, method, obfs, password_b64 = parts[:6]
            if validate_host_port(host, port) and protocol and method and obfs and password_b64:
                return node
            logger.debug(f"SSR节点参数或主机无效，已弃用: {node[:50]}...")
            return None

        elif node.startswith("vless://"):
            parts = node[len("vless://"):].split('@')
            if len(parts) < 2:
                logger.debug(f"VLESS节点缺少UUID或地址，已弃用: {node[:50]}...")
                return None
            uuid_part, host_port_params = parts
            host, port = host_port_params.split('?')[0].split(':', 1)
            if re.match(r'^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', uuid_part) and validate_host_port(host, port):
                return node
            logger.debug(f"VLESS节点UUID或主机无效，已弃用: {node[:50]}...")
            return None

        logger.debug(f"未知或不符合协议的节点格式，已弃用: {node[:100]}...")
        return None
    except Exception as e:
        logger.debug(f"节点验证过程中出现异常，已弃用: {node[:50]}... 错误: {e}")
        return None

async def process_url(url: str, processed_urls: Set[str], all_nodes: Dict[str, Set[str]], semaphore: asyncio.Semaphore, config: Config, depth: int = 0) -> None:
    """递归处理URL，提取和验证节点。"""
    base_url = url.split('#')[0].split('?')[0]
    if base_url in processed_urls:
        logger.debug(f"规范化后的URL已处理: {url} -> {base_url}")
        return
    processed_urls.add(base_url)

    logger.info(f"处理URL (深度 {depth}): {url}")
    content, resolved_url = await fetch_url_content(url, semaphore, config)
    if not content:
        logger.warning(f"无法获取内容: {url}，跳过节点提取")
        return

    nodes, new_urls = parse_and_extract_nodes(content, depth, config, resolved_url)
    if resolved_url not in all_nodes:
        all_nodes[resolved_url] = set()

    for node in nodes:
        valid_node = validate_node(node)
        if valid_node:
            all_nodes[resolved_url].add(valid_node)
        else:
            logger.debug(f"节点 '{node[:50]}...' 因不符合要求被弃用")

    logger.info(f"URL {resolved_url}: 发现 {len(all_nodes[resolved_url])} 个有效节点")

    if depth < config.MAX_DEPTH:
        tasks = [
            process_url(new_url, processed_urls, all_nodes, semaphore, config, depth + 1)
            for new_url in new_urls if new_url.split('#')[0].split('?')[0] not in processed_urls
        ]
        if tasks:
            logger.info(f"发现 {len(tasks)} 个新链接 (深度 {depth + 1})")
            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                logger.error("异步任务被取消，停止处理新链接")
                raise

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
    all_nodes: Dict[str, Set[str]] = {}
    processed_urls: Set[str] = set()
    semaphore = asyncio.Semaphore(config.CONCURRENT_REQUEST_LIMIT)

    try:
        await asyncio.gather(*[
            process_url(url, processed_urls, all_nodes, semaphore, config)
            for url in source_urls
        ])
    except asyncio.CancelledError:
        logger.error("主任务被取消，保存已有数据")
    except Exception as e:
        logger.error(f"主任务执行失败: {e}")

    logger.info("所有URL处理完毕，开始保存节点")
    async with aiofiles.open(os.path.join(config.DATA_DIR, "node_counts.csv"), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Valid Nodes"])
        total_valid_nodes = 0
        for url, nodes in all_nodes.items():
            valid_count = len(nodes)
            if valid_count > 0:
                output_path = os.path.join(config.DATA_DIR, get_safe_filename(url))
                async with aiofiles.open(output_path, 'w', encoding='utf-8') as node_file:
                    await node_file.write('\n'.join(sorted(nodes)))
                logger.info(f"保存 {valid_count} 个节点到 {output_path}")
            writer.writerow([url, valid_count])
            total_valid_nodes += valid_count

    logger.info(f"任务完成。共发现 {total_valid_nodes} 个有效节点，统计信息已保存")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        logger.error("程序被取消，退出")
    except Exception as e:
        logger.error(f"程序执行失败: {e}")
