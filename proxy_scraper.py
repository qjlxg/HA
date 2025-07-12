import re
import os
import csv
import base64
import yaml
import json
import hashlib
import random
import warnings
import time
import asyncio
from urllib.parse import unquote, urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup
import logging
import httpx
import urllib3
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
import aiofiles
import geoip2.database # 仍然需要导入，因为它在 CrawlerConfig 中定义了路径
import socket # 虽然 aiodns 是主要的，但 socket 仍可能是某些低层操作的依赖
import aiodns
from functools import lru_cache

# --- 导入去重模块 ---
import deduplication_module

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- 数据类定义 ---
@dataclass
class CrawlerConfig:
    """爬虫配置类"""
    data_dir: str = "data"
    sources_file: str = "sources.list"
    node_counts_file: str = field(default_factory=lambda: os.path.join("data", "node_counts.csv"))
    cache_file: str = field(default_factory=lambda: os.path.join("data", "url_cache.json"))
    failed_urls_file: str = field(default_factory=lambda: os.path.join("data", "failed_urls.txt"))
    duplicate_nodes_file: str = field(default_factory=lambda: os.path.join("data", "duplicate_nodes.txt"))
    concurrency_limit: int = 10
    timeout: int = 15
    retries: int = 1 # 修改：重试次数设置为1，即不重试
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36'
    ])
    # 缓存时间 TTL (秒)
    cache_ttl: int = 3600 # 1小时
    # 爬取深度，0 表示只处理初始 URL
    max_depth: int = 0
    # 代理设置，用于爬取时通过代理访问
    proxy_crawl: Optional[str] = None # 'http://user:pass@host:port' or 'socks5://user:pass@host:port'
    # GeoIP 配置
    geoip: Dict[str, str | bool] = field(default_factory=lambda: {
        'db_path': os.path.join("data", "GeoLite2-Country.mmdb"),
        'enable_geo_rename': True # 是否启用 GeoIP 命名和去重
    })
    # 节点测试配置
    node_test: Dict[str, int | bool] = field(default_factory=lambda: {
        'enable': True, # 默认启用节点测试
        'test_url': 'http://www.google.com/generate_204', # 测试连通性的URL
        'test_timeout': 5,
        'test_concurrency': 50
    })
    # 新增：是否验证 SSL 证书
    verify_ssl: bool = False # 修改：默认不验证 SSL 证书，以解决 CERTIFICATE_VERIFY_FAILED 错误
    # 新增：最大保存节点数量
    max_nodes_to_save: Optional[int] = None # 默认不限制，例如设置为 1000 限制为 1000 个

# --- 全局变量 ---
url_cache: Dict[str, Dict] = {} # 存储 URL 内容和上次抓取时间
all_nodes_global: List[str] = [] # 存储所有抓取到的原始节点 URL
nodes_lock = asyncio.Lock() # 异步锁，用于保护 all_nodes_global
failed_urls_list: List[str] = []
# duplicate_nodes_debug_list: List[str] = [] # 此列表现在由 deduplication_module 内部处理或不再需要

# --- 缓存管理 ---
async def load_cache(cache_file: str) -> Dict[str, Dict]:
    if os.path.exists(cache_file):
        try:
            async with aiofiles.open(cache_file, mode='r', encoding='utf-8') as f:
                content = await f.read()
                return json.loads(content)
        except Exception as e:
            logger.warning(f"加载缓存文件失败 {cache_file}: {e}")
    return {}

async def save_cache(cache_file: str, cache_data: Dict[str, Dict]):
    try:
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        async with aiofiles.open(cache_file, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(cache_data, indent=4, ensure_ascii=False))
        logger.info(f"已保存缓存文件到 {cache_file}。")
    except Exception as e:
        logger.error(f"保存缓存文件失败 {cache_file}: {e}")

# --- 辅助函数 ---
async def read_sources(sources_file: str) -> List[str]:
    """异步读取源 URL 列表，并确保每个 URL 都有协议头。"""
    if not os.path.exists(sources_file):
        logger.error(f"源文件未找到: {sources_file}")
        return []
    urls = []
    try:
        async with aiofiles.open(sources_file, mode='r', encoding='utf-8') as f:
            async for line in f: # 使用 async for 逐行读取
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    # 检查是否包含协议头
                    if not re.match(r'^[a-zA-Z]+://', stripped_line):
                        logger.warning(f"URL '{stripped_line}' 缺少协议头，默认添加 'https://'。")
                        stripped_line = 'https://' + stripped_line
                    urls.append(stripped_line)
            return urls
    except Exception as e:
        logger.error(f"读取源文件失败 {sources_file}: {e}")
        return []

async def fetch_url_content(client: httpx.AsyncClient, url: str, config: CrawlerConfig) -> Tuple[Optional[str], Optional[str]]:
    """安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。"""
    headers = {'User-Agent': random.choice(config.user_agents)}

    parsed_url = urlparse(url)
    netloc_path_query_fragment = parsed_url.netloc + parsed_url.path
    if parsed_url.query:
        netloc_path_query_fragment += '?' + parsed_url.query
    if parsed_url.fragment:
        netloc_path_query_fragment += '#' + parsed_url.fragment

    # 尝试顺序：HTTP -> HTTPS
    urls_to_try = [
        f"http://{netloc_path_query_fragment}",
        f"https://{netloc_path_query_fragment}"
    ]

    for current_attempt_url in urls_to_try:
        try:
            # client.get() 不再需要 verify 参数，因为它已在 AsyncClient 构造函数中设置
            response = await client.get(current_attempt_url, headers=headers, timeout=config.timeout, follow_redirects=True)
            response.raise_for_status() # 检查 HTTP 错误 (4xx, 5xx)

            # 修复：移除对 response.reason 的引用
            logger.info(f"HTTP Request: GET {current_attempt_url} \"HTTP/1.1 {response.status_code}\"")
            return response.text, response.headers.get('Content-Type', '').lower()
        except httpx.RequestError as e:
            error_type = type(e).__name__
            logger.warning(f"{current_attempt_url} 连接错误 ({error_type}: {e})。")
            # 不进行重试，直接尝试下一个协议或退出
            continue # Try the next URL in urls_to_try list

    # 如果所有尝试都失败了
    failed_urls_list.append(url) # 将原始 URL 添加到失败列表
    return None, None

def extract_proxies_from_text(text: str) -> List[str]:
    """从文本中提取 IP:Port 格式的代理和各种 URL 格式的代理。"""
    proxies = set()

    # 匹配 IP:Port 格式
    ip_port_matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', text)
    proxies.update(ip_port_matches)

    # 匹配 vmess://, ss://, trojan://, vless://, hysteria2://, ssr:// 格式
    # 这个正则表达式可能需要根据实际遇到的复杂 URL 格式进行调整
    # 匹配模式：协议头:// 后面跟着非空白字符，直到遇到空白字符或行尾
    node_url_matches = re.findall(r'(vmess|ss|trojan|vless|hysteria2|ssr):\/\/\S+', text)
    proxies.update(node_url_matches)

    # 从 JSON 中提取，兼容性差，最好是先判断是否为 JSON
    try:
        json_data = json.loads(text)
        if isinstance(json_data, dict) and 'proxies' in json_data and isinstance(json_data['proxies'], list):
            for proxy_obj in json_data['proxies']:
                # 假设 Clash 的 proxy 定义可以转化为 URL
                if isinstance(proxy_obj, dict) and 'type' in proxy_obj and 'server' in proxy_obj and 'port' in proxy_obj:
                    # 这是一个简化的转换，实际需要更复杂的逻辑
                    if proxy_obj['type'].lower() == 'ss':
                        proxies.add(f"ss://{proxy_obj.get('cipher','')}:{proxy_obj.get('password','')}@{proxy_obj['server']}:{proxy_obj['port']}#{proxy_obj.get('name','')}")
                    elif proxy_obj['type'].lower() == 'vmess':
                         # Clash VMess 转 VMess URL (简化)
                         # 这是一个复杂的转换，需要逆向构造 base64 编码的 JSON
                         # 暂时只添加一个标识，表示这是一个来自Clash JSON的VMess
                         proxies.add(f"vmess://clash-json-{proxy_obj['server']}:{proxy_obj['port']}#{proxy_obj.get('name','')}")
                    # TODO: 其他协议的转换
        elif isinstance(json_data, list): # 可能直接是节点 URL 列表
            for item in json_data:
                if isinstance(item, str) and (item.startswith('vmess://') or item.startswith('ss://') or item.startswith('trojan://') or item.startswith('ssr://') or item.startswith('vless://') or item.startswith('hysteria2://')):
                    proxies.add(item)
    except json.JSONDecodeError:
        pass # 不是 JSON 格式，忽略

    return list(proxies)

def extract_links(html_content: str, base_url: str) -> List[str]:
    """从 HTML 内容中提取所有链接。"""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        # 确保是 http 或 https 协议，并且是相对或绝对路径，而不是锚点或 js
        if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc:
            links.add(full_url)
    return list(links)

async def save_raw_nodes_to_file(nodes_list: List[str], filename: str, config: CrawlerConfig):
    """异步将原始抓取到的节点 URL 保存到文件。"""
    filepath = os.path.join(config.data_dir, filename)
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            for node_url in nodes_list:
                await f.write(f"{node_url}\n")
        logger.info(f"已将 {len(nodes_list)} 个原始节点保存到 {filepath}。")
    except Exception as e:
        logger.error(f"保存原始节点文件失败: {e}")

async def save_processed_nodes_to_file(nodes_info: List[Dict], filename: str, config: CrawlerConfig):
    """异步将处理后的节点信息（字典列表）保存到文件。"""
    filepath = os.path.join(config.data_dir, filename)
    
    nodes_to_save = nodes_info
    if config.max_nodes_to_save is not None and len(nodes_info) > config.max_nodes_to_save:
        nodes_to_save = nodes_info[:config.max_nodes_to_save]
        logger.info(f"节点数量超过限制 ({config.max_nodes_to_save})，只保存前 {len(nodes_to_save)} 个节点。")

    async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
        # 这里需要将节点信息字典转换回可读的字符串形式，例如原始 URL 或自定义格式
        # 为了简洁，暂时只保存 remark + server:port
        for node_info in nodes_to_save:
            # 尝试根据协议重新构建 URL，如果失败则使用简化格式
            reconstructed_url = ""
            if node_info.get('protocol') and node_info.get('server') and node_info.get('port'):
                # 这是一个非常简化的重建，完整重建需要每个协议的详细逻辑
                reconstructed_url = f"{node_info['protocol']}://{node_info['server']}:{node_info['port']}#{node_info.get('remark', '')}"
            else:
                reconstructed_url = f"{node_info.get('remark', 'NoRemark')}-{node_info.get('server')}:{node_info.get('port')}"
            
            await f.write(f"{reconstructed_url}\n")
    logger.info(f"已将 {len(nodes_to_save)} 个节点保存到文件: {filepath}。")


async def save_nodes_as_clash_config(filename: str, nodes_info: List[Dict], config: CrawlerConfig):
    """将处理后的节点信息（字典列表）保存为 Clash 配置文件。"""
    proxies = []
    for node_info in nodes_info:
        clash_proxy = {
            'name': node_info.get('remark', f"{node_info['server']}:{node_info['port']}"),
            'server': node_info['server'],
            'port': node_info['port'],
            'type': node_info['protocol'].upper() if node_info['protocol'] != 'ss' else 'ss', # SS协议在Clash中是小写
        }
        # 根据协议补充其他参数
        if node_info['protocol'] == 'vmess':
            clash_proxy['uuid'] = node_info.get('uuid')
            clash_proxy['alterId'] = node_info.get('alterId', 0)
            clash_proxy['cipher'] = node_info.get('security', 'auto')
            clash_proxy['network'] = node_info.get('network', 'tcp')
            if node_info.get('tls'):
                clash_proxy['tls'] = True
                clash_proxy['servername'] = node_info.get('sni', node_info['server'])
            if node_info.get('network') == 'ws':
                clash_proxy['ws-path'] = node_info.get('path', '/')
                clash_proxy['ws-headers'] = {'Host': node_info.get('host', node_info.get('sni', node_info['server']))}
            # ... 其他 VMess 参数
        elif node_info['protocol'] == 'ss':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['cipher'] = node_info.get('method')
            # ... 其他 SS 参数
        elif node_info['protocol'] == 'ssr':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['cipher'] = node_info.get('method')
            clash_proxy['protocol'] = node_info.get('protocol_ssr')
            clash_proxy['obfs'] = node_info.get('obfs')
            clash_proxy['obfsparam'] = node_info.get('obfsparam')
            clash_proxy['protoparam'] = node_info.get('protoparam')
        elif node_info['protocol'] == 'trojan':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['tls'] = node_info.get('tls', False)
            clash_proxy['sni'] = node_info.get('sni', node_info['server'])
            # ... 其他 Trojan 参数
        elif node_info['protocol'] == 'vless':
            clash_proxy['uuid'] = node_info.get('uuid')
            clash_proxy['network'] = node_info.get('network', 'tcp')
            if node_info.get('tls'):
                clash_proxy['tls'] = True
                clash_proxy['servername'] = node_info.get('sni', node_info['server'])
            clash_proxy['flow'] = node_info.get('flow')
            if node_info.get('network') == 'ws':
                clash_proxy['ws-path'] = node_info.get('path', '/')
                clash_proxy['ws-headers'] = {'Host': node_info.get('host', node_info.get('sni', node_info['server']))}
        elif node_info['protocol'] == 'hysteria2':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['obfs'] = node_info.get('obfs')
            clash_proxy['obfs-password'] = node_info.get('obfs_param')
            clash_proxy['tls'] = node_info.get('tls', True)
            clash_proxy['sni'] = node_info.get('sni', node_info['server'])
            clash_proxy['alpn'] = ['h2'] # Default for Hysteria2
        # TODO: 适配 HTTP, SOCKS5 等

        proxies.append(clash_proxy)

    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': ['DIRECT'] + [p['name'] for p in proxies]
            },
            {
                'name': 'DIRECT',
                'type': 'direct'
            }
        ],
        'rules': [
            'MATCH,PROXY'
        ]
    }
    filepath = os.path.join(config.data_dir, filename)
    async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
        await f.write(yaml.dump(clash_config, allow_unicode=True, sort_keys=False))
    logger.info(f"已将 Clash 配置保存到 {filepath}。")

async def save_node_counts_to_csv(filename: str, nodes_info: List[Dict], config: CrawlerConfig):
    """异步保存节点统计信息到 CSV 文件。"""
    filepath = os.path.join(config.data_dir, filename)
    node_counts = defaultdict(int)
    for node_info in nodes_info:
        # 假设 remark 字段已经包含了国家信息，格式为 "Country-OriginalRemark"
        # 或者从 node_info 中直接获取国家信息（如果 deduplication_module 返回了）
        country = node_info.get('remark', 'Unknown').split('-')[0] # 简化的提取国家方式
        if not country or len(country) > 50: # Avoid overly long or invalid country names
            country = "Unknown"
        node_counts[country] += 1

    async with aiofiles.open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        await f.writerow(['Country', 'Count'])
        for country, count in sorted(node_counts.items()):
            await writer.writerow([country, count])
    logger.info(f"节点统计信息已保存到 {filepath}。")

async def debug_duplicate_nodes(unique_nodes_info: List[Dict], config: CrawlerConfig):
    """记录去重过程中被剔除的重复节点 (此函数需要调整以匹配新的去重逻辑输出)。"""
    # 由于 deduplication_module 只返回唯一节点，此函数现在主要用于报告最终去重结果。
    # 如果需要记录被剔除的节点，deduplication_module 内部需要维护一个列表并返回。
    logger.info(f"去重后剩余 {len(unique_nodes_info)} 个唯一节点。")
    # 如果 deduplication_module 能够返回被剔除的节点列表，可以在这里保存
    # if deduplication_module.duplicate_nodes_found_in_last_run:
    #     dup_file = os.path.join(config.data_dir, "duplicate_nodes.txt")
    #     async with aiofiles.open(dup_file, 'w', encoding='utf-8') as f:
    #         for node_url in deduplication_module.duplicate_nodes_found_in_last_run:
    #             await f.write(f"{node_url}\n")
    #     logger.info(f"已将 {len(deduplication_module.duplicate_nodes_found_in_last_run)} 个重复节点记录到 {dup_file}。")

async def test_single_node(node_info: Dict, test_url: str, test_timeout: int) -> bool:
    """测试单个节点是否连通。"""
    protocol = node_info.get('protocol')
    server = node_info.get('server')
    port = node_info.get('port')
    
    if not server or not port:
        logger.debug(f"节点信息不完整，跳过测试: {node_info.get('remark', 'Unknown Node')}")
        return False

    proxies = {}
    if protocol == 'http':
        proxies = {'http://': f"http://{server}:{port}", 'https://': f"http://{server}:{port}"}
    elif protocol == 'socks5':
        proxies = {'http://': f"socks5://{server}:{port}", 'https://': f"socks5://{server}:{port}"}
    else:
        logger.debug(f"协议 {protocol} 暂不支持直接测试，跳过测试: {node_info.get('remark', 'Unknown Node')}")
        return True # 对于不支持直接测试的协议，假设其可用

    try:
        async with httpx.AsyncClient(proxies=proxies, timeout=test_timeout, verify=False) as client:
            response = await client.get(test_url)
            response.raise_for_status()
            logger.info(f"节点 {node_info.get('remark', 'Unknown')} ({server}:{port}) 测试成功。")
            return True
    except httpx.RequestError as e:
        logger.warning(f"节点 {node_info.get('remark', 'Unknown')} ({server}:{port}) 测试失败: {e}")
        return False
    except Exception as e:
        logger.error(f"测试节点 {node_info.get('remark', 'Unknown')} ({server}:{port}) 时发生未知错误: {e}", exc_info=True)
        return False

async def test_and_filter_nodes(nodes_info: List[Dict], config: CrawlerConfig) -> List[Dict]:
    """
    测试并过滤无法连通的节点。
    每个节点将作为代理尝试访问 config.node_test['test_url']。
    注意：此测试目前仅支持 HTTP 和 SOCKS5 代理。
    对于 VMess, Trojan, VLESS, SSR, Hysteria2 等协议，httpx 无法直接作为代理进行测试，因此这些节点会被跳过测试。
    """
    if not config.node_test['enable']:
        logger.info("节点活跃度测试已禁用。")
        return nodes_info

    logger.info(f"开始节点活跃度测试，测试 URL: {config.node_test['test_url']}，并发数: {config.node_test['test_concurrency']}。")
    
    working_nodes = []
    test_url = config.node_test['test_url']
    test_timeout = config.node_test['test_timeout']
    
    semaphore = asyncio.Semaphore(config.node_test['test_concurrency'])

    async def _test_node_with_semaphore(node):
        async with semaphore:
            is_working = await test_single_node(node, test_url, test_timeout)
            if is_working:
                working_nodes.append(node)

    tasks = [_test_node_with_semaphore(node) for node in nodes_info]
    await asyncio.gather(*tasks)

    logger.info(f"节点活跃度测试完成，发现 {len(working_nodes)} 个可用节点。")
    return working_nodes

# --- 主逻辑 ---
async def main():
    start_time_total = time.time()
    current_config = CrawlerConfig() # 使用默认配置
    os.makedirs(current_config.data_dir, exist_ok=True)

    global url_cache
    url_cache = await load_cache(current_config.cache_file)

    source_urls = await read_sources(current_config.sources_file)
    if not source_urls:
        logger.error("未找到源 URL，请检查 sources.list 文件。")
        return

    logger.info(f"成功读取 {len(source_urls)} 个源 URL。")

    url_queue = asyncio.Queue()
    processed_results_queue = asyncio.Queue()

    # 初始化 httpx 客户端
    # 将 verify 参数直接传递给 AsyncClient 构造函数
    client_args = {
        'timeout': current_config.timeout,
        'http2': True,
        'verify': current_config.verify_ssl # 将 verify 参数移到这里
    }
    if current_config.proxy_crawl:
        client_args['proxies'] = {'all://': current_config.proxy_crawl}

    async with httpx.AsyncClient(**client_args) as client:
        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())

        for url in source_urls:
            await url_queue.put({'url': url, 'depth': 0, 'original_url_base': url})

        tasks = []
        for _ in range(current_config.concurrency_limit):
            task = asyncio.create_task(process_url(client, url_queue, processed_results_queue, current_config))
            tasks.append(task)

        await url_queue.join()

        # 取消工作任务
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("所有 URL 抓取完成，开始处理节点。")

        # 保存原始抓取到的节点，以防丢失
        await save_raw_nodes_to_file(all_nodes_global, "raw_nodes.txt", current_config)

        # 调用新的去重模块
        # deduplicate_and_rename_nodes 返回处理后的节点信息字典列表
        unique_nodes_info = await deduplication_module.deduplicate_and_rename_nodes(
            all_nodes_global, # 传递所有抓取到的原始 URL 字符串
            resolver,
            current_config.geoip['db_path']
        )

        # 增强：在所有节点收集完毕后进行活跃度测试 (如果启用)
        if current_config.node_test.get('enable', False):
            unique_nodes_info = await test_and_filter_nodes(unique_nodes_info, current_config)

        # 保存总节点文件 (现在接受字典列表)
        # 这里的 save_processed_nodes_to_file 需要修改以正确处理字典列表
        await save_processed_nodes_to_file(unique_nodes_info, "all.txt", current_config) # 保存到 all.txt

        # 增强：保存 Clash 配置
        # save_nodes_as_clash_config 现在接受字典列表
        await save_nodes_as_clash_config("clash_config.yaml", unique_nodes_info, current_config)

        # 增强：保存节点统计信息
        # save_node_counts_to_csv 现在接受字典列表
        await save_node_counts_to_csv(current_config.node_counts_file, unique_nodes_info, current_config)

        await save_cache(current_config.cache_file, url_cache) # 脚本结束时保存缓存

        # debug_duplicate_nodes 现在只报告结果，不再依赖全局列表
        await debug_duplicate_nodes(unique_nodes_info, current_config)


    # --- 报告生成 ---
    total_processed_urls_count = 0
    status_counts = {'PROCESSED_SUCCESS': 0, 'SKIPPED_UNCHANGED': 0, 'FAILED': 0}
    while not processed_results_queue.empty():
        info = await processed_results_queue.get()
        total_processed_urls_count += 1
        status_counts[info['status']] += 1

    end_time_total = time.time()
    total_elapsed_time = end_time_total - start_time_total

    logger.info("\n--- 处理完成报告 ---")
    logger.info(f"总计处理 {total_processed_urls_count} 个 URL。")
    logger.info(f"总计提取并测试通过的唯一节点: {len(unique_nodes_info)}。")
    logger.info("状态统计:")
    for status, count in status_counts.items():
        logger.info(f"  {status}: {count} 个。")
    logger.info(f"总耗时: {total_elapsed_time:.2f} 秒。")

if __name__ == "__main__":
    asyncio.run(main())
