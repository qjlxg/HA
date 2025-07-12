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
import geoip2.database
import socket
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
    retries: int = 1  # 重试次数设置为 1
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36'
    ])
    cache_ttl: int = 3600  # 1小时
    max_depth: int = 0
    proxy_crawl: Optional[str] = None
    geoip: Dict[str, str | bool] = field(default_factory=lambda: {
        'db_path': os.path.join("data", "GeoLite2-Country.mmdb"),
        'enable_geo_rename': True
    })
    node_test: Dict[str, int | bool] = field(default_factory=lambda: {
        'enable': False,
        'test_url': 'http://www.google.com/generate_204',
        'test_timeout': 5,
        'test_concurrency': 50
    })
    verify_ssl: bool = False  # 默认不验证 SSL 证书

# --- 全局变量 ---
url_cache: Dict[str, Dict] = {}
all_nodes_global: List[str] = []
nodes_lock = asyncio.Lock()
failed_urls_list: List[str] = []

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
            async for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    if not re.match(r'^[a-zA-Z]+://', stripped_line):
                        logger.warning(f"URL '{stripped_line}' 缺少协议头，默认添加 'https://'。")
                        stripped_line = 'https://' + stripped_line
                    urls.append(stripped_line)
            return urls
    except Exception as e:
        logger.error(f"读取源文件失败 {sources_file}: {e}")
        return []

async def fetch_url_content(client: httpx.AsyncClient, url: str, config: CrawlerConfig) -> Tuple[Optional[str], Optional[str]]:
    """安全地异步获取 URL 内容，处理错误。"""
    headers = {'User-Agent': random.choice(config.user_agents)}
    for attempt in range(config.retries):
        try:
            response = await client.get(url, headers=headers, timeout=config.timeout, follow_redirects=True)
            response.raise_for_status()
            logger.info(f"HTTP Request: GET {url} \"HTTP/1.1 {response.status_code}\"")
            return response.text, response.headers.get('Content-Type', '').lower()
        except httpx.RequestError as e:
            error_type = type(e).__name__
            logger.warning(f"{url} 连接错误 ({error_type}: {e}) (尝试 {attempt + 1}/{config.retries})。")
            if attempt < config.retries - 1:
                await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"获取 URL 失败 {url}: {e}", exc_info=True)
            break
    failed_urls_list.append(url)
    return None, None

def extract_proxies_from_text(text: str) -> List[str]:
    """从文本中提取 IP:Port 格式的代理和各种 URL 格式的代理。"""
    proxies = set()
    ip_port_matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', text)
    proxies.update(ip_port_matches)
    node_url_matches = re.findall(r'(vmess|ss|trojan|vless|hysteria2|ssr):\/\/\S+', text)
    proxies.update(node_url_matches)
    try:
        json_data = json.loads(text)
        if isinstance(json_data, dict) and 'proxies' in json_data and isinstance(json_data['proxies'], list):
            for proxy_obj in json_data['proxies']:
                if isinstance(proxy_obj, dict) and 'type' in proxy_obj and 'server' in proxy_obj and 'port' in proxy_obj:
                    if proxy_obj['type'].lower() == 'ss':
                        proxies.add(f"ss://{proxy_obj.get('cipher','')}:{proxy_obj.get('password','')}@{proxy_obj['server']}:{proxy_obj['port']}#{proxy_obj.get('name','')}")
                    elif proxy_obj['type'].lower() == 'vmess':
                        proxies.add(f"vmess://clash-json-{proxy_obj['server']}:{proxy_obj['port']}#{proxy_obj.get('name','')}")
        elif isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, str) and (item.startswith('vmess://') or item.startswith('ss://') or item.startswith('trojan://')):
                    proxies.add(item)
    except json.JSONDecodeError:
        pass
    logger.info(f"从文本中提取到 {len(proxies)} 个代理节点: {proxies}")
    return list(proxies)

def extract_links(html_content: str, base_url: str) -> List[str]:
    """从 HTML 内容中提取所有链接。"""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc:
            links.add(full_url)
    return list(links)

async def save_processed_nodes_to_file(nodes_info: List[Dict], filename: str):
    """异步将处理后的节点信息（字典列表）保存到文件。"""
    filepath = os.path.join(config.data_dir, filename)
    async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
        for node_info in nodes_info:
            reconstructed_url = ""
            if node_info.get('protocol') and node_info.get('server') and node_info.get('port'):
                reconstructed_url = f"{node_info['protocol']}://{node_info['server']}:{node_info['port']}#{node_info.get('remark', '')}"
            else:
                reconstructed_url = f"{node_info.get('remark', 'NoRemark')}-{node_info.get('server')}:{node_info.get('port')}"
            await f.write(f"{reconstructed_url}\n")
    logger.info(f"已将 {len(nodes_info)} 个节点保存到文件: {filepath}。")

async def save_nodes_as_clash_config(filename: str, nodes_info: List[Dict]):
    """将处理后的节点信息（字典列表）保存为 Clash 配置文件。"""
    proxies = []
    for node_info in nodes_info:
        clash_proxy = {
            'name': node_info.get('remark', f"{node_info['server']}:{node_info['port']}"),
            'server': node_info['server'],
            'port': node_info['port'],
            'type': node_info['protocol'].upper() if node_info['protocol'] != 'ss' else 'ss',
        }
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
        elif node_info['protocol'] == 'ss':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['cipher'] = node_info.get('method')
        elif node_info['protocol'] == 'trojan':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['tls'] = node_info.get('tls', False)
            clash_proxy['sni'] = node_info.get('sni', node_info['server'])
        elif node_info['protocol'] == 'hysteria2':
            clash_proxy['password'] = node_info.get('password')
            clash_proxy['obfs'] = node_info.get('obfs')
            clash_proxy['obfs-password'] = node_info.get('obfs_param')
            clash_proxy['tls'] = node_info.get('tls', True)
            clash_proxy['sni'] = node_info.get('sni', node_info['server'])
            clash_proxy['alpn'] = ['h2']
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
            {'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT'] + [p['name'] for p in proxies]},
            {'name': 'DIRECT', 'type': 'direct'}
        ],
        'rules': ['MATCH,PROXY']
    }
    filepath = os.path.join(config.data_dir, filename)
    async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
        await f.write(yaml.dump(clash_config, allow_unicode=True, sort_keys=False))
    logger.info(f"已将 Clash 配置保存到 {filepath}。")

async def save_node_counts_to_csv(filename: str, nodes_info: List[Dict]):
    """异步保存节点统计信息到 CSV 文件。"""
    filepath = os.path.join(config.data_dir, filename)
    node_counts = defaultdict(int)
    for node_info in nodes_info:
        country = node_info.get('remark', 'Unknown').split('-')[0]
        if not country or len(country) > 50:
            country = "Unknown"
        node_counts[country] += 1
    async with aiofiles.open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        await f.write(['Country', 'Count'])
        for country, count in sorted(node_counts.items()):
            await f.write([country, count])
    logger.info(f"节点统计信息已保存到 {filepath}。")

async def debug_duplicate_nodes(unique_nodes_info: List[Dict], config: CrawlerConfig):
    """记录去重结果。"""
    logger.info(f"去重后剩余 {len(unique_nodes_info)} 个唯一节点。")

async def process_url(client: httpx.AsyncClient, url_queue: asyncio.Queue, processed_results_queue: asyncio.Queue, config: CrawlerConfig):
    """异步处理单个 URL，抓取代理并发现新链接。"""
    while True:
        try:
            url_info = await url_queue.get()
            url = url_info['url']
            current_depth = url_info['depth']
            original_url_base = url_info['original_url_base']
            logger.info(f"正在处理 URL: {url} (深度: {current_depth})。")
            current_time = time.time()
            if url in url_cache:
                last_processed_time = url_cache[url].get('timestamp', 0)
                cached_content = url_cache[url].get('content')
                if (current_time - last_processed_time) < config.cache_ttl and cached_content:
                    logger.info(f"{url} 内容未变更，使用缓存数据。")
                    proxies = extract_proxies_from_text(cached_content)
                    new_links = extract_links(cached_content, url) if current_depth < config.max_depth else []
                    logger.info(f"{url} 内容未变更，使用缓存数据。提取节点数: {len(proxies)}, 发现新URL数: {len(new_links)}。")
                    await processed_results_queue.put({'url': url, 'status': 'SKIPPED_UNCHANGED'})
                    async with nodes_lock:
                        all_nodes_global.extend(proxies)
                    for link in new_links:
                        if link not in url_cache and link not in [item['url'] for item in url_queue._queue]:
                            await url_queue.put({'url': link, 'depth': current_depth + 1, 'original_url_base': original_url_base})
                    url_queue.task_done()
                    continue
                else:
                    logger.info(f"{url} 缓存已过期，重新抓取。")
            content, content_type = await fetch_url_content(client, url, config)
            if content:
                url_cache[url] = {'content': content, 'timestamp': time.time()}
                proxies = extract_proxies_from_text(content)
                new_links = []
                if "html" in content_type:
                    logger.info(f"内容被识别为 HTML 格式。")
                    if current_depth < config.max_depth:
                        new_links = extract_links(content, url)
                        for link in new_links:
                            if link not in url_cache and link not in [item['url'] for item in url_queue._queue]:
                                await url_queue.put({'url': link, 'depth': current_depth + 1, 'original_url_base': original_url_base})
                else:
                    logger.info(f"内容被识别为纯文本格式。")
                async with nodes_lock:
                    all_nodes_global.extend(proxies)
                await processed_results_queue.put({'url': url, 'status': 'PROCESSED_SUCCESS'})
            else:
                logger.error(f"无法获取或处理 URL: {url}。")
                await processed_results_queue.put({'url': url, 'status': 'FAILED'})
                failed_urls_list.append(url)
            url_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"处理 URL 时发生未预期错误: {e}", exc_info=True)
            url_queue.task_done()

# --- 主逻辑 ---
async def main():
    start_time_total = time.time()
    global config
    config = CrawlerConfig()
    os.makedirs(config.data_dir, exist_ok=True)
    global url_cache
    url_cache = await load_cache(config.cache_file)
    source_urls = await read_sources(config.sources_file)
    if not source_urls:
        logger.error("未找到源 URL，请检查 sources.list 文件。")
        return
    logger.info(f"成功读取 {len(source_urls)} 个源 URL。")
    url_queue = asyncio.Queue()
    processed_results_queue = asyncio.Queue()
    client_args = {
        'timeout': config.timeout,
        'http2': True,
        'verify': config.verify_ssl
    }
    if config.proxy_crawl:
        client_args['proxies'] = {'all://': config.proxy_crawl}
    async with httpx.AsyncClient(**client_args) as client:
        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        for url in source_urls:
            await url_queue.put({'url': url, 'depth': 0, 'original_url_base': url})
        tasks = []
        for _ in range(config.concurrency_limit):
            task = asyncio.create_task(process_url(client, url_queue, processed_results_queue, config))
            tasks.append(task)
        await url_queue.join()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("开始去重和 GeoIP 命名。")
        unique_nodes_info = await deduplication_module.deduplicate_and_rename_nodes(
            all_nodes_global,
            resolver,
            config.geoip['db_path']
        )
        await save_processed_nodes_to_file(unique_nodes_info, "all_nodes.txt")
        await save_nodes_as_clash_config("clash_config.yaml", unique_nodes_info)
        await save_node_counts_to_csv(config.node_counts_file, unique_nodes_info)
        await save_cache(config.cache_file, url_cache)
        await debug_duplicate_nodes(unique_nodes_info, config)
        if config.node_test.get('enable', False):
            logger.info("节点活跃度测试功能尚未完全适配新的数据结构。")
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
    logger.info(f"总计提取唯一节点: {len(unique_nodes_info)}。")
    logger.info("状态统计:")
    for status, count in status_counts.items():
        logger.info(f"  {status}: {count} 个。")
    logger.info(f"总耗时: {total_elapsed_time:.2f} 秒。")

if __name__ == "__main__":
    asyncio.run(main())
