
import asyncio
import random
import re
import os
import csv
import aiofiles
import httpx
import yaml
import base64
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import Dict, List, Set, Tuple
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='scraper.log',
    encoding='utf-8'
)
logger = logging.getLogger(__name__)

# 模拟的请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; SM-G9980 Build/RP1A.200720.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36'
]

# 缓存文件路径和有效期（24小时）
CACHE_FILE = 'data/cache.json'
CACHE_DURATION = timedelta(hours=24)

# 支持的代理协议正则表达式
PROXY_PATTERNS = {
    'hysteria2': r'^hysteria2://[a-zA-Z0-9+/@=]+',
    'vmess': r'^vmess://[a-zA-Z0-9+/@=]+',
    'trojan': r'^trojan://[a-zA-Z0-9+/@=]+',
    'ss': r'^ss://[a-zA-Z0-9+/@=]+',
    'ssr': r'^ssr://[a-zA-Z0-9+/@=]+',
    'vless': r'^vless://[a-zA-Z0-9+/@=]+'
}

async def load_cache() -> Dict:
    """加载缓存文件"""
    try:
        async with aiofiles.open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        return {}

async def save_cache(cache: Dict):
    """保存缓存文件"""
    os.makedirs('data', exist_ok=True)
    async with aiofiles.open(CACHE_FILE, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(cache, ensure_ascii=False))

async def fetch_url(url: str, client: httpx.AsyncClient, cache: Dict) -> Tuple[str, str, bool]:
    """获取URL内容，优先HTTP，失败后尝试HTTPS"""
    for scheme in ['http', 'https']:
        full_url = f"{scheme}://{url}"
        cache_key = f"{full_url}_hash"
        cache_time_key = f"{full_url}_time"
        
        # 检查缓存
        if cache_key in cache and cache_time_key in cache:
            cache_time = datetime.fromisoformat(cache[cache_time_key])
            if datetime.now() - cache_time < CACHE_DURATION:
                logger.info(f"使用缓存: {full_url}")
                return full_url, cache[cache_key], False

        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = await client.get(full_url, headers=headers, timeout=10)
            response.raise_for_status()
            content = response.text
            cache[cache_key] = content
            cache[cache_time_key] = datetime.now().isoformat()
            logger.info(f"成功获取: {full_url}")
            return full_url, content, True
        except Exception as e:
            logger.warning(f"{full_url} 获取失败: {str(e)}")
    
    return url, "", False

def validate_node(node: str) -> bool:
    """验证节点格式是否有效"""
    for pattern in PROXY_PATTERNS.values():
        if re.match(pattern, node):
            # 进一步验证节点完整性
            try:
                if node.startswith('vmess://'):
                    decoded = base64.b64decode(node[8:]).decode('utf-8')
                    config = json.loads(decoded)
                    required = {'v', 'ps', 'add', 'port', 'id'}
                    return all(key in config for key in required)
                elif node.startswith('trojan://'):
                    parts = node[9:].split('@')
                    if len(parts) < 2:
                        return False
                    return ':' in parts[1]
                elif node.startswith('ss://'):
                    parts = node[5:].split('@')
                    if len(parts) < 2:
                        return False
                    return ':' in parts[1]
                return True
            except:
                return False
    return False

def parse_and_extract_nodes(content: str) -> List[str]:
    """解析并提取节点"""
    nodes = []
    soup = BeautifulSoup(content, 'html.parser')
    
    # 优先处理特定标签
    for tag in ['pre', 'code', 'textarea']:
        for element in soup.find_all(tag):
            nodes.extend(extract_nodes_from_text(element.get_text()))
    
    # 处理其他内容
    nodes.extend(extract_nodes_from_text(soup.get_text()))
    
    # 验证并清理节点
    valid_nodes = [node[:5] if len(node) > 5 else node for node in nodes if validate_node(node)]
    return valid_nodes

def extract_nodes_from_text(text: str) -> List[str]:
    """从文本中提取节点"""
    nodes = []
    # 尝试解析不同格式
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # 检查是否是支持的协议
        for protocol in PROXY_PATTERNS:
            if line.startswith(protocol):
                nodes.append(line)
                continue
                
        # 尝试解析YAML
        try:
            data = yaml.safe_load(line)
            if isinstance(data, dict):
                nodes.extend(extract_nodes_from_dict(data))
        except:
            pass
            
        # 尝试解析Base64
        try:
            decoded = base64.b64decode(line).decode('utf-8')
            nodes.extend(extract_nodes_from_text(decoded))
        except:
            pass
            
        # 尝试解析JSON
        try:
            data = json.loads(line)
            nodes.extend(extract_nodes_from_dict(data))
        except:
            pass
            
    return nodes

def extract_nodes_from_dict(data: Dict) -> List[str]:
    """从字典中提取节点"""
    nodes = []
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, str) and any(value.startswith(p) for p in PROXY_PATTERNS):
                nodes.append(value)
            elif isinstance(value, (dict, list)):
                nodes.extend(extract_nodes_from_dict(value))
    elif isinstance(data, list):
        for item in data:
            nodes.extend(extract_nodes_from_dict(item))
    return nodes

async def save_nodes(url: str, nodes: List[str]):
    """保存节点到文件"""
    domain = urlparse(url).netloc.split('.')[0]
    filename = f"data/{domain}.txt"
    os.makedirs('data', exist_ok=True)
    async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
        for node in nodes:
            await f.write(f"{node}\n")
    logger.info(f"保存节点到: {filename}")

async def update_csv(url: str, node_count: int):
    """更新CSV统计文件"""
    filename = 'data/statistics.csv'
    os.makedirs('data', exist_ok=True)
    file_exists = os.path.exists(filename)
    
    async with aiofiles.open(filename, 'a', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            await f.write('URL,Node Count,Timestamp\n')
        await f.write(f"{url},{node_count},{datetime.now().isoformat()}\n")

async def crawl_url(url: str, client: httpx.AsyncClient, cache: Dict, visited: Set[str]):
    """递归爬取URL"""
    full_url, content, updated = await fetch_url(url, client, cache)
    if not content:
        return []
        
    nodes = parse_and_extract_nodes(content)
    await save_nodes(full_url, nodes)
    await update_csv(full_url, len(nodes))
    
    # 提取新链接并递归爬取
    soup = BeautifulSoup(content, 'html.parser')
    new_urls = {a['href'] for a in soup.find_all('a', href=True) if a['href'] not in visited}
    
    for new_url in new_urls:
        if not new_url.startswith(('http://', 'https://')):
            new_url = f"http://{new_url}"
        if new_url not in visited:
            visited.add(new_url)
            nodes.extend(await crawl_url(new_url, client, cache, visited))
    
    return nodes

async def main():
    """主函数"""
    cache = await load_cache()
    visited = set()
    
    async with httpx.AsyncClient(http2=True) as client:
        # 读取sources.list
        try:
            async with aiofiles.open('sources.list', 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in await f.read().splitlines() if line.strip()]
        except FileNotFoundError:
            logger.error("sources.list 文件不存在")
            return

        # 并行爬取
        tasks = [crawl_url(url, client, cache, visited) for url in urls]
        await asyncio.gather(*tasks)
        
        # 保存缓存
        await save_cache(cache)
        logger.info("爬取完成")

if __name__ == "__main__":
    asyncio.run(main())
