import aiohttp
import asyncio
import re
import base64
import yaml
import csv
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging
from concurrent.futures import ThreadPoolExecutor
import time

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 支持的节点协议
NODE_PROTOCOLS = [
    r'hysteria2://', r'vmess://', r'trojan://', 
    r'ss://', r'ssr://', r'vless://'
]

# 节点格式正则表达式，移除后向断言
NODE_PATTERN = re.compile(
    r'(hysteria2|vmess|trojan|ss|ssr|vless)://[^\s]+|' +
    r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|' +
    r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+(?:\?[^\s]*)?(?:#[^\s]*)?'
)

async def fetch_url(session, url, max_retries=3):
    """尝试用HTTP和HTTPS获取网页内容"""
    for protocol in ['http://', 'https://']:
        test_url = url if url.startswith('http') else f"{protocol}{url}"
        for attempt in range(max_retries):
            try:
                async with session.get(test_url, timeout=10) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        logger.warning(f"URL {test_url} 返回状态码 {response.status}")
            except Exception as e:
                logger.error(f"获取 {test_url} 失败: {str(e)}")
                if attempt == max_retries - 1 and protocol == 'https://':
                    return None
            await asyncio.sleep(1)
    return None

def parse_yaml(content):
    """解析YAML格式内容"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return extract_nodes_from_dict(data)
        return []
    except yaml.YAMLError:
        return []

def decode_base64(content):
    """解码Base64内容"""
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return [decoded] if is_valid_node(decoded) else []
    except:
        return []

def extract_nodes_from_dict(data):
    """从字典中提取节点"""
    nodes = []
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, str) and is_valid_node(value):
                nodes.append(value)
            elif isinstance(value, (dict, list)):
                nodes.extend(extract_nodes_from_dict(value) if isinstance(value, dict) else value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str) and is_valid_node(item):
                nodes.append(item)
            elif isinstance(item, (dict, list)):
                nodes.extend(extract_nodes_from_dict(item))
    return nodes

def is_valid_node(node):
    """检查节点格式是否有效"""
    if not node:
        return False
    for protocol in NODE_PROTOCOLS:
        if re.match(protocol, node):
            return True
    # 检查明文节点格式
    if re.match(r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+', node):
        return True
    # 检查Base64格式
    try:
        decoded = base64.b64decode(node).decode('utf-8')
        for protocol in NODE_PROTOCOLS:
            if re.match(protocol, decoded):
                return True
    except:
        pass
    return False

async def parse_content(content):
    """解析网页内容"""
    nodes = []
    
    # 尝试直接提取节点
    found_nodes = re.findall(NODE_PATTERN, content)
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node)])
    
    # 尝试解析为HTML
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    found_nodes = re.findall(NODE_PATTERN, text)
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node)])
    
    # 尝试解析YAML
    nodes.extend(parse_yaml(content))
    
    # 尝试解析Base64
    nodes.extend(decode_base64(content))
    
    return list(set(nodes))  # 去重

async def test_node(node):
    """简单测试节点连通性"""
    try:
        # 这里实现一个简单的ping测试，实际可能需要根据协议类型实现更复杂的测试
        parsed = urlparse(node)
        if parsed.scheme in ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']:
            # 模拟测试，实际需要根据协议实现
            return node[:5] if await asyncio.sleep(0.1) else None
        return node[:5] if parsed.scheme else None
    except:
        return None

async def process_nodes(nodes):
    """并行测试节点"""
    valid_nodes = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(executor, lambda n=n: asyncio.run(test_node(n))) for n in nodes]
        results = await asyncio.gather(*[loop.create_task(asyncio.sleep(0)) or t for t in tasks])
        valid_nodes = [r for r in results if r]
    return valid_nodes

async def process_url(session, url):
    """处理单个URL"""
    content = await fetch_url(session, url)
    if not content:
        return url, []
    
    nodes = await parse_content(content)
    # 保存原始节点
    os.makedirs('data/raw', exist_ok=True)
    with open(f'data/raw/{urlparse(url).netloc}.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(nodes))
    
    # 测试节点
    valid_nodes = await process_nodes(nodes)
    return url, valid_nodes

async def main():
    """主函数"""
    os.makedirs('data', exist_ok=True)
    
    # 读取sources.list
    try:
        with open('sources.list', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error("sources.list 文件不存在")
        return
    
    # 并行处理URL
    async with aiohttp.ClientSession() as session:
        tasks = [process_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
    
    # 保存统计信息
    with open('data/stats.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        all_nodes = []
        for url, nodes in results:
            writer.writerow([url, len(nodes)])
            all_nodes.extend(nodes)
    
    # 保存所有有效节点
    with open('data/all.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(set(all_nodes)))

if __name__ == '__main__':
    start_time = time.time()
    asyncio.run(main())
    logger.info(f"处理完成，耗时 {time.time() - start_time:.2f} 秒")
