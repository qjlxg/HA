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
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
import random
import socket

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 支持的节点协议
NODE_PROTOCOLS = [
    r'hysteria2://', r'vmess://', r'trojan://', 
    r'ss://', r'ssr://', r'vless://'
]

# 节点格式正则表达式
NODE_PATTERN = re.compile(
    r'(hysteria2|vmess|trojan|ss|ssr|vless)://[^\s]+|' +
    r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|' +
    r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+(?:\?[^\s]*)?(?:#[^\s]*)?'
)

# 丰富的 User-Agent 列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20250101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/129.0.0.0 Safari/537.36",
]

# 额外的 HTTP 头部
EXTRA_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

def is_valid_url(url):
    """验证 URL 或 IP 是否有效"""
    try:
        # 检查域名格式
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        # 尝试解析 IP 或域名
        socket.getaddrinfo(parsed.netloc, None)
        return True
    except (socket.gaierror, ValueError):
        return False

async def fetch_url(page, url, max_retries=3):
    """使用浏览器模拟获取网页内容，随机选择 User-Agent"""
    if not is_valid_url(url):
        logger.error(f"无效 URL: {url}")
        return None

    user_agent = random.choice(USER_AGENTS)
    headers = {**EXTRA_HEADERS, "User-Agent": user_agent}
    
    for protocol in ['http://', 'https://']:
        test_url = url if url.startswith('http') else f"{protocol}{url}"
        for attempt in range(max_retries):
            try:
                await page.set_extra_http_headers(headers)
                await page.goto(test_url, timeout=30000, wait_until="networkidle")
                content = await page.content()
                logger.info(f"成功获取 {test_url}，使用 User-Agent: {user_agent}")
                return content
            except PlaywrightTimeoutError:
                logger.warning(f"URL {test_url} 加载超时 (尝试 {attempt + 1}/{max_retries})")
            except Exception as e:
                logger.error(f"获取 {test_url} 失败: {str(e)}")
            if attempt < max_retries - 1:
                await asyncio.sleep(random.uniform(1, 3))
        if protocol == 'https://':
            logger.error(f"URL {test_url} 多次尝试失败")
            return None
    return None

def parse_yaml(content):
    """解析YAML格式内容"""
    try:
        data = yaml.safe_load(content)
        if data:
            return extract_nodes_from_dict(data)
        return []
    except yaml.YAMLError:
        logger.error("YAML 解析失败")
        return []

def decode_base64(content):
    """解码Base64内容"""
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        return [decoded] if is_valid_node(decoded) else []
    except:
        return []

def extract_nodes_from_dict(data):
    """从字典或列表中提取节点，确保只返回字符串"""
    nodes = []
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, str) and is_valid_node(value):
                nodes.append(value)
            elif isinstance(value, (dict, list)):
                nodes.extend(extract_nodes_from_dict(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str) and is_valid_node(item):
                nodes.append(item)
            elif isinstance(item, (dict, list)):
                nodes.extend(extract_nodes_from_dict(item))
    return nodes

def is_valid_node(node):
    """检查节点格式是否有效"""
    if not isinstance(node, str):
        return False
    for protocol in NODE_PROTOCOLS:
        if re.match(protocol, node):
            return True
    if re.match(r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+', node):
        return True
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
    
    found_nodes = re.findall(NODE_PATTERN, content)
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node) and is_valid_node(node[0] or node[1] or node[2])])
    
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    found_nodes = re.findall(NODE_PATTERN, text)
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node) and is_valid_node(node[0] or node[1] or node[2])])
    
    nodes.extend(parse_yaml(content))
    nodes.extend(decode_base64(content))
    
    nodes = [node for node in nodes if isinstance(node, str)]
    return list(set(nodes))

async def test_node(node):
    """简单测试节点连通性"""
    try:
        parsed = urlparse(node)
        if parsed.scheme in ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']:
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
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_nodes = [r for r in results if r and not isinstance(r, Exception)]
    return valid_nodes

async def process_url(context, url):
    """处理单个URL"""
    page = await context.new_page()
    content = await fetch_url(page, url)
    await page.close()
    if not content:
        return url, []
    
    nodes = await parse_content(content)
    os.makedirs('data/raw', exist_ok=True)
    with open(f'data/raw/{urlparse(url).netloc}.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(nodes))
    
    valid_nodes = await process_nodes(nodes)
    return url, valid_nodes

async def main():
    """主函数"""
    os.makedirs('data', exist_ok=True)
    
    try:
        with open('sources.list', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error("sources.list 文件不存在")
        return
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        
        tasks = [process_url(context, url) for url in urls if is_valid_url(url)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        await browser.close()
    
    with open('data/stats.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        all_nodes = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"处理 URL 时发生错误: {str(result)}")
                continue
            url, nodes = result
            writer.writerow([url, len(nodes)])
            all_nodes.extend(nodes)
    
    with open('data/all.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(set(all_nodes)))

if __name__ == '__main__':
    start_time = time.time()
    asyncio.run(main())
    logger.info(f"处理完成，耗时 {time.time() - start_time:.2f} 秒")
