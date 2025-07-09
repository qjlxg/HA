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
    r'(hV|hysteria2|vmess|trojan|ss|ssr|vless)://[^\s]+|' +
    r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|' +
    r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+(?:\?[^\s]*)?(?:#[^\s]*)?'
)

# 丰富的 User-Agent 列表，涵盖 PC、手机、PDA、iPhone 等设备
USER_AGENTS = [
    # PC 浏览器的 User-Agent
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20250101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Opera/114.0.0.0 Safari/537.36",

    # 手机浏览器的 User-Agent
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.70 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",

    # PDA 和其他设备的 User-Agent
    "Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFOT Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",  # Kindle Fire
    "Mozilla/5.0 (webOS/3.0.2; U; en-US) AppleWebKit/532.2 (KHTML, like Gecko) Version/1.0 Safari/532.2 Pre/3.0",  # Palm Pre
    "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.296 Mobile Safari/534.11+",

    # 其他流行厂商的 User-Agent
    "Mozilla/5.0 (Linux; Android 14; Xiaomi 14 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; HUAWEI Mate 50) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15",  # Firefox iOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) UCBrowser/7.0.185.1002 Safari/537.36",
]

async def fetch_url(page, url, max_retries=3):
    """使用浏览器模拟获取网页内容，随机选择 User-Agent"""
    user_agent = random.choice(USER_AGENTS)
    for protocol in ['http://', 'https://']:
        test_url = url if url.startswith('http') else f"{protocol}{url}"
        for attempt in range(max_retries):
            try:
                await page.set_extra_http_headers({"User-Agent": user_agent})
                await page.goto(test_url, timeout=30000)  # 30秒超时
                await page.wait_for_load_state('networkidle', timeout=30000)
                content = await page.content()
                logger.info(f"成功获取 {test_url}，使用 User-Agent: {user_agent}")
                return content
            except PlaywrightTimeoutError:
                logger.warning(f"URL {test_url} 加载超时 (尝试 {attempt + 1}/{max_retries})")
            except Exception as e:
                logger.error(f"获取 {test_url} 失败: {str(e)}")
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
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
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node) and is_valid_node(node[0] or node[1] or node[2])])
    
    # 尝试解析为HTML
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    found_nodes = re.findall(NODE_PATTERN, text)
    nodes.extend([node[0] or node[1] or node[2] for node in found_nodes if any(node) and is_valid_node(node[0] or node[1] or node[2])])
    
    # 尝试解析YAML
    nodes.extend(parse_yaml(content))
    
    # 尝试解析Base64
    nodes.extend(decode_base64(content))
    
    # 确保所有节点都是字符串
    nodes = [node for node in nodes if isinstance(node, str)]
    return list(set(nodes))  # 去重

async def test_node(node):
    """简单测试节点连通性"""
    try:
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

async def process_url(page, url):
    """处理单个URL"""
    content = await fetch_url(page, url)
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
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        # 并行处理URL
        tasks = [process_url(page, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        await browser.close()
    
    # 保存统计信息
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
    
    # 保存所有有效节点
    with open('data/all.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(set(all_nodes)))

if __name__ == '__main__':
    start_time = time.time()
    asyncio.run(main())
    logger.info(f"处理完成，耗时 {time.time() - start_time:.2f} 秒")
