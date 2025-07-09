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

# 节点格式正则表达式 - 优化：移除Base64部分，由专门函数处理
NODE_PATTERN = re.compile(
    r'(hysteria2|vmess|trojan|ss|ssr|vless)://[^\s]+|' +  # 匹配协议头节点
    r'[^\s:]+:[^\s:]+@[^\s:]+:[0-9]+'  # 匹配 user:pass@host:port 格式的节点
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
        # 如果是 IP 地址，则直接返回 True
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url):
            return True
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        # 尝试解析域名
        socket.gethostbyname(parsed.netloc)
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
    await page.set_extra_http_headers(headers) # 在页面创建后设置一次

    # 尝试添加协议前缀，优先尝试HTTPS
    urls_to_try = []
    if url.startswith('http'):
        urls_to_try.append(url)
    else:
        urls_to_try.append(f"https://{url}")
        urls_to_try.append(f"http://{url}")

    for test_url in urls_to_try:
        for attempt in range(max_retries):
            try:
                await page.goto(test_url, timeout=30000, wait_until="networkidle")
                content = await page.content()
                logger.info(f"成功获取 {test_url}，使用 User-Agent: {user_agent}")
                return content
            except PlaywrightTimeoutError:
                logger.warning(f"URL {test_url} 加载超时 (尝试 {attempt + 1}/{max_retries})")
            except Exception as e:
                logger.error(f"获取 {test_url} 失败: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(random.uniform(1, 3)) # 增加重试间隔
    logger.error(f"URL {url} 多次尝试失败")
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
    """解码Base64内容，返回所有可能的节点"""
    try:
        decoded_bytes = base64.b64decode(content)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore') # 忽略解码错误
        
        # 尝试按行分割，因为base64编码可能包含多行节点
        potential_nodes = decoded_str.splitlines()
        valid_decoded_nodes = [node for node in potential_nodes if is_valid_node(node)]
        return valid_decoded_nodes
    except (base64.binascii.Error, UnicodeDecodeError):
        return []

def extract_nodes_from_dict(data):
    """从字典或列表中递归提取节点，确保只返回字符串"""
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
    """检查节点格式是否有效，现在可以识别出未编码的节点或已经解码的节点"""
    if not isinstance(node, str):
        return False
    
    # 尝试匹配协议头节点或user:pass@host:port格式的节点
    if NODE_PATTERN.match(node):
        return True
    
    # 尝试解码并检查解码后的内容是否是有效节点
    try:
        decoded_node = base64.b64decode(node).decode('utf-8', errors='ignore')
        if NODE_PATTERN.match(decoded_node):
            return True
    except (base64.binascii.Error, UnicodeDecodeError):
        pass # 不是有效的base64编码或者解码后不是有效UTF-8
        
    return False

async def parse_content(content):
    """解析网页内容，提取节点"""
    nodes = set() # 使用集合避免重复
    
    # 1. 直接通过正则表达式匹配
    # re.findall 返回的是一个元组列表，我们需要处理组匹配
    found_regex_matches = NODE_PATTERN.findall(content)
    for match_tuple in found_regex_matches:
        # match_tuple 可能包含多个组，取第一个非空的匹配
        for match in match_tuple:
            if match and is_valid_node(match):
                nodes.add(match)

    # 2. 从文本内容中提取（去除HTML标签）
    try:
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text()
        found_text_matches = NODE_PATTERN.findall(text)
        for match_tuple in found_text_matches:
            for match in match_tuple:
                if match and is_valid_node(match):
                    nodes.add(match)
    except Exception as e:
        logger.warning(f"BeautifulSoup 解析失败: {e}")

    # 3. 尝试解析YAML
    nodes.update(parse_yaml(content))

    # 4. 尝试Base64解码
    nodes.update(decode_base64(content))
    
    return list(nodes) # 返回列表形式

async def test_node(node):
    """简单测试节点连通性 (此处为模拟，实际应调用专业测试库)"""
    # 真实场景下，这里会调用如 `ping` 或 `connect` 到节点服务端口的逻辑
    # 为了演示优化，我们仍然保持其同步且模拟的性质
    try:
        # 模拟一个轻微的耗时操作，表示进行了一次“测试”
        await asyncio.sleep(0.01) # 显著减少睡眠时间
        # 假设所有格式正确的节点都是“有效的”
        if is_valid_node(node):
            return node
    except Exception as e:
        logger.debug(f"节点测试失败 {node[:30]}...: {e}")
    return None

async def process_nodes(nodes):
    """并行测试节点"""
    # 由于 test_node 内部还是异步模拟，这里直接用 asyncio.gather 运行异步任务更合适
    # 如果 test_node 确实需要阻塞执行（如外部库），则 ThreadPoolExecutor 是合适的
    # 假设 test_node 已经是一个 "awaitable" 的函数
    tasks = [test_node(node) for node in nodes]
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
    
    # 确保 data/raw 目录存在
    raw_data_dir = 'data/raw'
    os.makedirs(raw_data_dir, exist_ok=True)
    
    # 获取URL的网络位置作为文件名
    file_name = urlparse(url).netloc.replace(':', '_').replace('/', '_') # 替换可能的文件名非法字符
    if not file_name: # 如果urlparse解析不出netloc，则用hash避免文件名冲突
        file_name = f"unknown_{hash(url)}"

    try:
        with open(f'{raw_data_dir}/{file_name}.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(nodes))
        logger.info(f"原始节点已写入 {raw_data_dir}/{file_name}.txt ({len(nodes)} 个节点)")
    except IOError as e:
        logger.error(f"写入原始节点文件失败 {raw_data_dir}/{file_name}.txt: {e}")
    
    valid_nodes = await process_nodes(nodes)
    return url, valid_nodes

async def main():
    """主函数"""
    os.makedirs('data', exist_ok=True)
    
    try:
        with open('sources.list', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if not urls:
            logger.warning("sources.list 中没有找到有效的 URL。")
            return
    except FileNotFoundError:
        logger.error("sources.list 文件不存在。请确保文件存在并包含要抓取的 URL。")
        return
    except Exception as e:
        logger.error(f"读取 sources.list 文件时发生错误: {e}")
        return

    all_nodes_collected = []
    stats_data = []

    try:
        async with async_playwright() as p:
            # 启动浏览器，可以根据需要选择不同的浏览器或配置
            browser = await p.chromium.launch(headless=True) # 可以改为 False 查看浏览器操作
            context = await browser.new_context()
            
            logger.info(f"开始处理 {len(urls)} 个 URL...")
            
            # 过滤掉无效 URL，并为每个有效 URL 创建任务
            tasks = [process_url(context, url) for url in urls if is_valid_url(url)]
            
            # 并发执行所有 URL 处理任务
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            await browser.close() # 关闭浏览器
            logger.info("所有 URL 处理任务完成。")

    except Exception as e:
        logger.critical(f"Playwright 启动或运行过程中发生严重错误: {e}")
        return

    # 处理结果并写入文件
    for result in results:
        if isinstance(result, Exception):
            # 假设result是异常，我们可能需要知道是哪个URL导致了异常
            # 但gather返回的异常不会直接包含原始任务的参数
            # 如果需要更详细的错误对应，需要修改process_url的返回逻辑或者在gather时记录
            logger.error(f"处理 URL 时发生错误: {result}")
            continue
        
        url, nodes = result
        stats_data.append([url, len(nodes)])
        all_nodes_collected.extend(nodes)
    
    # 写入统计数据
    try:
        with open('data/stats.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Node Count'])
            writer.writerows(stats_data)
        logger.info("统计数据已写入 data/stats.csv")
    except IOError as e:
        logger.error(f"写入 data/stats.csv 失败: {e}")

    # 写入所有唯一节点
    unique_all_nodes = list(set(all_nodes_collected))
    try:
        with open('data/all.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_all_nodes))
        logger.info(f"所有唯一节点 (共 {len(unique_all_nodes)} 个) 已写入 data/all.txt")
    except IOError as e:
        logger.error(f"写入 data/all.txt 失败: {e}")

if __name__ == '__main__':
    start_time = time.time()
    asyncio.run(main())
    logger.info(f"处理完成，耗时 {time.time() - start_time:.2f} 秒")
