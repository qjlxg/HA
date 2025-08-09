# clash_proxy_crawler.py
import time
import yaml
import os
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse, parse_qs

# --- 配置部分 ---
SEARCH_ENGINE_URL = "https://www.google.com"  # 或 "https://www.bing.com"
SEARCH_INPUT_NAME = "q"  # Google 和 Bing 的搜索框 input name 都是 'q'
SEARCH_RESULT_SELECTOR = "a[href]" # 搜索结果链接的CSS选择器

# 文件路径
CACHE_FILE = 'sc/search_cache.txt'
PROXIES_FILE = 'sc/clash_proxies.yaml'
STATS_FILE = 'sc/query_stats.csv'

search_queries = [
    'clash.yaml "proxies:" filetype:yaml',
    'clash.yml "proxies:" filetype:yml',
    'clash.yaml "proxy-providers:" filetype:yaml',
    'clash.yml "proxy-providers:" filetype:yml'
]

# 创建所需的目录
os.makedirs('sc', exist_ok=True)

# --- 初始化浏览器 ---
def initialize_driver():
    """初始化并返回一个无头模式的Chrome浏览器实例"""
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    
    # 防止被反爬机制检测
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

# --- 文件操作函数 ---
def load_cache():
    """加载已缓存的链接"""
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, 'r') as f:
        return {line.strip().split(',')[0]: line.strip().split(',')[1] for line in f if ',' in line}

def save_cache(cache):
    """保存缓存的链接及其哈希值"""
    with open(CACHE_FILE, 'w') as f:
        for url, content_hash in cache.items():
            f.write(f"{url},{content_hash}\n")

def get_content_hash(content):
    """计算内容的哈希值以判断是否更新"""
    import hashlib
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def append_to_yaml(content):
    """将新的代理节点内容追加到 YAML 文件"""
    with open(PROXIES_FILE, 'a', encoding='utf-8') as f:
        f.write(content + '\n')

def append_stats(query, count):
    """追加统计数据到 CSV 文件"""
    file_exists = os.path.exists(STATS_FILE)
    with open(STATS_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['query', 'node_count', 'timestamp'])
        writer.writerow([query, count, time.strftime('%Y-%m-%d %H:%M:%S')])

# --- 主要爬取逻辑 ---
def crawl():
    driver = initialize_driver()
    cached_links = load_cache()
    new_cache_entries = {}
    
    try:
        for query in search_queries:
            print(f"正在搜索: {query}")
            driver.get(SEARCH_ENGINE_URL)
            
            # 定位搜索框并输入关键词
            search_input = driver.find_element(By.NAME, SEARCH_INPUT_NAME)
            search_input.send_keys(query)
            search_input.send_keys(Keys.RETURN)
            
            time.sleep(5) # 给予页面加载时间
            
            # 提取搜索结果中的链接
            links = driver.find_elements(By.CSS_SELECTOR, SEARCH_RESULT_SELECTOR)
            
            current_query_nodes_count = 0
            
            for link in links:
                url = link.get_attribute('href')
                
                # 过滤掉无效链接和搜索引擎内部链接
                if not url or url.startswith(SEARCH_ENGINE_URL) or not url.startswith('http'):
                    continue
                
                # 特殊处理Google的重定向链接
                if url.startswith('https://www.google.com/url?'):
                    parsed_url = parse_qs(urlparse(url).query)
                    url = parsed_url.get('q', [None])[0]
                    if not url:
                        continue
                
                # 检查缓存，如果已缓存且内容未更新，则跳过
                if url in cached_links:
                    print(f" - 链接已缓存: {url}")
                    continue
                
                try:
                    # 访问链接并提取内容
                    driver.get(url)
                    time.sleep(3) # 给予页面加载时间
                    
                    # 获取页面的原始文本内容
                    page_content = driver.find_element(By.TAG_NAME, 'pre').text # 假设文件内容在 <pre> 标签中
                    
                    # 验证是否为 YAML 内容并提取节点
                    config = yaml.safe_load(page_content)
                    
                    # 检查 'proxies' 或 'proxy-providers'
                    if 'proxies' in config:
                        # TODO: 这里需要根据 YAML 格式提取代理节点
                        print(f" - 找到代理节点在 {url}")
                        append_to_yaml(page_content)
                        current_query_nodes_count += len(config['proxies']) # 假设 proxies 是列表
                        new_cache_entries[url] = get_content_hash(page_content)
                    elif 'proxy-providers' in config:
                        # TODO: 这里需要根据 YAML 格式提取代理提供者
                        print(f" - 找到代理提供者在 {url}")
                        # 暂时只记录，如果您有需要，可以自行解析 proxy-providers
                        current_query_nodes_count += len(config['proxy-providers'])
                        new_cache_entries[url] = get_content_hash(page_content)
                        
                except Exception as e:
                    print(f" - 处理链接 {url} 时出错: {e}")
                    continue
            
            # 记录本次搜索的统计数据
            append_stats(query, current_query_nodes_count)
            
    finally:
        # 保存新的缓存条目，并关闭浏览器
        cached_links.update(new_cache_entries)
        save_cache(cached_links)
        driver.quit()

if __name__ == '__main__':
    crawl()
