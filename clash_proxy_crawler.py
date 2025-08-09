# clash_proxy_crawler.py
import time
import yaml
import os
import csv
import hashlib
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import NoSuchElementException, TimeoutException

# --- 配置部分 ---
SEARCH_ENGINE_URL = "https://www.google.com"
SEARCH_INPUT_NAME = "q"
SEARCH_RESULT_SELECTOR = "h3 > a"  # Google搜索结果链接的CSS选择器

# 文件路径
CACHE_FILE = 'sc/search_cache.txt'
PROXIES_FILE = 'sc/clash_proxies.yaml'
STATS_FILE = 'sc/query_stats.csv'

# 优化后的搜索关键词，专注于 GitHub
search_queries = [
    'clash.yaml "proxies:" site:github.com',
    'clash.yml "proxies:" site:github.com',
    'clash.yaml "proxy-providers:" site:github.com',
    'clash.yml "proxy-providers:" site:github.com'
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
    driver.set_page_load_timeout(30) # 设置页面加载超时时间
    return driver

# --- 文件操作函数 ---
def load_cache():
    """加载已缓存的链接及其内容哈希值"""
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
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def append_to_yaml(content):
    """将新的代理节点内容追加到 YAML 文件，并使用 --- 分隔"""
    with open(PROXIES_FILE, 'a', encoding='utf-8') as f:
        f.write(content + '\n---\n')

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
            
            try:
                driver.get(SEARCH_ENGINE_URL)
                search_input = driver.find_element(By.NAME, SEARCH_INPUT_NAME)
                search_input.send_keys(query)
                search_input.send_keys(Keys.RETURN)
                time.sleep(5)  # 给予页面加载时间
            except NoSuchElementException:
                print(" - 找不到搜索框，可能页面结构已改变。跳过此查询。")
                continue
            except TimeoutException:
                print(" - 页面加载超时，跳过此查询。")
                continue

            links = driver.find_elements(By.CSS_SELECTOR, SEARCH_RESULT_SELECTOR)
            current_query_nodes_count = 0
            
            for link in links:
                url = link.get_attribute('href')
                
                # 严格过滤链接：只处理来自 GitHub 的链接
                if not url or 'github.com' not in url:
                    continue
                
                # 检查缓存
                if url in cached_links:
                    print(f" - 链接已缓存: {url}")
                    continue
                
                try:
                    # 访问链接并尝试获取内容
                    driver.get(url)
                    time.sleep(3)  # 给予页面加载时间
                    
                    page_content = None
                    # 特别处理 GitHub 的 'blob' 页面，尝试访问其原始文件链接
                    if 'github.com' in url and '/blob/' in url:
                        raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                        print(f" - 这是一个GitHub页面，尝试访问原始文件链接: {raw_url}")
                        driver.get(raw_url)
                        time.sleep(2)
                        page_content = driver.page_source
                    else:
                        # 否则，尝试从 <pre> 标签获取内容
                        try:
                            pre_element = driver.find_element(By.TAG_NAME, 'pre')
                            page_content = pre_element.text
                        except NoSuchElementException:
                            print(f" - 在 {url} 找不到 <pre> 标签，跳过此链接。")
                            continue
                    
                    if page_content:
                        try:
                            # 严格验证是否为有效的 YAML，并检查是否包含 Clash 节点
                            config = yaml.safe_load(page_content)
                            
                            if isinstance(config, dict) and ('proxies' in config or 'proxy-providers' in config):
                                print(f" - 在 {url} 找到有效的 Clash 配置文件！")
                                append_to_yaml(page_content)
                                
                                node_count = 0
                                if 'proxies' in config and isinstance(config['proxies'], list):
                                    node_count += len(config['proxies'])
                                if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
                                    node_count += len(config['proxy-providers'])
                                
                                current_query_nodes_count += node_count
                                new_cache_entries[url] = get_content_hash(page_content)
                            else:
                                print(f" - {url} 是有效的 YAML，但不是 Clash 配置文件，跳过。")
                        except yaml.YAMLError:
                            print(f" - {url} 的内容不是有效的 YAML 格式，跳过。")
                
                except Exception as e:
                    print(f" - 处理链接 {url} 时出错: {e}")
            
            append_stats(query, current_query_nodes_count)
            
    finally:
        cached_links.update(new_cache_entries)
        save_cache(cached_links)
        driver.quit()

if __name__ == '__main__':
    crawl()
