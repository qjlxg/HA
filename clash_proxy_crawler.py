import os
import requests
import yaml
import csv
import time
from datetime import datetime
from urllib.parse import quote
from bs4 import BeautifulSoup
import hashlib
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# 搜索关键词
QUERIES = [
    'filename:clash.yaml OR filename:clash.yml "proxies:" language:YAML site:*.github.com',
    'filename:clash.yaml OR filename:clash.yml "proxy-providers:" language:YAML site:*.github.com',
    'extension:yaml OR extension:yml "proxies:" "clash" path:/ site:*.github.com',
    'extension:yaml OR extension:yml "proxy-providers:" "clash" path:/ site:*.github.com'
]

# 缓存和输出文件路径
CACHE_FILE = "sc/search_cache.txt"
OUTPUT_FILE = "sc/clash_proxies.yaml"
STATS_FILE = "sc/query_stats.csv"

def setup_driver():
    """设置无头浏览器"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def load_cache():
    """加载缓存文件"""
    cache = {}
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if ',' in line:
                    url, hash_val = line.strip().split(',', 1)
                    cache[url] = hash_val
    return cache

def save_cache(cache):
    """保存缓存文件"""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        for url, hash_val in cache.items():
            f.write(f"{url},{hash_val}\n")

def get_content_hash(content):
    """计算内容哈希值"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def fetch_url_content(url):
    """获取URL内容"""
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def convert_to_raw_url(url):
    """将GitHub blob URL转换为raw URL"""
    if '/blob/' in url:
        return url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    return url

def validate_proxy(proxy):
    """验证Clash节点有效性"""
    if isinstance(proxy, dict):
        required_keys = ['server', 'port', 'type']
        return all(key in proxy for key in required_keys)
    return False

def parse_yaml_content(content):
    """解析YAML文件中的proxies或proxy-providers"""
    try:
        data = yaml.safe_load(content)
        proxies = data.get('proxies', []) or data.get('proxy-providers', {})
        if isinstance(proxies, list):
            # 过滤有效节点
            return [p for p in proxies if validate_proxy(p)]
        elif isinstance(proxies, dict):
            return proxies
        return None
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None

def save_proxies(proxies, query, cache, url):
    """保存代理节点并更新缓存和统计"""
    if not proxies:
        return 0

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        yaml.dump(proxies, f, allow_unicode=True, sort_keys=False)
        f.write("\n---\n")

    content = fetch_url_content(url)
    if content:
        cache[url] = get_content_hash(content)
        save_cache(cache)

    count = len(proxies) if isinstance(proxies, list) else len(proxies.keys())
    with open(STATS_FILE, 'a', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), query, count, url])
    return count

def search_with_browser(query, engine="google"):
    """使用Selenium模拟浏览器搜索"""
    driver = setup_driver()
    search_url = f"https://www.{engine}.com/search?q={quote(query)}"
    links = []
    
    try:
        driver.get(search_url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.g a"))
        )
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        for a in soup.select("div.g a"):
            href = a.get('href')
            if href and 'github.com' in href and not href.startswith('/url'):
                links.append(convert_to_raw_url(href))
    except Exception as e:
        print(f"Error searching {query} on {engine}: {e}")
        if engine == "google":
            print("Switching to Bing...")
            driver.quit()
            return search_with_browser(query, engine="bing")
    finally:
        driver.quit()
    
    return links

def main():
    """主函数"""
    cache = load_cache()
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    
    if not os.path.exists(STATS_FILE):
        with open(STATS_FILE, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Query', 'NodeCount', 'URL'])

    for query in QUERIES:
        print(f"Searching for: {query}")
        links = search_with_browser(query)
        total_nodes = 0

        for url in links:
            cached_hash = cache.get(url)
            content = fetch_url_content(url)
            if not content:
                continue

            current_hash = get_content_hash(content)
            if cached_hash == current_hash:
                print(f"Skipping unchanged URL: {url}")
                continue

            proxies = parse_yaml_content(content)
            if proxies:
                node_count = save_proxies(proxies, query, cache, url)
                total_nodes += node_count
                print(f"Extracted {node_count} nodes from {url}")
            
            time.sleep(2)

        print(f"Total nodes for query '{query}': {total_nodes}")

if __name__ == "__main__":
    main()
