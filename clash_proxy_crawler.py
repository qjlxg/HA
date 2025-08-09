# clash_proxy_crawler.py
import requests
import yaml
import os
import csv
import hashlib
import time

# --- 配置部分 ---
GITHUB_API_TOKEN = os.getenv("BOT")
if not GITHUB_API_TOKEN:
    raise ValueError("请在环境变量中设置 BOT")

GITHUB_API_URL = "https://api.github.com/search/code"
HEADERS = {
    "Authorization": f"token {GITHUB_API_TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json"
}

# 文件路径
CACHE_FILE = 'sc/search_cache.txt'
PROXIES_FILE = 'sc/clash_proxies.yaml'
STATS_FILE = 'sc/query_stats.csv'

# 搜索关键词
search_queries = [
    'filename:clash.yaml "proxies:" language:YAML',
    'filename:clash.yml "proxies:" language:YAML',
    'filename:clash.yaml "proxy-providers:" language:YAML',
    'filename:clash.yml "proxy-providers:" language:YAML'
]

# 创建所需的目录
os.makedirs('sc', exist_ok=True)

# --- 文件操作函数 ---
def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, 'r') as f:
        return {line.strip().split(',')[0]: line.strip().split(',')[1] for line in f if ',' in line}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        for url, content_hash in cache.items():
            f.write(f"{url},{content_hash}\n")

def get_content_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def append_to_yaml(content):
    with open(PROXIES_FILE, 'a', encoding='utf-8') as f:
        f.write(content + '\n---\n')

def append_stats(query, count):
    file_exists = os.path.exists(STATS_FILE)
    with open(STATS_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['query', 'node_count', 'timestamp'])
        writer.writerow([query, count, time.strftime('%Y-%m-%d %H:%M:%S')])

# --- 主要爬取逻辑 ---
def crawl():
    cached_links = load_cache()
    new_cache_entries = {}

    for query in search_queries:
        print(f"正在搜索: {query}")
        current_query_nodes_count = 0
        page = 1
        has_more_results = True

        while has_more_results:
            params = {
                "q": query,
                "per_page": 100,
                "page": page
            }
            
            try:
                response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
                response.raise_for_status()
                
                results = response.json()
                items = results.get("items", [])
                
                if not items:
                    has_more_results = False
                    break

                for item in items:
                    html_url = item.get("html_url")
                    repo_full_name = item['repository']['full_name']
                    file_path = item['path']
                    # 构建正确的原始文件下载链接
                    raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/main/{file_path}"
                    
                    if html_url in cached_links:
                        print(f" - 链接已缓存: {html_url}")
                        continue
                    
                    try:
                        raw_response = requests.get(raw_url)
                        raw_response.raise_for_status()
                        page_content = raw_response.text

                        if page_content:
                            try:
                                config = yaml.safe_load(page_content)
                                if isinstance(config, dict) and ('proxies' in config or 'proxy-providers' in config):
                                    print(f" - 在 {html_url} 找到有效的 Clash 配置文件！")
                                    append_to_yaml(page_content)
                                    
                                    node_count = 0
                                    if 'proxies' in config and isinstance(config['proxies'], list):
                                        node_count += len(config['proxies'])
                                    if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
                                        node_count += len(config['proxy-providers'])
                                    
                                    current_query_nodes_count += node_count
                                    new_cache_entries[html_url] = get_content_hash(page_content)
                                else:
                                    print(f" - {html_url} 是有效的 YAML，但不是 Clash 配置文件，跳过。")
                            except yaml.YAMLError:
                                print(f" - {html_url} 的内容不是有效的 YAML 格式，跳过。")
                    
                    except requests.exceptions.RequestException as e:
                        print(f" - 下载原始文件 {raw_url} 时出错: {e}")
                
                next_link = response.links.get('next', None)
                if next_link:
                    page += 1
                    time.sleep(2)
                else:
                    has_more_results = False

            except requests.exceptions.HTTPError as e:
                print(f" - API请求失败: {e.response.status_code} {e.response.reason}")
                if e.response.status_code == 403 and "rate limit exceeded" in e.response.text:
                    print(" - 达到API速率限制。请等待或检查你的令牌。")
                has_more_results = False
            except requests.exceptions.RequestException as e:
                print(f" - API请求发生其他错误: {e}")
                has_more_results = False

        append_stats(query, current_query_nodes_count)
        time.sleep(5)

    cached_links.update(new_cache_entries)
    save_cache(cached_links)

if __name__ == '__main__':
    crawl()
