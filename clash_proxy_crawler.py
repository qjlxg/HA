# clash_proxy_crawler_v11.py
import requests
import yaml
import os
import csv
import hashlib
import time
from datetime import datetime, timedelta

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

# 优化和扩展后的搜索关键词
search_queries = [
    # 1. 基本文件名变体（聚焦clash.yaml/yml）
    'filename:clash.yaml "proxies:" language:YAML',
    'filename:clash.yml "proxies:" language:YAML',
    'filename:clash-config.yaml "proxies:" language:YAML',
    'filename:clash-config.yml "proxies:" language:YAML',
    'filename:config.yaml "proxies:" "clash" language:YAML',
    'filename:config.yml "proxies:" "clash" language:YAML',

    # 2. Proxy-Providers变体（针对providers部分，可能包含节点URL）
    'filename:clash.yaml "proxy-providers:" language:YAML',
    'filename:clash.yml "proxy-providers:" language:YAML',
    'filename:clash.yaml "providers:" language:YAML',  # 简写变体
    'filename:config.yaml "proxy-providers:" language:YAML',

    # 3. 扩展锚点（包括proxy-groups和rules，常与proxies关联）
    'filename:clash.yaml "proxy-groups:" language:YAML',
    'filename:clash.yaml "rules:" "proxies:" language:YAML',
    'filename:clash.yaml "proxy-groups:" "proxies:" language:YAML',
    'filename:clash.yml "proxy-groups:" language:YAML',

    # 4. 路径和扩展限制（针对仓库结构）
    'extension:yaml "proxies:" "clash" path:/',
    'extension:yml "proxies:" "clash" path:/',
    'path:clash/config.yaml "proxies:" language:YAML',
    'path:configs/clash.yaml "proxies:" language:YAML',
    'path:sub/clash.yaml "proxies:" language:YAML',  # 常见订阅路径

    # 5. 站点和原始文件限制（聚焦GitHub raw内容）
    'filename:clash.yaml "proxies:" site:raw.githubusercontent.com',
    'filename:clash.yaml "proxies:" site:github.com language:YAML',
    'filename:clash.yml "proxies:" site:raw.githubusercontent.com',
    'clash.yaml "proxies:" filetype:yaml site:github.com',

    # 6. 高级组合（OR运算符，覆盖更多变体）
    'filename:clash.yaml OR filename:clash.yml "proxies:" language:YAML',
    'extension:yaml OR extension:yml "proxies:" "clash" path:/',
    'filename:clash.yaml OR config.yaml "proxies:" language:YAML',
    'filename:clash.yaml "proxies:" OR "proxy-providers:" language:YAML',
    'filename:clash.yaml "proxies:" OR "proxy-groups:" language:YAML',

    # 7. 其他常见变体（基于Clash社区模式）
    'clash "proxies:" filetype:yaml',
    'clash-sub "proxies:" language:YAML',  # 订阅相关
    'premium-clash.yaml "proxies:" language:YAML',  # Premium版本
    'clash-meta.yaml "proxies:" language:YAML',  # Meta内核变体
]

# 新增文件年龄配置项，单位：天
MAX_FILE_AGE_DAYS = 90

# 创建所需的目录
os.makedirs('sc', exist_ok=True)

# --- 文件操作函数 ---
def load_cache():
    cache = {}
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    if ',' in line:
                        url, hash_val = line.strip().split(',', 1)
                        cache[url] = hash_val
                except ValueError:
                    print(f" - 跳过无效缓存行: {line.strip()}")
    return cache

def save_cache(cache):
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        for url, hash_val in cache.items():
            f.write(f"{url},{hash_val}\n")

def get_content_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def write_proxies_to_yaml(all_proxies):
    final_config = {'proxies': all_proxies}
    with open(PROXIES_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)

def append_stats(query, count):
    file_exists = os.path.exists(STATS_FILE)
    with open(STATS_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['query', 'node_count', 'timestamp'])
        writer.writerow([query, count, datetime.now().isoformat()])

# --- 节点验证和解析 ---
def validate_proxy(proxy):
    if isinstance(proxy, dict):
        required_keys = ['server', 'port', 'type']
        valid_types = ['ss', 'vmess', 'trojan', 'snell', 'http']
        return all(key in proxy for key in required_keys) and proxy['type'] in valid_types
    return False

def parse_yaml_content(content):
    try:
        config = yaml.safe_load(content)
        
        all_nodes = []

        # 情况1: 文件本身就是一个代理节点列表 (list)
        if isinstance(config, list):
            valid_proxies = [p for p in config if validate_proxy(p)]
            all_nodes.extend(valid_proxies)
        
        # 情况2: 文件是一个包含顶级键的字典 (dict)
        elif isinstance(config, dict):
            # 优先从 'proxies' 键获取
            proxies_list = config.get('proxies', [])
            if isinstance(proxies_list, list):
                valid_proxies = [p for p in proxies_list if validate_proxy(p)]
                all_nodes.extend(valid_proxies)

            # 其次从 'proxy-providers' 键获取
            proxy_providers = config.get('proxy-providers', {})
            if isinstance(proxy_providers, dict):
                for provider_data in proxy_providers.values():
                    provider_proxies = []
                    if isinstance(provider_data, dict):
                        provider_proxies = provider_data.get('proxies', [])
                    elif isinstance(provider_data, list):
                        provider_proxies = provider_data
                    
                    if isinstance(provider_proxies, list):
                        valid_proxies = [p for p in provider_proxies if validate_proxy(p)]
                        all_nodes.extend(valid_proxies)
            
            # 最后从 'proxy-groups' 键获取
            proxy_groups = config.get('proxy-groups', [])
            if isinstance(proxy_groups, list):
                for group in proxy_groups:
                    if isinstance(group, dict):
                        group_proxies = group.get('proxies', [])
                        if isinstance(group_proxies, list):
                            for proxy_item in group_proxies:
                                if isinstance(proxy_item, dict):
                                    all_nodes.append(proxy_item)
        
        # 对所有收集到的节点进行最终验证
        final_valid_nodes = [node for node in all_nodes if validate_proxy(node)]
        return final_valid_nodes

    except yaml.YAMLError:
        print(f" - 内容不是有效的 YAML 格式，跳过。")
        return []

# --- 核心去重逻辑 ---
def get_node_key(proxy):
    if not isinstance(proxy, dict):
        return None
    
    key_components = [
        proxy.get('server'),
        str(proxy.get('port')),
        proxy.get('type')
    ]
    
    if proxy.get('type') == 'trojan':
        key_components.append(proxy.get('password'))
    elif proxy.get('type') in ['ss', 'vmess']:
        key_components.append(proxy.get('cipher'))
        key_components.append(proxy.get('password'))
    
    key_string = ":".join(str(c) for c in key_components if c is not None)
    
    return hashlib.sha256(key_string.encode('utf-8')).hexdigest()

# --- 主要爬取逻辑 ---
def crawl():
    cached_links = load_cache()
    new_cache_entries = {}
    all_found_proxies = []
    seen_nodes = set()

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
                    
                    # --- 新增文件年龄检查 ---
                    repo_pushed_at_str = item['repository']['pushed_at']
                    repo_pushed_at = datetime.strptime(repo_pushed_at_str, "%Y-%m-%dT%H:%M:%SZ")
                    if datetime.utcnow() - repo_pushed_at > timedelta(days=MAX_FILE_AGE_DAYS):
                        print(f" - 跳过旧文件 ({repo_pushed_at_str}): {html_url}")
                        continue
                    # --- 结束文件年龄检查 ---
                    
                    repo_full_name = item['repository']['full_name']
                    file_path = item['path']
                    repo_branch = item['repository'].get('default_branch', 'main')
                    raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{repo_branch}/{file_path}"
                    
                    if html_url in cached_links:
                        print(f" - 链接已缓存: {html_url}")
                        continue
                    
                    try:
                        raw_response = requests.get(raw_url)
                        raw_response.raise_for_status()
                        page_content = raw_response.text

                        if page_content:
                            proxies = parse_yaml_content(page_content)
                            if proxies:
                                print(f" - 在 {html_url} 找到有效的 Clash 配置文件！")
                                for proxy in proxies:
                                    node_key = get_node_key(proxy)
                                    if node_key and node_key not in seen_nodes:
                                        all_found_proxies.append(proxy)
                                        seen_nodes.add(node_key)
                                
                                node_count = len(proxies)
                                current_query_nodes_count += node_count
                                new_cache_entries[html_url] = get_content_hash(page_content)
                            else:
                                print(f" - {html_url} 是有效的 YAML，但不是有效 Clash 配置文件，跳过。")
                    
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
                    wait_time = int(e.response.headers.get('X-RateLimit-Reset', 0)) - time.time() + 10
                    print(f" - 速率限制，等待 {wait_time} 秒...")
                    time.sleep(max(wait_time, 0))
                    continue
                has_more_results = False
            except requests.exceptions.RequestException as e:
                print(f" - API请求发生其他错误: {e}")
                has_more_results = False

        append_stats(query, current_query_nodes_count)
        time.sleep(5)

    cached_links.update(new_cache_entries)
    save_cache(cached_links)

    if all_found_proxies:
        write_proxies_to_yaml(all_found_proxies)
        print(f"\n✅ 所有找到的代理节点（已去重）已成功合并并写入 {PROXIES_FILE}")
        print(f"   最终节点总数：{len(all_found_proxies)}")
    else:
        print("\n⚠️ 未找到任何有效的代理节点。")

if __name__ == '__main__':
    crawl()
