import os
import asyncio
import aiohttp
import yaml
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re
import csv
from datetime import datetime
import urllib.parse
from collections import deque
import sys
import pytz

# 核心配置
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY_1")
SEARCH_ENGINE_ID = os.getenv("SEARCH_ENGINE_ID")

OUTPUT_DIR = "sc"
OUTPUT_FILE = "clash_proxies.yaml"
CACHE_FILE = os.path.join(OUTPUT_DIR, "search_cache.txt")
STATS_FILE = os.path.join(OUTPUT_DIR, "query_stats.csv")
SEARCH_QUERIES = [
    'filetype:yaml | filetype:yml "proxies:" "clash" site:raw.githubusercontent.com | site:gist.github.com | site:gitlab.com',
    'filetype:yaml | filetype:yml "proxy-providers:" "clash" site:raw.githubusercontent.com | site:gist.github.com',
    '"proxies:" "clash" "ss" | "vmess" | "trojan" | "vless" | "hysteria2" | "http"',
    '"proxy-providers:" "clash" | "subscribe" | "freeclash" | "free proxy" site:*.herokuapp.com | site:*.pages.dev | site:*.workers.dev',
    '"clash" "proxypool" | "free proxy" | "node" site:raw.githubusercontent.com from:lagzian from:ReaJason from:vxiaov'
]
MAX_RESULTS_PER_QUERY = 10  # 调整为更保守的配额
PAGE_SIZE = 10
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
MAX_WORKERS = 30
MAX_SUB_LINKS = 100
MAX_TOTAL_LINKS = 5000
LINK_BLACKLIST = ['.md', '.png', '.jpg', '.pdf', '/issues/', '/wiki/', '/login', '/signup', '/readme', '/Ruleset/', '/rule/']
LINK_PRIORITY = ['.yaml', '.yml', '/clash', '/proxies', '/proxy', '/subscribe', '/nodes', '/api']
DOMAIN_BLACKLIST = {'raw.sevencdn.com', '192.168.1.19', 'nachoneko.azurefd.net'}
FAILED_DOMAINS = set()
RECURSION_DEPTH = 3
STATS = {
    'links_processed': 0,
    'nodes_found': 0,
    'links_by_source': {},
    'protocol_counts': {},
    'failed_requests': 0,
    'nodes_by_depth': {},
    'failed_domains': {},
    'query_results': {}
}

def create_output_dir():
    """创建输出目录"""
    print(f"创建输出目录: {OUTPUT_DIR}")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    os.makedirs('output', exist_ok=True)

def load_cache():
    """从缓存文件加载已处理的链接"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f)
    return set()

def save_cache(links):
    """将新链接追加到缓存文件"""
    with open(CACHE_FILE, 'a', encoding='utf-8') as f:
        for link in links:
            f.write(link + '\n')
            
def save_query_stats():
    """保存关键词统计结果到 CSV 文件"""
    with open(STATS_FILE, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Query', 'Results'])
        for query, count in STATS['query_results'].items():
            writer.writerow([query, count])

def search_with_google(query):
    """使用 Google Custom Search API 搜索"""
    links = []
    if not GOOGLE_API_KEY:
        print("错误: 未配置 Google API 密钥", file=sys.stderr)
        return []
    
    try:
        service = build("customsearch", "v1", developerKey=GOOGLE_API_KEY)
        for start_index in range(1, MAX_RESULTS_PER_QUERY + 1, PAGE_SIZE):
            try:
                result = service.cse().list(
                    q=query,
                    cx=SEARCH_ENGINE_ID,
                    num=PAGE_SIZE,
                    start=start_index
                ).execute()
                items = result.get("items", [])
                filtered_links = [item["link"] for item in items if not any(b in item["link"] for b in LINK_BLACKLIST)]
                links.extend(filtered_links)
                if len(items) < PAGE_SIZE:
                    break
            except HttpError as e:
                print(f"Google API 搜索失败 (query={query}, start={start_index}): {e}", file=sys.stderr)
                break
        return links
    except HttpError as e:
        print(f"Google API 初始化失败: {e}", file=sys.stderr)
        return []

def search_links():
    """执行所有搜索查询，合并结果并按优先级排序"""
    print("开始搜索链接")
    all_links = set()
    for query in SEARCH_QUERIES:
        print(f"执行搜索: {query}")
        links = search_with_google(query)
        all_links.update(links)
        STATS['query_results'][query] = len(links)
    
    prioritized_links = sorted(
        list(all_links),
        key=lambda x: sum(p in x for p in LINK_PRIORITY),
        reverse=True
    )
    print(f"共获取 {len(all_links)} 个唯一链接")
    return prioritized_links[:500]

async def fetch_content(session, url):
    """异步获取网页内容，支持预检查和多平台 raw 链接转换"""
    print(f"获取内容: {url}")
    domain = urllib.parse.urlparse(url).netloc
    if domain in DOMAIN_BLACKLIST or domain in FAILED_DOMAINS:
        STATS['failed_requests'] += 1
        STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
        print(f"警告: 跳过黑名单域名: {domain}", file=sys.stderr)
        return None, url
    for attempt in range(MAX_RETRIES):
        try:
            async with session.head(url, timeout=REQUEST_TIMEOUT/2) as head_response:
                if head_response.status != 200:
                    STATS['failed_requests'] += 1
                    STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                    FAILED_DOMAINS.add(domain)
                    print(f"警告: HEAD 请求失败: {url}, 状态码: {head_response.status}", file=sys.stderr)
                    return None, url
                content_type = head_response.headers.get('content-type', '').lower()
                if not ('yaml' in content_type or 'octet-stream' in content_type or 'text/plain' in content_type):
                    print(f"警告: 跳过 {url}，无效内容类型: {content_type}", file=sys.stderr)
                    return None, url
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            elif "gitlab.com" in url and "/blob/" in url:
                url = url.replace("/blob/", "/-/raw/")
            elif "bitbucket.org" in url and "/src/" in url:
                url = url.replace("/src/", "/raw/")
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status == 200:
                    print(f"成功获取内容: {url}")
                    return await response.text(), url
                print(f"警告: 获取 {url} 失败，状态码: {response.status}", file=sys.stderr)
                STATS['failed_requests'] += 1
                STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                FAILED_DOMAINS.add(domain)
                await asyncio.sleep(2 ** attempt)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"警告: 获取 {url} 失败 (尝试 {attempt + 1}/{MAX_RETRIES}): {e}", file=sys.stderr)
            STATS['failed_requests'] += 1
            STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
            FAILED_DOMAINS.add(domain)
            await asyncio.sleep(2 ** attempt)
    print(f"错误: 获取 {url} 失败，已达最大重试次数", file=sys.stderr)
    return None, url

def extract_urls_from_content(content):
    """从内容中提取潜在的订阅链接"""
    urls = []
    if not content:
        return urls
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, content)
    for url in matches:
        if any(ext in url.lower() for ext in LINK_PRIORITY) and not any(b in url for b in LINK_BLACKLIST):
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme and parsed.netloc:
                    urls.append(url)
            except ValueError:
                continue
    print(f"提取到 {len(urls)} 个订阅链接")
    return urls[:MAX_SUB_LINKS]

def is_valid_clash_yaml(content):
    """验证是否为有效的 Clash YAML 配置，统计协议类型"""
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            print("警告: YAML 解析失败: 非字典格式", file=sys.stderr)
            return False, None, []
        
        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            print("警告: proxies 字段非列表", file=sys.stderr)
            proxies = []
            
        valid_proxies = []
        supported_protocols = ["ss", "trojan", "vmess", "vless", "http", "https", "snell", "hysteria2"]
        for proxy in proxies:
            if isinstance(proxy, dict) and "name" in proxy and "server" in proxy:
                protocol = proxy.get("type", "unknown")
                if protocol in supported_protocols:
                    valid_proxies.append(proxy)
                    STATS['protocol_counts'][protocol] = STATS['protocol_counts'].get(protocol, 0) + 1
        
        provider_urls = []
        if "proxy-providers" in data:
            for provider in data.get("proxy-providers", {}).values():
                if isinstance(provider, dict) and "url" in provider:
                    provider_urls.append(provider["url"])
                    
        print(f"找到 {len(valid_proxies)} 个有效代理，{len(provider_urls)} 个订阅链接")
        return bool(valid_proxies) or bool(provider_urls), valid_proxies, provider_urls
        
    except yaml.YAMLError as e:
        print(f"错误: YAML 解析错误: {e}", file=sys.stderr)
        return False, None, []

async def process_link(session, link, depth=0):
    """异步处理单个链接，提取代理节点和订阅链接"""
    print(f"处理链接: {link} (深度: {depth})")
    if depth > RECURSION_DEPTH:
        print(f"警告: 超过最大递归深度 ({RECURSION_DEPTH})，跳过: {link}", file=sys.stderr)
        return [], []
    STATS['links_processed'] += 1
    try:
        async with asyncio.timeout(60):
            content, url = await fetch_content(session, link)
            if not content:
                return [], []
            
            is_valid, proxies, provider_urls = is_valid_clash_yaml(content)
            valid_proxies = []
            
            if is_valid:
                domain = urllib.parse.urlparse(url).netloc
                valid_proxies.extend(proxies)
                STATS['nodes_found'] += len(proxies)
                STATS['links_by_source'][domain] = STATS['links_by_source'].get(domain, 0) + len(proxies)
                STATS['nodes_by_depth'][depth] = STATS['nodes_by_depth'].get(depth, 0) + len(proxies)
                print(f"从 {url} 提取到 {len(proxies)} 个节点 (深度: {depth})")
            
            additional_urls = extract_urls_from_content(content)
            all_new_urls = list(set(additional_urls + provider_urls))
            
            sub_proxies = []
            if all_new_urls and depth < RECURSION_DEPTH:
                prioritized_urls = sorted(
                    all_new_urls,
                    key=lambda x: sum(p in x for p in LINK_PRIORITY),
                    reverse=True
                )[:MAX_SUB_LINKS]
                tasks = [process_link(session, sub_url, depth + 1) for sub_url in prioritized_urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, tuple):
                        sub_prox, sub_urls = result
                        sub_proxies.extend(sub_prox)
            return valid_proxies + sub_proxies, all_new_urls
    except asyncio.TimeoutError:
        print(f"错误: 处理链接 {link} 超时", file=sys.stderr)
        return [], []

async def main_async():
    try:
        create_output_dir()
        all_proxies = []
        processed_links = load_cache()
        newly_found_links = set()
        failed_links = []
        
        print(f"已从缓存加载 {len(processed_links)} 个链接")
        
        async with aiohttp.ClientSession() as session:
            print("开始搜索链接")
            links_from_search = search_links()
            save_query_stats()
            print(f"搜索完成，获取 {len(links_from_search)} 个初始链接")
            
            links_to_process = deque(link for link in links_from_search if link not in processed_links)
            
            print(f"需要处理 {len(links_to_process)} 个新链接")

            while links_to_process and len(processed_links) < MAX_TOTAL_LINKS:
                batch_size = min(len(links_to_process), MAX_WORKERS)
                tasks = []
                for _ in range(batch_size):
                    if not links_to_process:
                        break
                    link = links_to_process.popleft()
                    processed_links.add(link)
                    newly_found_links.add(link)
                    tasks.append(process_link(session, link))
                print(f"处理批量链接，批次大小: {len(tasks)}")
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, tuple):
                        proxies, new_links = result
                        all_proxies.extend(proxies)
                        prioritized_new_links = sorted(
                            list(set(new_links)),
                            key=lambda x: sum(p in x for p in LINK_PRIORITY),
                            reverse=True
                        )[:MAX_SUB_LINKS]
                        for new_link in prioritized_new_links:
                            if new_link not in processed_links and len(processed_links) < MAX_TOTAL_LINKS:
                                links_to_process.append(new_link)
                    else:
                        failed_links.append(("URL未记录", str(result)))
                print(f"批次处理完成，当前处理链接总数: {len(processed_links)}")
        
        save_cache(newly_found_links)
        
        print("开始去重代理")
        unique_proxies = []
        seen = set()
        for proxy in all_proxies:
            if not isinstance(proxy, dict):
                continue
            key = (proxy.get("name"), proxy.get("server"), proxy.get("port"), proxy.get("type"))
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        print(f"去重后保留 {len(unique_proxies)} 个代理")

        output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
        if unique_proxies:
            output_data = {"proxies": unique_proxies}
            with open(output_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(output_data, f, allow_unicode=True)
            print(f"已保存 {len(unique_proxies)} 个节点到 {output_path}")
        else:
            print("警告: 未找到任何有效的 Clash 代理配置", file=sys.stderr)

        failed_path = "output/clash_failed.txt"
        with open(failed_path, "w", encoding="utf-8") as f:
            f.write("失败链接,#genre#\n")
            for link, error in failed_links:
                f.write(f"{link},{error}\n")
        print(f"已保存 {len(failed_links)} 个失败链接到 {failed_path}")

        print("\n统计信息：")
        print(f"处理链接总数: {STATS['links_processed']}")
        print(f"失败请求数: {STATS['failed_requests']}")
        print(f"发现节点总数: {STATS['nodes_found']}")
        print("节点来源分布：")
        for domain, count in sorted(STATS['links_by_source'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {domain}: {count} 个节点")
        print("协议分布：")
        for protocol, count in sorted(STATS['protocol_counts'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {protocol}: {count} 个节点")
        print("深度分布：")
        for depth, count in sorted(STATS['nodes_by_depth'].items()):
            print(f"  深度 {depth}: {count} 个节点")
        print("失败域名分布：")
        for domain, count in sorted(STATS['failed_domains'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {domain}: {count} 次失败")
    except Exception as e:
        print(f"主程序发生错误: {e}", file=sys.stderr)
        raise

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
