import os
import asyncio
import aiohttp
import yaml
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re
from datetime import datetime
import urllib.parse
from collections import deque

# 配置
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
SEARCH_ENGINE_ID = os.getenv("SEARCH_ENGINE_ID")
OUTPUT_DIR = "sc"
SEARCH_QUERIES = [
    'filetype:yaml | filetype:yml "proxies:" "clash" site:raw.githubusercontent.com | site:gist.github.com | site:gitlab.com',
    'filetype:yaml | filetype:yml "proxy-providers:" "clash" site:raw.githubusercontent.com | site:gist.github.com',
    '"proxies:" "clash" "ss" | "vmess" | "trojan" | "vless" | "hysteria2"',
    '"proxy-providers:" "clash" | "subscribe" | "freeclash" | "free proxy" site:*.herokuapp.com | site:*.pages.dev | site:*.workers.dev',
    '"clash" "proxypool" | "free proxy" | "node" site:raw.githubusercontent.com from:lagzian from:ReaJason from:vxiaov'
]
MAX_RESULTS_PER_QUERY = 50
PAGE_SIZE = 10
REQUEST_TIMEOUT = 8
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
    'failed_domains': {}
}

def create_output_dir():
    """创建输出目录"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def search_with_google(query):
    """使用 Google Custom Search API 搜索"""
    links = []
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
                print(f"Google API 搜索失败 (query={query}, start={start_index}): {e}")
                break
        return links
    except HttpError as e:
        print(f"Google API 初始化失败: {e}")
        return []

def search_links():
    """执行所有搜索查询，合并结果并按优先级排序"""
    all_links = set()
    query_results = []
    for query in SEARCH_QUERIES:
        print(f"执行搜索: {query}")
        links = search_with_google(query)
        all_links.update(links)
        query_results.append((query, len(links)))
    for query, count in sorted(query_results, key=lambda x: x[1]):
        print(f"查询 {query} 获取 {count} 个链接")
    prioritized_links = sorted(
        list(all_links),
        key=lambda x: sum(p in x for p in LINK_PRIORITY),
        reverse=True
    )
    print(f"共获取 {len(all_links)} 个唯一链接")
    return prioritized_links[:500]

async def fetch_content(session, url):
    """异步获取网页内容，支持预检查和多平台 raw 链接转换"""
    domain = urllib.parse.urlparse(url).netloc
    if domain in DOMAIN_BLACKLIST or domain in FAILED_DOMAINS:
        STATS['failed_requests'] += 1
        STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
        return None, url
    for attempt in range(MAX_RETRIES):
        try:
            async with session.head(url, timeout=REQUEST_TIMEOUT/2) as head_response:
                if head_response.status != 200:
                    STATS['failed_requests'] += 1
                    STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                    FAILED_DOMAINS.add(domain)
                    return None, url
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            elif "gitlab.com" in url and "/blob/" in url:
                url = url.replace("/blob/", "/-/raw/")
            elif "bitbucket.org" in url and "/src/" in url:
                url = url.replace("/src/", "/raw/")
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status == 200:
                    return await response.text(), url
                print(f"获取 {url} 失败，状态码: {response.status}")
                STATS['failed_requests'] += 1
                STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                FAILED_DOMAINS.add(domain)
                await asyncio.sleep(2 ** attempt)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"获取 {url} 失败: {e}")
            STATS['failed_requests'] += 1
            STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
            FAILED_DOMAINS.add(domain)
            await asyncio.sleep(2 ** attempt)
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
    return urls[:MAX_SUB_LINKS]

def is_valid_clash_yaml(content):
    """验证是否为有效的 Clash YAML 配置，统计协议类型"""
    try:
        if "proxies:" not in content:
            return False, None, []
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return False, None, []
        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            return False, None, []
        valid_proxies = []
        for proxy in proxies:
            if isinstance(proxy, dict) and "name" in proxy and "server" in proxy:
                valid_proxies.append(proxy)
                protocol = proxy.get("type", "unknown")
                STATS['protocol_counts'][protocol] = STATS['protocol_counts'].get(protocol, 0) + 1
        provider_urls = []
        if "proxy-providers" in data:
            for provider in data.get("proxy-providers", {}).values():
                if isinstance(provider, dict) and "url" in provider:
                    provider_urls.append(provider["url"])
        return bool(valid_proxies), valid_proxies, provider_urls
    except yaml.YAMLError:
        return False, None, []

async def process_link(session, link, depth=0):
    """异步处理单个链接，提取代理节点和订阅链接"""
    if depth > RECURSION_DEPTH:
        return [], []
    STATS['links_processed'] += 1
    content, url = await fetch_content(session, link)
    if not content:
        return [], []
    is_valid, proxies, provider_urls = is_valid_clash_yaml(content)
    if is_valid:
        domain = urllib.parse.urlparse(url).netloc
        STATS['nodes_found'] += len(proxies)
        STATS['links_by_source'][domain] = STATS['links_by_source'].get(domain, 0) + len(proxies)
        STATS['nodes_by_depth'][depth] = STATS['nodes_by_depth'].get(depth, 0) + len(proxies)
        print(f"从 {url} 提取到 {len(proxies)} 个有效节点 (深度: {depth})")
    additional_urls = extract_urls_from_content(content)
    sub_proxies = []
    if additional_urls and depth < RECURSION_DEPTH:
        prioritized_urls = sorted(
            list(set(additional_urls)),
            key=lambda x: sum(p in x for p in LINK_PRIORITY),
            reverse=True
        )[:MAX_SUB_LINKS]
        tasks = [process_link(session, url, depth + 1) for url in prioritized_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, tuple):
                sub_prox, sub_urls = result
                sub_proxies.extend(sub_prox)
    return proxies + sub_proxies, provider_urls + additional_urls

async def main_async():
    create_output_dir()
    links = search_links()
    all_proxies = []
    processed_links = set()
    link_queue = deque(links)

    async with aiohttp.ClientSession() as session:
        while link_queue and len(processed_links) < MAX_TOTAL_LINKS:
            batch_size = min(len(link_queue), MAX_WORKERS)
            tasks = []
            for _ in range(batch_size):
                if not link_queue:
                    break
                link = link_queue.popleft()
                if link in processed_links:
                    continue
                processed_links.add(link)
                tasks.append(process_link(session, link))
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
                            link_queue.append(new_link)

    # 去重
    unique_proxies = []
    seen = set()
    for proxy in all_proxies:
        if not isinstance(proxy, dict):
            continue
        if "port" not in proxy or "password" not in proxy:
            continue
        key = (proxy.get("name"), proxy.get("server"), proxy.get("type"))
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)

    # 保存结果
    if unique_proxies:
        output_file = f"clash_proxies_{len(unique_proxies)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
        output_data = {"proxies": unique_proxies}
        output_path = os.path.join(OUTPUT_DIR, output_file)
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(output_data, f, allow_unicode=True)
        print(f"已保存 {len(unique_proxies)} 个节点到 {output_path}")
    else:
        print("未找到任何有效的 Clash 代理配置")

    # 打印统计信息
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

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
