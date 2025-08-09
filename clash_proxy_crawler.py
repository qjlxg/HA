import os
import asyncio
import aiohttp
import yaml
import re
import json
import logging
from datetime import datetime
import urllib.parse
from collections import deque
import pytz

# 配置日志
try:
    os.makedirs('logs', exist_ok=True)
    log_handler = logging.FileHandler('logs/clash_crawler.log', encoding='utf-8')
except Exception as e:
    logging.warning(f"无法创建日志文件: {e}，回退到控制台输出")
    log_handler = logging.StreamHandler()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z',
    handlers=[logging.StreamHandler(), log_handler]
)
# 设置上海时间
logging.Formatter.converter = lambda *args: datetime.now(pytz.timezone('Asia/Shanghai')).timetuple()

# 配置
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OUTPUT_DIR = "sc"
MAX_RESULTS_PER_QUERY = 50
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
MAX_WORKERS = 5
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
    logging.info(f"创建输出目录: {OUTPUT_DIR}")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    os.makedirs('output', exist_ok=True)

def load_cached_links(cache_file="output/cached_links.json"):
    """加载缓存的链接"""
    logging.info(f"加载缓存链接: {cache_file}")
    try:
        # 检查文件是否存在且不为空
        if os.path.exists(cache_file) and os.path.getsize(cache_file) > 0:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            # 文件不存在或为空，返回空列表
            logging.warning(f"缓存文件 {cache_file} 不存在或为空")
            return []
    except Exception as e:
        # 捕获所有潜在的解析错误，包括 JSONDecodeError
        logging.error(f"加载缓存文件 {cache_file} 失败: {e}")
        return []

def save_cached_links(links, cache_file="output/cached_links.json"):
    """保存链接到缓存"""
    logging.info(f"保存缓存链接到: {cache_file}")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(links, f, ensure_ascii=False)

async def search_with_github_api(session, queries=["proxies: clash", "proxy-providers: clash", "subscription: clash"]):
    """使用 GitHub API 搜索代码"""
    links = []
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    for query in queries:
        logging.info(f"执行 GitHub API 搜索: {query}")
        page = 1
        per_page = 100
        while True:
            api_url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}+extension:yaml+extension:yml&per_page={per_page}&page={page}"
            logging.info(f"GitHub API 请求: {api_url}")
            try:
                async with session.get(api_url, headers=headers, timeout=REQUEST_TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        items = data.get("items", [])
                        if not items:
                            break
                        for item in items:
                            repo = item["repository"]["full_name"]
                            path = item["path"]
                            if "gist.github.com" in item["html_url"]:
                                gist_id = item["html_url"].split("/")[-1]
                                raw_url = f"https://gist.githubusercontent.com/{repo}/{gist_id}/raw/{path}"
                            else:
                                raw_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
                            if not any(b in raw_url for b in LINK_BLACKLIST):
                                links.append(raw_url)
                        logging.info(f"GitHub API 获取 {len(items)} 个链接 (page={page})")
                        page += 1
                    elif response.status == 403:
                        logging.warning("GitHub API 配额超限，等待 60 秒")
                        await asyncio.sleep(60)
                    else:
                        logging.error(f"GitHub API 搜索失败，状态码: {response.status}")
                        break
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.error(f"GitHub API 搜索失败: {e}")
                break
    logging.info(f"GitHub API 搜索完成，获取 {len(links)} 个链接")
    return links

async def search_links(session):
    """执行所有搜索查询，合并结果并按优先级排序"""
    logging.info("开始搜索链接")
    all_links = set(load_cached_links())
    github_links = await search_with_github_api(session)
    all_links.update(github_links)
    logging.info(f"GitHub API 查询获取 {len(github_links)} 个链接")
    prioritized_links = sorted(
        list(all_links),
        key=lambda x: sum(p in x for p in LINK_PRIORITY),
        reverse=True
    )
    save_cached_links(prioritized_links)
    if len(all_links) < 50:
        logging.warning(f"搜索结果不足 ({len(all_links)} 个链接)，请检查 GITHUB_TOKEN 或缓存文件 output/cached_links.json")
    logging.info(f"共获取 {len(all_links)} 个唯一链接")
    return prioritized_links[:500]

async def fetch_content(session, url):
    """异步获取网页内容，支持预检查和多平台 raw 链接转换"""
    logging.info(f"获取内容: {url}")
    domain = urllib.parse.urlparse(url).netloc
    if domain in DOMAIN_BLACKLIST or domain in FAILED_DOMAINS:
        STATS['failed_requests'] += 1
        STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
        logging.warning(f"跳过黑名单域名: {domain}")
        return None, url
    for attempt in range(MAX_RETRIES):
        try:
            async with session.head(url, timeout=REQUEST_TIMEOUT/2) as head_response:
                if head_response.status != 200:
                    STATS['failed_requests'] += 1
                    STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                    FAILED_DOMAINS.add(domain)
                    logging.warning(f"HEAD 请求失败: {url}, 状态码: {head_response.status}")
                    return None, url
                content_type = head_response.headers.get('content-type', '').lower()
                if not ('yaml' in content_type or 'octet-stream' in content_type or 'text/plain' in content_type):
                    logging.warning(f"跳过 {url}，无效内容类型: {content_type}")
                    return None, url
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            elif "gitlab.com" in url and "/blob/" in url:
                url = url.replace("/blob/", "/-/raw/")
            elif "bitbucket.org" in url and "/src/" in url:
                url = url.replace("/src/", "/raw/")
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status == 200:
                    logging.info(f"成功获取内容: {url}")
                    return await response.text(), url
                logging.warning(f"获取 {url} 失败，状态码: {response.status}")
                STATS['failed_requests'] += 1
                STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
                FAILED_DOMAINS.add(domain)
                await asyncio.sleep(2 ** attempt)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"获取 {url} 失败 (尝试 {attempt + 1}/{MAX_RETRIES}): {e}")
            STATS['failed_requests'] += 1
            STATS['failed_domains'][domain] = STATS['failed_domains'].get(domain, 0) + 1
            FAILED_DOMAINS.add(domain)
            await asyncio.sleep(2 ** attempt)
    logging.error(f"获取 {url} 失败，已达最大重试次数")
    return None, url

def extract_urls_from_content(content):
    """从内容中提取潜在的订阅链接"""
    logging.info("提取订阅链接")
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
    logging.info(f"提取到 {len(urls)} 个订阅链接")
    return urls[:MAX_SUB_LINKS]

def is_valid_clash_yaml(content):
    """验证是否为有效的 Clash YAML 配置，统计协议类型"""
    logging.info("验证 Clash YAML 配置")
    try:
        if "proxies:" not in content:
            logging.warning("未找到 proxies: 字段")
            return False, None, []
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            logging.warning("YAML 解析失败: 非字典格式")
            return False, None, []
        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            logging.warning("proxies 字段非列表")
            return False, None, []
        valid_proxies = []
        for proxy in proxies:
            if isinstance(proxy, dict) and "name" in proxy and "server" in proxy:
                protocol = proxy.get("type", "unknown")
                if protocol in ["ss", "trojan"]:
                    valid_proxies.append(proxy)
                    STATS['protocol_counts'][protocol] = STATS['protocol_counts'].get(protocol, 0) + 1
        provider_urls = []
        if "proxy-providers" in data:
            for provider in data.get("proxy-providers", {}).values():
                if isinstance(provider, dict) and "url" in provider:
                    provider_urls.append(provider["url"])
        logging.info(f"找到 {len(valid_proxies)} 个有效代理，{len(provider_urls)} 个订阅链接")
        return bool(valid_proxies), valid_proxies, provider_urls
    except yaml.YAMLError as e:
        logging.error(f"YAML 解析错误: {e}")
        return False, None, []

async def process_link(session, link, depth=0):
    """异步处理单个链接，提取代理节点和订阅链接"""
    logging.info(f"处理链接: {link} (深度: {depth})")
    if depth > RECURSION_DEPTH:
        logging.warning(f"超过最大递归深度 ({RECURSION_DEPTH})，跳过: {link}")
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
                valid_proxies.extend(proxies)  # 直接添加，无需测试
                STATS['nodes_found'] += len(proxies)
                STATS['links_by_source'][domain] = STATS['links_by_source'].get(domain, 0) + len(proxies)
                STATS['nodes_by_depth'][depth] = STATS['nodes_by_depth'].get(depth, 0) + len(proxies)
                logging.info(f"从 {url} 提取到 {len(proxies)} 个节点 (深度: {depth})")
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
            return valid_proxies + sub_proxies, provider_urls + additional_urls
    except asyncio.TimeoutError:
        logging.error(f"处理链接 {link} 超时")
        return [], []

async def main_async():
    try:
        create_output_dir()
        all_proxies = []
        processed_links = set()
        failed_links = []
        async with aiohttp.ClientSession() as session:
            logging.info("开始搜索链接")
            links = await search_links(session)
            logging.info(f"搜索完成，获取 {len(links)} 个初始链接")
            link_queue = deque(links)
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
                logging.info(f"处理批量链接，批次大小: {len(tasks)}")
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, result in enumerate(results):
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
                    else:
                        failed_links.append((link, str(result)))
                logging.info(f"批次处理完成，当前处理链接总数: {len(processed_links)}")

        # 去重
        logging.info("开始去重代理")
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
        logging.info(f"去重后保留 {len(unique_proxies)} 个代理")

        # 保存结果
        output_file = "clash_proxies.yaml"
        output_path = os.path.join(OUTPUT_DIR, output_file)
        if unique_proxies:
            output_data = {"proxies": unique_proxies}
            with open(output_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(output_data, f, allow_unicode=True)
            logging.info(f"已保存 {len(unique_proxies)} 个节点到 {output_path}")
        else:
            logging.warning("未找到任何有效的 Clash 代理配置")

        # 保存失败链接
        failed_path = "output/clash_failed.txt"
        with open(failed_path, "w", encoding="utf-8") as f:
            f.write("失败链接,#genre#\n")
            for link, error in failed_links:
                f.write(f"{link},{error}\n")
        logging.info(f"已保存 {len(failed_links)} 个失败链接到 {failed_path}")

        # 打印统计信息
        logging.info("\n统计信息：")
        logging.info(f"处理链接总数: {STATS['links_processed']}")
        logging.info(f"失败请求数: {STATS['failed_requests']}")
        logging.info(f"发现节点总数: {STATS['nodes_found']}")
        logging.info("节点来源分布：")
        for domain, count in sorted(STATS['links_by_source'].items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  {domain}: {count} 个节点")
        logging.info("协议分布：")
        for protocol, count in sorted(STATS['protocol_counts'].items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  {protocol}: {count} 个节点")
        logging.info("深度分布：")
        for depth, count in sorted(STATS['nodes_by_depth'].items()):
            logging.info(f"  深度 {depth}: {count} 个节点")
        logging.info("失败域名分布：")
        for domain, count in sorted(STATS['failed_domains'].items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  {domain}: {count} 次失败")
    except Exception as e:
        logging.error(f"主程序发生错误: {e}")
        raise

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
