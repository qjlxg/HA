import asyncio
import httpx
import re
import json
import base64
import yaml
from bs4 import BeautifulSoup
import aiofiles
import csv
from collections import defaultdict
import os
import random
import time
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# --- 配置 ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; HMA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.106 Mobile Safari/537.36",
]

# 缓存过期时间 (秒)
CACHE_EXPIRATION_TIME = 3600  # 1小时
cache = {}

# 代理协议正则表达式 (部分简化，完整的验证在 validate_and_fix_node 中完成)
NODE_PATTERNS = {
    "hysteria2": r"hysteria2:\/\/[^=\s]+(?:[^=\s]*=[^=\s]*)*",
    "vmess": r"vmess:\/\/[a-zA-Z0-9+\/=]+",
    "trojan": r"trojan:\/\/[^@]+@[^:]+:\d+",
    "ss": r"ss:\/\/[a-zA-Z0-9+\/=]+",
    "ssr": r"ssr:\/\/[a-zA-Z0-9+\/=]+",
    "vless": r"vless:\/\/[a-zA-Z0-9-]+@[^:]+:\d+",
}

# 用于存储所有处理过的 URL，避免重复抓取
processed_urls = set()

# --- 辅助函数 ---

def decode_base64_content(encoded_string):
    """递归解码 Base64 字符串，处理多层嵌套。"""
    decoded_content = encoded_string
    while True:
        try:
            # 尝试 Base64 解码，处理 URL 安全 Base64
            temp_decoded = base64.urlsafe_b64decode(decoded_content + "===").decode('utf-8', errors='ignore')
            if temp_decoded == decoded_content: # 没有变化，说明无法再解码
                break
            decoded_content = temp_decoded
        except Exception:
            break # 解码失败，停止
    return decoded_content

def clean_node(node_string):
    """清理节点字符串，移除多余空格、换行符等。"""
    return node_string.strip().replace('\r', '').replace('\n', '')

def validate_and_fix_node(node_string):
    """
    验证并尝试修复节点字符串。
    返回 (cleaned_node, status, reason)
    status: 'valid', 'fixed', 'invalid'
    reason: 详细的丢弃原因
    """
    cleaned_node = clean_node(node_string)
    original_node = cleaned_node

    if not cleaned_node:
        return "", "invalid", "empty_node"

    # 尝试识别并修复协议头
    if not any(cleaned_node.startswith(p) for p in NODE_PATTERNS.keys()):
        # 尝试推测协议类型并添加协议头
        if "vmess" in cleaned_node.lower() and not cleaned_node.startswith("vmess://"):
            try:
                # 尝试解析 JSON 来判断是否是 VMess
                json_data = json.loads(decode_base64_content(cleaned_node))
                if isinstance(json_data, dict) and "v" in json_data and "ps" in json_data:
                    cleaned_node = "vmess://" + base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')
                    # print(f"Fixed VMess: {original_node} -> {cleaned_node}")
            except Exception:
                pass
        # 更多协议的修复逻辑可以根据需要添加
    
    # 再次清理，以防修复后产生新的空白
    cleaned_node = clean_node(cleaned_node)

    # 逐一验证已知协议
    for protocol, pattern in NODE_PATTERNS.items():
        if re.fullmatch(pattern, cleaned_node):
            if original_node != cleaned_node:
                return cleaned_node, "fixed", f"protocol_fixed_{protocol}"
            return cleaned_node, "valid", protocol

    # 对于明文或无法识别的节点，尝试 Base64 解码后再次验证
    try:
        decoded_content = decode_base64_content(cleaned_node)
        if decoded_content != cleaned_node: # 成功解码
            for protocol, pattern in NODE_PATTERNS.items():
                if re.fullmatch(pattern, decoded_content):
                    if original_node != decoded_content:
                        return decoded_content, "fixed", f"base64_decoded_{protocol}"
                    return decoded_content, "valid", f"base64_valid_{protocol}"
            
            # 如果解码后仍然不是标准协议，尝试解析为 YAML 或 JSON 列表
            try:
                # 尝试 YAML
                yaml_data = yaml.safe_load(decoded_content)
                if isinstance(yaml_data, dict) and "proxies" in yaml_data:
                    # 假定是 Clash 格式
                    return cleaned_node, "valid", "clash_yaml"
                elif isinstance(yaml_data, list):
                    # 如果是节点列表，将其转换为字符串以便后续处理（例如，每个元素作为单独的潜在节点）
                    return cleaned_node, "fixed", "yaml_list"
            except yaml.YAMLError:
                pass # 不是有效的 YAML

            try:
                # 尝试 JSON
                json_data = json.loads(decoded_content)
                if isinstance(json_data, dict) and ("outbounds" in json_data or "proxies" in json_data):
                    # 假定是 sing-box 或 Clash 格式
                    return cleaned_node, "valid", "json_config"
                elif isinstance(json_data, list):
                    return cleaned_node, "fixed", "json_list"
            except json.JSONDecodeError:
                pass # 不是有效的 JSON

            # 如果解码后依然无法识别，但内容看起来有潜在节点
            if len(decoded_content) > 10 and not re.match(r'[^a-zA-Z0-9]', decoded_content): # 避免全是乱码
                return cleaned_node, "invalid", "base64_decoded_unrecognized"

    except Exception as e:
        # print(f"Base64 decode error for {original_node}: {e}")
        pass # 解码失败

    # 如果以上都没有匹配成功，则标记为无效
    return "", "invalid", "unrecognized_format"

# --- 核心逻辑 ---

async def fetch_url_content(url, use_playwright=False):
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    可以模拟浏览器获取动态内容。
    """
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    
    full_url_http = f"http://{url}" if not url.startswith(("http://", "https://")) else url
    full_url_https = f"https://{url}" if not url.startswith(("http://", "https://")) else url

    if use_playwright:
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                # 设置请求头
                await page.set_extra_http_headers(headers)
                
                # 尝试 HTTPS
                try:
                    await page.goto(full_url_https, wait_until='networkidle', timeout=30000)
                    await page.wait_for_timeout(2000) # 等待 JS 渲染
                    content = await page.content()
                    return content, "playwright_https"
                except PlaywrightTimeoutError:
                    print(f"Playwright HTTPS timeout for {full_url_https}, trying HTTP...")
                    # 尝试 HTTP
                    try:
                        await page.goto(full_url_http, wait_until='networkidle', timeout=30000)
                        await page.wait_for_timeout(2000) # 等待 JS 渲染
                        content = await page.content()
                        return content, "playwright_http"
                    except PlaywrightTimeoutError:
                        print(f"Playwright HTTP timeout for {full_url_http}.")
                        return None, None
                except Exception as e:
                    print(f"Playwright failed for {url}: {e}")
                    return None, None
            finally:
                if browser:
                    await browser.close()
    else:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, http2=True) as client:
            try:
                response = await client.get(full_url_https, headers=headers)
                response.raise_for_status()
                return response.text, "httpx_https"
            except httpx.RequestError as e:
                print(f"HTTPX HTTPS request failed for {full_url_https}: {e}, trying HTTP...")
            except httpx.HTTPStatusError as e:
                print(f"HTTPX HTTPS status error for {full_url_https}: {e}, trying HTTP...")

            try:
                response = await client.get(full_url_http, headers=headers)
                response.raise_for_status()
                return response.text, "httpx_http"
            except httpx.RequestError as e:
                print(f"HTTPX HTTP request failed for {full_url_http}: {e}")
            except httpx.HTTPStatusError as e:
                print(f"HTTPX HTTP status error for {full_url_http}: {e}")
        return None, None

def extract_urls_from_text(text):
    """从文本中提取 URL。"""
    # 匹配常见的 URL 模式，包括没有协议的域名
    urls = re.findall(r'(?:https?://|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/[^\s"<]*)?', text)
    # 过滤掉图片、CSS 等非HTML资源，并尝试补全协议
    filtered_urls = []
    for url in urls:
        if not re.search(r'\.(jpg|jpeg|png|gif|bmp|css|js|ico|xml|txt|json|pdf|zip|rar|tar\.gz)$', url, re.IGNORECASE):
            if not url.startswith(("http://", "https://")):
                url = f"http://{url}" # 默认使用 http
            filtered_urls.append(url)
    return list(set(filtered_urls))


def parse_and_extract_nodes(content, source_url):
    """
    解析网页内容，提取节点和新链接。
    优先处理 <pre>, <code>, <textarea> 等标签。
    支持嵌套 Base64 解码。
    """
    soup = BeautifulSoup(content, 'html.parser')
    extracted_nodes = []
    new_links = set()

    # 1. 优先从特定标签中提取内容
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            # 尝试 Base64 解码
            decoded_text = decode_base64_content(text_content)
            
            # 尝试解析为 YAML 或 JSON
            try:
                yaml_data = yaml.safe_load(decoded_text)
                if isinstance(yaml_data, dict) and "proxies" in yaml_data:
                    # Clash 格式，提取 proxies 字段
                    for proxy in yaml_data["proxies"]:
                        if isinstance(proxy, dict) and "type" in proxy:
                            # 转换为字符串，以便后续验证
                            extracted_nodes.append(f"{proxy['type']}://{json.dumps(proxy)}")
                elif isinstance(yaml_data, list):
                    for item in yaml_data:
                        if isinstance(item, str):
                            extracted_nodes.append(item)
            except yaml.YAMLError:
                pass

            try:
                json_data = json.loads(decoded_text)
                if isinstance(json_data, dict) and ("outbounds" in json_data or "proxies" in json_data):
                    # Sing-box 或 Clash 格式，提取相关字段
                    if "outbounds" in json_data:
                        for outbound in json_data["outbounds"]:
                            if isinstance(outbound, dict) and "type" in outbound:
                                extracted_nodes.append(f"{outbound['type']}://{json.dumps(outbound)}")
                    elif "proxies" in json_data:
                        for proxy in json_data["proxies"]:
                            if isinstance(proxy, dict) and "type" in proxy:
                                extracted_nodes.append(f"{proxy['type']}://{json.dumps(proxy)}")
                elif isinstance(json_data, list):
                    for item in json_data:
                        if isinstance(item, str):
                            extracted_nodes.append(item)
            except json.JSONDecodeError:
                pass

            # 提取文本中可能包含的节点
            for protocol, pattern in NODE_PATTERNS.items():
                extracted_nodes.extend(re.findall(pattern, decoded_text))
            
            # 从文本中提取新链接
            new_links.update(extract_urls_from_text(decoded_text))


    # 2. 从所有文本内容中提取节点和链接 (补充)
    text_content_full = soup.get_text()
    
    # 尝试 Base64 解码整个页面文本
    decoded_full_text = decode_base64_content(text_content_full)

    for protocol, pattern in NODE_PATTERNS.items():
        extracted_nodes.extend(re.findall(pattern, decoded_full_text))

    # 提取所有链接
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # 排除邮件链接，相对路径等
        if href.startswith(("http://", "https://")) or href.startswith("//"):
            if href.startswith("//"): # 补全协议
                href = f"http:{href}" # 默认 HTTP
            new_links.add(href)
        elif not re.match(r'^(#|mailto:|javascript:)', href):
            # 尝试拼接相对路径
            parsed_source = urllib.parse.urlparse(source_url)
            full_link = urllib.parse.urljoin(source_url, href)
            new_links.add(full_link)
    
    # 从整个页面文本中提取 URL
    new_links.update(extract_urls_from_text(decoded_full_text))

    # 去重
    extracted_nodes = list(set(extracted_nodes))
    new_links = list(set(link for link in new_links if link not in processed_urls))

    return extracted_nodes, new_links

async def process_url(url, depth=0, max_depth=2, use_playwright_for_dynamic=False, all_nodes_stats=None):
    """
    处理单个 URL，抓取内容，提取节点和新链接。
    递归抓取嵌套链接，限制最大深度。
    """
    if url in processed_urls:
        return []
    
    processed_urls.add(url)
    print(f"Processing URL (Depth {depth}): {url}")

    current_nodes = []
    content_key = url # 缓存键
    content, fetch_method = None, None

    # 检查缓存
    if content_key in cache and (time.time() - cache[content_key]['timestamp']) < CACHE_EXPIRATION_TIME:
        content = cache[content_key]['content']
        print(f"Cache hit for {url}")
    else:
        content, fetch_method = await fetch_url_content(url, use_playwright=use_playwright_for_dynamic)
        if content:
            cache[content_key] = {'content': content, 'timestamp': time.time()}
        else:
            print(f"Failed to fetch content from {url}")
            return []

    if content:
        extracted_nodes, new_links = parse_and_extract_nodes(content, url)
        
        node_stats = defaultdict(int)
        valid_nodes_for_url = []
        
        for node_raw in extracted_nodes:
            cleaned_node, status, reason = validate_and_fix_node(node_raw)
            all_nodes_stats[status][reason] += 1
            node_stats[status] += 1

            if status in ('valid', 'fixed'):
                valid_nodes_for_url.append(cleaned_node)
                current_nodes.append(cleaned_node)
                # print(f"  Node: {cleaned_node[:50]}... Status: {status}, Reason: {reason}")
            else:
                # print(f"  Discarded node: {node_raw[:50]}... Status: {status}, Reason: {reason}")
                pass
        
        # 保存每个 URL 获取到的有效节点
        if valid_nodes_for_url:
            output_filename = os.path.join("data", f"{re.sub(r'[^a-zA-Z0-9]', '_', url)[:100]}.txt") # 安全文件名
            async with aiofiles.open(output_filename, "w", encoding="utf-8") as f:
                await f.write("\n".join(valid_nodes_for_url))
            print(f"  Saved {len(valid_nodes_for_url)} nodes from {url} to {output_filename}")
        
        # 记录每个 URL 的节点统计
        stats_csv_path = os.path.join("data", "node_counts.csv")
        is_new_file = not os.path.exists(stats_csv_path) or os.path.getsize(stats_csv_path) == 0
        async with aiofiles.open(stats_csv_path, "a", newline="", encoding="utf-8") as csvfile:
            fieldnames = ['URL', 'FetchMethod', 'ValidCount', 'FixedCount', 'InvalidCount', 'TotalExtracted']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if is_new_file:
                await writer.writeheader()
            
            await writer.writerow({
                'URL': url,
                'FetchMethod': fetch_method,
                'ValidCount': node_stats['valid'],
                'FixedCount': node_stats['fixed'],
                'InvalidCount': node_stats['invalid'],
                'TotalExtracted': len(extracted_nodes)
            })

        if depth < max_depth:
            # 异步并发处理新发现的链接
            tasks = [process_url(link, depth + 1, max_depth, use_playwright_for_dynamic, all_nodes_stats) for link in new_links if link not in processed_urls]
            await asyncio.gather(*tasks)
    
    return current_nodes

async def main():
    if not os.path.exists("data"):
        os.makedirs("data")

    sources_path = "sources.list"
    urls_to_process = []
    try:
        async with aiofiles.open(sources_path, "r", encoding="utf-8") as f:
            async for line in f:
                url = line.strip()
                if url:
                    urls_to_process.append(url)
    except FileNotFoundError:
        print(f"Error: {sources_path} not found. Please create it and add URLs.")
        return

    all_nodes_stats = defaultdict(lambda: defaultdict(int)) # {status: {reason: count}}

    tasks = [process_url(url, use_playwright_for_dynamic=True, all_nodes_stats=all_nodes_stats) for url in urls_to_process]
    await asyncio.gather(*tasks)

    # 打印最终节点统计
    print("\n--- Final Node Statistics ---")
    total_valid = 0
    total_fixed = 0
    total_invalid = 0

    for status, reasons in all_nodes_stats.items():
        print(f"Status: {status.upper()}")
        for reason, count in reasons.items():
            print(f"  Reason '{reason}': {count} nodes")
            if status == 'valid':
                total_valid += count
            elif status == 'fixed':
                total_fixed += count
            elif status == 'invalid':
                total_invalid += count
    
    print(f"\nTotal Valid Nodes: {total_valid}")
    print(f"Total Fixed Nodes: {total_fixed}")
    print(f"Total Invalid Nodes: {total_invalid}")

if __name__ == "__main__":
    import urllib.parse # 仅在 main 启动时导入，避免循环依赖
    asyncio.run(main())
