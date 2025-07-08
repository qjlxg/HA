import requests
import re
import os
import csv
import base64
import yaml
import json
import hashlib
import random
from urllib.parse import unquote, urlparse

# --- 配置部分 ---
DATA_DIR = "data"
SOURCES_FILE = "sources.list"
ALL_NODES_FINAL_FILE = os.path.join(DATA_DIR, "all_nodes_final.txt")
NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义支持的节点协议正则表达式
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# 随机 User-Agent 池
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.56',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
]

# --- 辅助函数 ---

def read_sources(file_path):
    """从 sources.list 文件读取所有 URL"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    urls.append(stripped_line)
        print(f"成功读取 {len(urls)} 个源 URL。")
    except FileNotFoundError:
        print(f"错误：源文件 '{file_path}' 未找到。请确保它位于脚本的同级目录。")
    return urls

def load_cache(cache_file):
    """加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("警告: 缓存文件损坏，将重新生成。")
            return {}
    return {}

def save_cache(cache_file, cache_data):
    """保存 URL 缓存"""
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(cache_data, f, indent=4)

def fetch_content(url, retries=3, cache_data=None):
    """
    尝试通过 HTTP 或 HTTPS 获取网页内容，并包含重试机制。
    会模拟随机浏览器用户代理。
    并尝试利用 ETag 或 Last-Modified 进行条件请求。
    如果URL没有协议，会先尝试http，再尝试https。
    """
    print(f"正在尝试获取内容：{url}")
    current_headers = {
        'User-Agent': random.choice(USER_AGENTS), # 每次请求随机User-Agent
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'DNT': '1', # Do Not Track
        'Connection': 'keep-alive'
    }

    # 添加条件请求头
    if cache_data and url in cache_data:
        if 'etag' in cache_data[url]:
            current_headers['If-None-Match'] = cache_data[url]['etag']
            # print(f"  使用 If-None-Match: {cache_data[url]['etag']}") # 调试信息
        if 'last_modified' in cache_data[url]:
            current_headers['If-Modified-Since'] = cache_data[url]['last_modified']
            # print(f"  使用 If-Modified-Since: {cache_data[url]['last_modified']}") # 调试信息
    
    # 确定要尝试的URL列表
    test_urls = []
    if urlparse(url).scheme: # 如果URL已经有协议头
        test_urls.append(url)
    else: # 如果URL没有协议头
        test_urls.append(f"http://{url}")
        test_urls.append(f"https://{url}")

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                print(f"  尝试请求: {current_url_to_test} (尝试 {attempt + 1}/{retries})")
                response = requests.get(current_url_to_test, timeout=20, headers=current_headers, allow_redirects=True)
                
                if response.status_code == 304: # Not Modified
                    print(f"  内容未修改 (304 Not Modified) for {current_url_to_test}，跳过下载。")
                    return None, None # 返回 None 表示内容未更新
                    
                response.raise_for_status() # 对 4xx/5xx 状态码抛出 HTTPError
                print(f"  成功获取 {current_url_to_test}")
                
                # 更新缓存数据
                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                
                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': hashlib.sha256(response.text.encode('utf-8')).hexdigest()}
                
            except requests.exceptions.Timeout:
                print(f"  请求超时 for {current_url_to_test}")
            except requests.exceptions.RequestException as e:
                print(f"  获取失败 for {current_url_to_test} ({e})")
        
        if attempt < retries - 1:
            import time
            time.sleep(2 ** attempt + 1) # 指数退避，增加1秒基础等待时间

    print(f"所有 {retries} 次尝试均失败，无法获取 {url} 的内容。")
    return None, None

def decode_base64(data):
    """尝试解码 Base64 字符串"""
    if not isinstance(data, str):
        return None
    data = data.strip()
    # 尝试 Base64 解码，并确保是 UTF-8 可读
    try:
        # base64.urlsafe_b64decode 适用于处理包含 - 和 _ 的 base64 字符串
        decoded_bytes = base64.urlsafe_b64decode(data + '==') # 补齐填充字符
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        try: # 尝试标准 Base64
            decoded_bytes = base64.b64decode(data + '==')
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None

def is_valid_node(node_url):
    """
    检查节点 URL 的基本有效性。
    这只是初步的格式和内容检查，不涉及网络连通性。
    """
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False

    parsed_url = urlparse(node_url)
    
    # 检查是否有识别的协议头
    found_protocol = False
    for proto in NODE_PATTERNS.keys():
        if node_url.lower().startswith(f"{proto}://"):
            found_protocol = True
            break
    if not found_protocol:
        return False

    # 检查是否有主机名/IP (对于非 ss/ssr/vmess 编码的协议)
    if not node_url.lower().startswith(("ss://", "ssr://", "vmess://")):
        if not parsed_url.hostname:
            return False

    # 简单的额外检查：例如，vmess:// 后面通常跟着 Base64 编码的 JSON
    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = node_url[len("vmess://"):]
            decoded = decode_base64(b64_content)
            if not decoded or not decoded.strip().startswith('{') or not decoded.strip().endswith('}'):
                return False
            json.loads(decoded) # 尝试解析，确保是有效JSON
        except (ValueError, json.JSONDecodeError, TypeError):
            return False
    
    return True

def parse_content(content):
    """
    尝试解析内容，可能是纯文本、HTML、Base64 或 YAML。
    返回解析后的纯文本字符串，其中可能包含节点。
    """
    if not content:
        return ""

    # 1. 尝试 Base64 解码 (通常订阅链接返回的 Base64 编码列表)
    decoded_content = decode_base64(content)
    if decoded_content:
        # 再次检查解码后的内容是否包含节点模式，防止误判
        if any(pattern.search(decoded_content) for pattern in NODE_PATTERNS.values()):
            print("内容被识别为 Base64 编码，已解码。")
            return decoded_content

    # 2. 尝试 YAML 解析 (V2rayN 或 Clash 配置)
    try:
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml):
            print("内容被识别为 YAML 格式。")
            nodes_from_yaml_structure = [] # 从YAML结构中提取的节点
            if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
                for proxy in parsed_yaml['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        try:
                            # 尝试根据 proxy 的类型和字段重构标准节点 URL
                            # 这部分需要根据 YAML 配置的结构来具体实现
                            if proxy['type'].lower() == 'vmess':
                                # Vmess 通常是 Base64 编码的JSON，这里需要重新编码整个代理配置
                                nodes_from_yaml_structure.append(f"vmess://{base64.b64encode(json.dumps(proxy).encode('utf-8')).decode('utf-8')}")
                            elif proxy['type'].lower() == 'ss' and 'password' in proxy:
                                method_pwd = f"{proxy.get('cipher')}:{proxy.get('password')}"
                                nodes_from_yaml_structure.append(f"ss://{base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'trojan' and 'password' in proxy:
                                nodes_from_yaml_structure.append(f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'vless' and 'uuid' in proxy:
                                nodes_from_yaml_structure.append(f"vless://{proxy.get('uuid')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'hysteria2' and 'password' in proxy:
                                nodes_from_yaml_structure.append(f"hysteria2://{proxy.get('server')}:{proxy.get('port')}?password={proxy.get('password')}")
                        except Exception as e:
                            print(f"  警告: 解析 YAML 代理条目失败 ({proxy.get('type')}): {e}")
            
            # 将解析出的 YAML 节点与原始内容合并，以便后续正则表达式提取
            # 这样可以确保如果YAML文件中同时有原生节点字符串和结构化代理配置，都能被捕获
            return content + "\n" + "\n".join(nodes_from_yaml_structure)
    except yaml.YAMLError:
        pass # 不是有效的 YAML

    # 3. 尝试 HTML 解析 (网页内容)
    if '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower():
        print("内容被识别为 HTML 格式。")
        soup = BeautifulSoup(content, 'html.parser')
        
        extracted_text = []
        # 查找所有可能是代码块或预格式化文本的标签
        potential_node_containers = soup.find_all(['pre', 'code', 'textarea'])
        for tag in potential_node_containers:
            extracted_text.append(tag.get_text(separator="\n", strip=True))

        # 尝试从整个 body 提取文本，作为最后的补充
        if soup.body:
            body_text = soup.body.get_text(separator="\n", strip=True)
            # 仅在body_text足够长或包含可能节点时添加，避免添加大量无关内容
            if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()):
                extracted_text.append(body_text)
            
        return "\n".join(extracted_text)
        
    # 4. 否则，视为纯文本
    print("内容被识别为纯文本格式。")
    return content

def extract_and_validate_nodes(content):
    """
    从解析后的内容中提取并验证所有支持格式的节点 URL。
    """
    if not content:
        return []
    
    found_nodes = set()
    
    for pattern_name, pattern_regex in NODE_PATTERNS.items():
        matches = pattern_regex.findall(content)
        for match in matches:
            decoded_match = unquote(match).strip()
            if is_valid_node(decoded_match):
                found_nodes.add(decoded_match)

    return list(found_nodes)

def load_existing_nodes(file_path):
    """加载已存在的节点列表，用于增量更新"""
    existing_nodes = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(' = ', 1)
                    if len(parts) == 2:
                        existing_nodes.add(parts[1])
            print(f"已加载 {len(existing_nodes)} 个现有节点。")
        except Exception as e:
            print(f"警告: 加载现有节点文件失败 ({file_path}): {e}，将从头开始。")
    return existing_nodes

def save_nodes_to_file(file_path, nodes):
    """将处理后的节点保存到文本文件，并进行升序自定义命名"""
    with open(file_path, 'w', encoding='utf-8') as f:
        for i, node in enumerate(nodes):
            f.write(f"Proxy-{i+1:03d} = {node}\n")
    print(f"最终节点列表已保存到 {file_path}")

def save_node_counts_to_csv(file_path, counts_data):
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Source URL", "Node Count"])
        for url, count in counts_data.items():
            writer.writerow([url, count])
    print(f"节点数量统计已保存到 {file_path}")

# --- 主逻辑 ---

def main():
    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        print("未找到任何源 URL，脚本终止。")
        return

    url_cache = load_cache(CACHE_FILE)
    existing_nodes = load_existing_nodes(ALL_NODES_FINAL_FILE)
    
    all_new_and_existing_nodes = set(existing_nodes)
    url_node_counts = {}

    processed_urls_count = 0
    skipped_urls_count = 0

    for url in source_urls:
        # 获取内容并更新缓存元数据
        content, new_cache_meta = fetch_content(url, cache_data=url_cache)

        # 如果内容未更新（304）或获取失败
        if content is None and new_cache_meta is None:
            print(f"  {url}: 内容未更新或获取失败，跳过处理。")
            # 沿用上次缓存的节点数量，或设为0如果无缓存
            url_node_counts[url] = url_cache.get(url, {}).get('node_count', 0) 
            skipped_urls_count += 1
            continue
        
        # 即使获取到内容，也要再次检查哈希值，防止ETag/Last-Modified失效但内容未变
        last_content_hash = url_cache.get(url, {}).get('content_hash')
        current_content_hash = new_cache_meta['content_hash'] if new_cache_meta else None

        if last_content_hash and current_content_hash == last_content_hash:
            print(f"  {url}: 内容哈希值未变，跳过重新解析和提取。")
            url_node_counts[url] = url_cache.get(url, {}).get('node_count', 0)
            skipped_urls_count += 1
            continue
            
        processed_urls_count += 1
        
        # 解析内容 (包含 Base64, YAML, HTML 处理)
        parsed_content = parse_content(content)
        
        # 提取并验证节点
        nodes_from_url = extract_and_validate_nodes(parsed_content)
        
        print(f"从 {url} 提取到 {len(nodes_from_url)} 个有效节点。")
        url_node_counts[url] = len(nodes_from_url)
        all_new_and_existing_nodes.update(nodes_from_url) # 将新提取的节点加入总集合

        # 更新缓存信息
        if new_cache_meta:
            url_cache[url] = {
                'etag': new_cache_meta.get('etag'),
                'last_modified': new_cache_meta.get('last_modified'),
                'content_hash': current_content_hash,
                'node_count': len(nodes_from_url) # 缓存本次提取到的节点数量
            }
        else: # 如果内容获取失败，也更新缓存以避免下次再次尝试下载（如果失败是持续的）
             url_cache[url] = url_cache.get(url, {}) # 保持旧的缓存，如果新的没有成功获取
             url_cache[url]['node_count'] = 0 # 设为0，表示上次获取失败
        
        # 每处理一个URL就保存一次缓存，防止中断丢失
        save_cache(CACHE_FILE, url_cache)

    print(f"\n处理完成。共处理 {processed_urls_count} 个URL，跳过 {skipped_urls_count} 个URL。")
    print(f"总共收集到 {len(all_new_and_existing_nodes)} 个去重后的节点 (含原有节点)。")

    # 对所有收集到的节点进行最终排序
    final_nodes_list = sorted(list(all_new_and_existing_nodes)) 

    # 保存最终节点列表和统计数据
    save_nodes_to_file(ALL_NODES_FINAL_FILE, final_nodes_list)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_node_counts)
    save_cache(CACHE_FILE, url_cache) # 最终保存一次缓存

if __name__ == "__main__":
    main()
