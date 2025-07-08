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
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置部分 ---
DATA_DIR = "data"
SOURCES_FILE = "sources.list"
NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, "proxy_nodes_")
MAX_NODES_PER_SLICE = 2000

NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")

# 并发配置
MAX_WORKERS = 10 # 同时处理的 URL 数量，您可以根据网络和服务器负载调整，建议5-20之间
REQUEST_TIMEOUT = 10 # 单次请求超时时间，可适当缩短，单位秒

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义支持的节点协议正则表达式
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    # 已修复：将 'a-9' 改为 'a-zA-Z0-9'，以包含大小写字母和数字
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
    Simulates a random browser user agent.
    Tries to use ETag or Last-Modified for conditional requests.
    If the URL has no scheme, it will first try http, then https.
    """
    current_headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'DNT': '1',
        'Connection': 'keep-alive'
    }

    if cache_data and url in cache_data:
        if 'etag' in cache_data[url]:
            current_headers['If-None-Match'] = cache_data[url]['etag']
        if 'last_modified' in cache_data[url]:
            current_headers['If-Modified-Since'] = cache_data[url]['last_modified']
    
    test_urls = []
    # 确保 URL 具有方案 (scheme)，如果缺失则尝试添加 http/https
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        test_urls.append(f"http://{url}")
        test_urls.append(f"https://{url}")
    else:
        test_urls.append(url)

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                response = requests.get(current_url_to_test, timeout=REQUEST_TIMEOUT, headers=current_headers, allow_redirects=True, verify=False)
                
                if response.status_code == 304:
                    print(f"  {url} 内容未修改 (304)。")
                    return None, None
                    
                response.raise_for_status()
                
                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                
                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': hashlib.sha256(response.text.encode('utf-8')).hexdigest()}
                
            except requests.exceptions.Timeout:
                print(f"  {url} 请求超时。")
            except requests.exceptions.RequestException as e:
                print(f"  {url} 获取失败 ({e})。")
        
        if attempt < retries - 1:
            import time
            time.sleep(2 ** attempt + 1)

    print(f"  {url} 所有 {retries} 次尝试均失败。")
    return None, None

def decode_base64(data):
    """尝试解码 Base64 字符串"""
    if not isinstance(data, str):
        return None
    data = data.strip()
    try:
        decoded_bytes = base64.urlsafe_b64decode(data + '==')
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        try:
            decoded_bytes = base64.b64decode(data + '==')
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None

def is_valid_node(node_url):
    """
    检查节点 URL 的基本有效性。
    """
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False

    parsed_url = urlparse(node_url)
    
    found_protocol = False
    for proto in NODE_PATTERNS.keys():
        if node_url.lower().startswith(f"{proto}://"):
            found_protocol = True
            break
    if not found_protocol:
        return False

    # 对于非 ss/ssr/vmess 协议，需要有主机名
    # 对于 ss/ssr/vmess，它们内部可能会有编码，因此不强制检查 parsed_url.hostname
    if not node_url.lower().startswith(("ss://", "ssr://", "vmess://")):
        if not parsed_url.hostname:
            return False

    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = node_url[len("vmess://"):]
            decoded = decode_base64(b64_content)
            if not decoded or not decoded.strip().startswith('{') or not decoded.strip().endswith('}'):
                return False
            json.loads(decoded)
        except (ValueError, json.JSONDecodeError, TypeError):
            return False
    
    return True

def parse_content(content):
    """
    尝试解析内容，可能是纯文本、HTML、Base64 或 YAML。
    """
    if not content:
        return ""

    decoded_content = decode_base64(content)
    if decoded_content:
        if any(pattern.search(decoded_content) for pattern in NODE_PATTERNS.values()):
            print("内容被识别为 Base64 编码，已解码。")
            return decoded_content

    try:
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml):
            print("内容被识别为 YAML 格式。")
            nodes_from_yaml_structure = []
            if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
                for proxy in parsed_yaml['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        try:
                            if proxy['type'].lower() == 'vmess':
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
            
            return content + "\n" + "\n".join(nodes_from_yaml_structure)
    except yaml.YAMLError:
        pass

    if '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower():
        print("内容被识别为 HTML 格式。")
        soup = BeautifulSoup(content, 'html.parser')
        
        extracted_text = []
        potential_node_containers = soup.find_all(['pre', 'code', 'textarea'])
        for tag in potential_node_containers:
            extracted_text.append(tag.get_text(separator="\n", strip=True))

        if soup.body:
            body_text = soup.body.get_text(separator="\n", strip=True)
            if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()):
                extracted_text.append(body_text)
            
        return "\n".join(extracted_text)
        
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

def load_existing_nodes_from_slices(directory, prefix):
    """从多个切片文件中加载已存在的节点列表，用于增量更新"""
    existing_nodes = set()
    loaded_count = 0
    for filename in os.listdir(directory):
        if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(' = ', 1)
                        if len(parts) == 2:
                            existing_nodes.add(parts[1])
                            loaded_count += 1
            except Exception as e:
                print(f"警告: 加载现有节点文件失败 ({file_path}): {e}")
    print(f"已从 {len(os.listdir(directory))} 个切片文件中加载 {loaded_count} 个现有节点。")
    return existing_nodes

def save_nodes_to_sliced_files(output_prefix, nodes, max_nodes_per_slice):
    """将处理后的节点切片保存到多个文本文件，并进行升序自定义命名"""
    total_nodes = len(nodes)
    num_slices = (total_nodes + max_nodes_per_slice - 1) // max_nodes_per_slice
    
    # 清理旧的切片文件
    for filename in os.listdir(DATA_DIR):
        if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'):
            os.remove(os.path.join(DATA_DIR, filename))
            print(f"已删除旧切片文件: {filename}")

    saved_files_count = 0
    for i in range(num_slices):
        start_index = i * max_nodes_per_slice
        end_index = min((i + 1) * max_nodes_per_slice, total_nodes)
        
        slice_nodes = nodes[start_index:end_index]
        slice_file_name = f"{output_prefix}{i+1:03d}.txt"
        
        with open(slice_file_name, 'w', encoding='utf-8') as f:
            for j, node in enumerate(slice_nodes):
                global_index = start_index + j
                f.write(f"Proxy-{global_index+1:05d} = {node}\n")
        print(f"已保存切片文件: {slice_file_name} (包含 {len(slice_nodes)} 个节点)")
        saved_files_count += 1
    
    print(f"最终节点列表已切片保存到 {saved_files_count} 个文件。")

def save_node_counts_to_csv(file_path, counts_data):
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Source URL", "Node Count"])
        for url, count in counts_data.items():
            writer.writerow([url, count])
    print(f"节点数量统计已保存到 {file_path}")

# --- 主逻辑 ---

def process_single_url(url, url_cache_data):
    """处理单个URL的逻辑，方便并发调用"""
    content, new_cache_meta = fetch_content(url, cache_data=url_cache_data)

    if content is None and new_cache_meta is None:
        return url, 0, None, url_cache_data.get(url, {}) # 返回 URL, 节点数, 新缓存元数据, 旧缓存数据

    last_content_hash = url_cache_data.get(url, {}).get('content_hash')
    current_content_hash = new_cache_meta['content_hash'] if new_cache_meta else None

    if last_content_hash and current_content_hash == last_content_hash:
        return url, url_cache_data.get(url, {}).get('node_count', 0), None, url_cache_data.get(url, {})

    parsed_content = parse_content(content)
    nodes_from_url = extract_and_validate_nodes(parsed_content)
    
    print(f"从 {url} 提取到 {len(nodes_from_url)} 个有效节点。")

    if new_cache_meta:
        new_cache_meta['node_count'] = len(nodes_from_url)
    else:
        # 如果没有新的缓存元数据（例如，fetch_content返回了None但不是304），也要确保node_count被设置
        new_cache_meta = url_cache_data.get(url, {}) # 获取旧的缓存信息
        new_cache_meta['node_count'] = len(nodes_from_url) # 更新节点数量
        
    return url, len(nodes_from_url), new_cache_meta, nodes_from_url


def main():
    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        print("未找到任何源 URL，脚本终止。")
        return

    url_cache = load_cache(CACHE_FILE)
    existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX)
    
    all_new_and_existing_nodes = set(existing_nodes)
    url_node_counts = {}

    processed_urls_count = 0
    skipped_urls_count = 0

    # 使用线程池并发处理 URL
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有 URL 任务
        future_to_url = {executor.submit(process_single_url, url, url_cache.get(url, {}).copy()): url for url in source_urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                processed_url, node_count, updated_cache_meta, extracted_nodes_list = future.result()
                
                url_node_counts[processed_url] = node_count
                
                if extracted_nodes_list: # 只有成功提取到节点时才更新总节点集合
                    all_new_and_existing_nodes.update(extracted_nodes_list)
                
                if updated_cache_meta:
                    url_cache[processed_url] = updated_cache_meta
                    processed_urls_count += 1
                else: # 如果 updated_cache_meta 为 None，说明是 304 或内容未变
                    url_cache[processed_url] = url_cache.get(processed_url, {}) # 保持旧缓存
                    url_cache[processed_url]['node_count'] = node_count # 确保节点数量更新（即使是0）
                    skipped_urls_count += 1 # 计入跳过
                
                save_cache(CACHE_FILE, url_cache) # 每次处理完一个 URL 就保存缓存
            except Exception as exc:
                print(f'{url} 生成了一个异常: {exc}')
                url_node_counts[url] = url_cache.get(url, {}).get('node_count', 0) # 失败的URL，节点数保持不变
                skipped_urls_count += 1 # 错误也算跳过处理
                save_cache(CACHE_FILE, url_cache) # 确保缓存也被保存

    print(f"\n处理完成。共处理 {processed_urls_count} 个URL，跳过 {skipped_urls_count} 个URL。")
    final_nodes_list = sorted(list(all_new_and_existing_nodes))
    print(f"总共收集到 {len(final_nodes_list)} 个去重后的节点 (含原有节点)。")

    save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_node_counts)
    save_cache(CACHE_FILE, url_cache) # 最终保存一次缓存

if __name__ == "__main__":
    main()
