import os
import requests
import yaml
import csv
import re
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from bs4 import BeautifulSoup
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 定义需要尝试的 YAML 文件名
CONFIG_NAMES = [
    'config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml',
    'clash.yaml', 'openclash.yaml', 'clash-socket.yaml', 'v2ray.yaml',
    'proxies.yaml', 'nodes.yaml', 'new.yaml', 'sf.yaml'
]

# 浏览器User-Agent列表，用于伪装请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
]

# 初始化 IP 地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    logger.info("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    logger.error(f"无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)
except Exception as e:
    logger.error(f"初始化地理位置数据库时发生错误: {e}")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def test_connection_and_get_protocol(link):
    """
    测试一个链接的连通性，并返回成功的协议和内容类型。
    优先测试 HTTPS。
    """
    link = link.replace('http://', '').replace('https://', '')
    
    # 优先尝试 HTTPS
    try:
        response = requests.head(f"https://{link}", headers=get_headers(), timeout=5) # 缩短超时时间
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            return link, "https", "html" if 'text/html' in content_type else "yaml"
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTPS 失败，尝试 HTTP
    try:
        response = requests.head(f"http://{link}", headers=get_headers(), timeout=5) # 缩短超时时间
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            return link, "http", "html" if 'text/html' in content_type else "yaml"
    except requests.exceptions.RequestException:
        pass
        
    return None, None, None

def pre_test_links(links):
    """并发预测试所有链接，返回可用链接、协议和内容类型的字典"""
    working_links = {}
    max_workers = min(64, os.cpu_count() * 4) if os.cpu_count() else 32 # 增加并发数量
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(test_connection_and_get_protocol, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result_link, result_protocol, content_type = future.result()
            if result_link:
                working_links[result_link] = {'protocol': result_protocol, 'type': content_type}
    return working_links

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def fetch_yaml_content(url):
    """尝试直接下载 YAML 文件，使用流式读取"""
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10, stream=True) # 缩短超时时间
        if response.status_code == 200 and 'text/html' not in response.headers.get('content-type', '').lower():
            content = ''
            content_length = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk.decode('utf-8')
                downloaded += len(chunk)
            if content_length and downloaded < content_length:
                logger.warning(f"下载不完整: {url}, 预期 {content_length} 字节, 实际 {downloaded} 字节")
                return None, None
            try:
                yaml.safe_load(content)
                return content, url
            except yaml.YAMLError as e:
                logger.warning(f"YAML 解析失败: {url}, 错误: {e}")
                return None, None
        return None, None
    except requests.exceptions.RequestException as e:
        logger.warning(f"下载失败: {url}, 错误: {e}")
        return None, None

def parse_and_fetch_from_html(url):
    """解析 HTML 页面，批量收集并尝试下载 YAML 文件"""
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10) # 缩短超时时间
        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 策略1: 收集所有以 .yaml 或 .yml 结尾的链接
            yaml_urls = [requests.compat.urljoin(url, link.get('href'))
                         for link in soup.find_all('a')
                         if link.get('href') and link.get('href').lower().endswith(('.yaml', '.yml'))]
            
            # 策略2: 寻找包含特定关键字的链接
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and re.search(r'(clash|v2ray|mihomo|config)', href, re.IGNORECASE):
                    full_url = requests.compat.urljoin(url, href)
                    if full_url not in yaml_urls:
                        yaml_urls.append(full_url)
            
            # 策略3: 从 <script> 标签中解析
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    match = re.search(r'\"url\"\s*:\s*\"(.*?\.ya?ml)\"', script_content, re.DOTALL | re.IGNORECASE)
                    if match:
                        yaml_url = match.group(1)
                        if not yaml_url.startswith(('http://', 'https://')):
                            yaml_url = requests.compat.urljoin(url, yaml_url)
                        if yaml_url not in yaml_urls:
                            yaml_urls.append(yaml_url)
            
            # 批量尝试下载 YAML 文件
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(fetch_yaml_content, yaml_url): yaml_url for yaml_url in yaml_urls}
                for future in as_completed(future_to_url):
                    content, final_url = future.result()
                    if content:
                        return content, final_url  # 返回第一个成功下载的 YAML 文件
        return None, None
    except requests.exceptions.RequestException as e:
        logger.warning(f"HTML 解析失败: {url}, 错误: {e}")
        return None, None

def process_links(working_links):
    """第二阶段：处理可用的链接，分批处理"""
    all_nodes = []
    node_counts = []
    processed_links = set()
    
    max_workers = min(32, os.cpu_count() * 2) if os.cpu_count() else 16
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {}
        for link, info in working_links.items():
            full_url = f"{info['protocol']}://{link}"
            if info['type'] == 'html':
                # 优先处理 HTML 解析
                task = {'type': 'html_parse', 'url': full_url}
                future = executor.submit(parse_and_fetch_from_html, task['url'])
                future_to_task[future] = task
            else:
                # 否则，直接尝试下载
                for config_name in CONFIG_NAMES:
                    full_yaml_url = f"{full_url}/{config_name}"
                    if full_yaml_url not in processed_links:
                        task = {'type': 'direct', 'url': full_yaml_url}
                        future = executor.submit(fetch_yaml_content, task['url'])
                        future_to_task[future] = task
        
        for future in tqdm(as_completed(future_to_task), total=len(future_to_task), desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            
            if not successful_url or successful_url in processed_links:
                continue
            
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            ip = node.get('server', '')
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                try:
                                    country_code, country_name = geolocator.get_location(ip)
                                    node['name'] = country_name or '未知'
                                except:
                                    node['name'] = '未知'
                        all_nodes.extend(nodes)
                        node_counts.append({'url': successful_url, 'count': len(nodes)})
                        processed_links.add(successful_url)
                        logger.info(f"成功从 {successful_url} 获取 {len(nodes)} 个节点")
                    else:
                        logger.warning(f"YAML 内容格式不正确: {successful_url}")
                except yaml.YAMLError as e:
                    logger.warning(f"无法解析 YAML 内容: {successful_url}, 错误: {e}")
    
    return all_nodes, node_counts

def get_node_key(node):
    """定义节点唯一键，忽略 server IP 以处理 CDN 重复"""
    ws_opts = node.get('ws-opts', {}) or node.get('ws_opts', {})
    headers = ws_opts.get('headers', {}) or {}
    reality_opts = node.get('reality-opts', {}) or {}
    key = (
        node.get('type', ''),
        node.get('uuid', ''),
        node.get('cipher', ''),
        node.get('network', ''),
        node.get('port', ''),
        node.get('alterId', ''),
        ws_opts.get('path', ''),
        headers.get('Host', ''),
        node.get('servername', ''),
        node.get('flow', ''),
        node.get('password', ''),
        node.get('skip-cert-verify', ''),
        reality_opts.get('public-key', ''),
        node.get('sni', ''),
    )
    return key

def main():
    logger.info("脚本开始运行...")
    
    if not os.path.exists(LINKS_FILE):
        logger.error(f"链接文件 {LINKS_FILE} 不存在。请创建一个包含链接的 link.txt 文件。")
        exit(1)

    try:
        with open(LINKS_FILE, 'r', encoding='utf-8') as f:
            links_to_test = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"读取 {LINKS_FILE} 失败: {e}")
        exit(1)

    logger.info(f"第一阶段：预测试 {len(links_to_test)} 个链接，优先尝试 HTTPS...")
    working_links = pre_test_links(links_to_test)
    logger.info(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    if not working_links:
        logger.warning("未发现可用链接，脚本结束。")
        return
    
    logger.info("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
    unique_nodes = []
    node_keys = set()
    for node in all_nodes:
        node_key = get_node_key(node)
        if node_key not in node_keys:
            node_keys.add(node_key)
            unique_nodes.append(node)
    
    # 重新为节点命名
    final_nodes = []
    final_names_count = {}
    for node in unique_nodes:
        name = node.get('name', f"{node.get('server', 'unknown')}_{node.get('port', 'unknown')}")
        if name in final_names_count:
            final_names_count[name] += 1
            node['name'] = f"{name}_{final_names_count[name]:02d}"
        else:
            final_names_count[name] = 1
            node['name'] = name
        final_nodes.append(node)

    # 保存结果
    logger.info("所有链接处理完毕，开始保存文件。")
    try:
        final_data = {'proxies': final_nodes}
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(final_data, f, allow_unicode=True)
        logger.info(f"节点已保存到 {OUTPUT_YAML}，共 {len(final_nodes)} 个节点。")
    except Exception as e:
        logger.error(f"保存 {OUTPUT_YAML} 失败: {e}")
        exit(1)
    
    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Node Count'])
            for item in node_counts:
                writer.writerow([item['url'], item['count']])
        logger.info(f"统计信息已保存到 {OUTPUT_CSV}")
    except Exception as e:
        logger.error(f"保存 {OUTPUT_CSV} 失败: {e}")
        exit(1)
    
    logger.info("脚本运行结束。")

if __name__ == "__main__":
    main()
