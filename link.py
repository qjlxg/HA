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
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)
except Exception as e:
    print(f"初始化地理位置数据库时发生错误: {e}")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def test_connection_and_get_protocol(link):
    """
    测试一个链接的连通性，并返回成功的协议。
    优先测试 HTTPS。
    """
    link = link.replace('http://', '').replace('https://', '')
    
    # 优先尝试 HTTPS
    try:
        response = requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        if response.status_code == 200:
            return link, "https"
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTPS 失败，尝试 HTTP
    try:
        response = requests.head(f"http://{link}", headers=get_headers(), timeout=5)
        if response.status_code == 200:
            return link, "http"
    except requests.exceptions.RequestException:
        pass
        
    return None, None

def pre_test_links(links):
    """并发预测试所有链接，返回可用链接及其协议的字典"""
    working_links = {}
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_link = {executor.submit(test_connection_and_get_protocol, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result_link, result_protocol = future.result()
            if result_link:
                working_links[result_link] = result_protocol
    return working_links

def fetch_yaml_content(url):
    """尝试直接下载 YAML 文件"""
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and 'text/html' not in response.headers.get('content-type', '').lower():
            # 简单验证内容是否为 YAML
            try:
                yaml.safe_load(response.text)
                return response.text, url
            except yaml.YAMLError:
                return None, None
    except requests.exceptions.RequestException as e:
        return None, None
    return None, None

def parse_and_fetch_from_html(url):
    """解析 HTML 页面，寻找 YAML 文件链接并尝试下载"""
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 策略1: 寻找所有以 .yaml 或 .yml 结尾的链接
            yaml_urls = [requests.compat.urljoin(url, link.get('href'))
                         for link in soup.find_all('a')
                         if link.get('href') and link.get('href').lower().endswith(('.yaml', '.yml'))]
            for yaml_url in yaml_urls:
                content, final_url = fetch_yaml_content(yaml_url)
                if content:
                    return content, final_url
            
            # 策略2: 寻找包含特定关键字的链接，比如“clash”或“v2ray”
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and re.search(r'(clash|v2ray|mihomo|config)', href, re.IGNORECASE):
                    full_url = requests.compat.urljoin(url, href)
                    # 再次验证是否为YAML
                    content, final_url = fetch_yaml_content(full_url)
                    if content:
                        return content, final_url
            
            # 策略3: 从 <script> 标签中解析
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    match = re.search(r'\"url\"\s*:\s*\"(.*?\.ya?ml)\"', script_content, re.DOTALL | re.IGNORECASE)
                    if match:
                        yaml_url = match.group(1)
                        if not yaml_url.startswith(('http://', 'https://')):
                            yaml_url = requests.compat.urljoin(url, yaml_url)
                        
                        content, final_url = fetch_yaml_content(yaml_url)
                        if content:
                            return content, final_url
    except requests.exceptions.RequestException as e:
        return None, None
        
    return None, None

def process_links(working_links):
    """第二阶段：处理可用的链接"""
    all_nodes = []
    node_counts = []
    
    urls_to_process = []
    for link, protocol in working_links.items():
        base_url = f"{protocol}://{link}"
        urls_to_process.append({'type': 'direct', 'url': base_url, 'config_names': CONFIG_NAMES})
        urls_to_process.append({'type': 'html_parse', 'url': base_url})
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_task = {}
        for task in urls_to_process:
            if task['type'] == 'direct':
                for config_name in task['config_names']:
                    full_url = f"{task['url']}/{config_name}"
                    future = executor.submit(fetch_yaml_content, full_url)
                    future_to_task[future] = task
            elif task['type'] == 'html_parse':
                future = executor.submit(parse_and_fetch_from_html, task['url'])
                future_to_task[future] = task
        
        total_tasks = len(future_to_task)
        processed_links = set()
        
        for future in tqdm(as_completed(future_to_task), total=total_tasks, desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            
            # 避免重复处理
            if successful_url and successful_url in processed_links:
                continue
            
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        
                        # 解析国家/地区信息
                        for node in nodes:
                            ip = node.get('server', '')
                            # 简单的IP地址验证
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                country_code, country_name = geolocator.get_location(ip)
                                if country_name:
                                    node['name'] = country_name
                        
                        all_nodes.extend(nodes)
                        node_counts.append({'url': successful_url, 'count': len(nodes)})
                        processed_links.add(successful_url)
                        print(f"成功从 {successful_url} 获取 {len(nodes)} 个节点。")
                    else:
                        print(f"警告: {successful_url} 的 YAML 内容格式不正确。")
                except yaml.YAMLError:
                    print(f"错误: 无法解析 {successful_url} 的 YAML 内容。")
    
    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    if not os.path.exists(LINKS_FILE):
        print(f"错误: 链接文件 {LINKS_FILE} 不存在。请创建一个包含链接的 link.txt 文件。")
        exit(1)

    with open(LINKS_FILE, 'r') as f:
        links_to_test = [line.strip() for line in f if line.strip()]

    print("第一阶段：预测试所有链接，优先尝试 HTTPS...")
    working_links = pre_test_links(links_to_test)
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    if not working_links:
        print("未发现可用链接，脚本结束。")
        return
    
    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
    unique_nodes = []
    names_count = {}
    for node in all_nodes:
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 重新为节点命名
    final_nodes = []
    final_names_count = {}
    for node in unique_nodes:
        name = node.get('name')
        if name:
            if name in final_names_count:
                final_names_count[name] += 1
                node['name'] = f"{name}_{final_names_count[name]:02d}"
            else:
                final_names_count[name] = 1
        final_nodes.append(node)

    # 保存结果
    print("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': final_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    print(f"节点已保存到 {OUTPUT_YAML}，共 {len(final_nodes)} 个节点。")
    
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        for item in node_counts:
            writer.writerow([item['url'], item['count']])
    print(f"统计信息已保存到 {OUTPUT_CSV}")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
