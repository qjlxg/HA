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
CONFIG_NAMES = ['config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml']

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
        requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        return link, "https"
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTPS 失败，尝试 HTTP
    try:
        requests.head(f"http://{link}", headers=get_headers(), timeout=5)
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

def parse_and_fetch_yaml(url):
    """
    通用解析和获取 YAML 文件内容
    - 尝试直接下载
    - 尝试解析 HTML 页面，寻找 .yaml 链接
    """
    headers = get_headers()
    
    # 尝试直接下载 YAML 文件
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200 and 'text/html' not in response.headers.get('content-type', '').lower():
            return response.text, url
    except requests.exceptions.RequestException:
        pass
    
    # 如果不是直接的 YAML 文件，尝试解析 HTML 页面
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 策略1: 寻找所有以 .yaml 或 .yml 结尾的链接
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.lower().endswith(('.yaml', '.yml')):
                    full_url = requests.compat.urljoin(url, href)
                    yaml_response = requests.get(full_url, headers=headers, timeout=5)
                    if yaml_response.status_code == 200:
                        return yaml_response.text, full_url

            # 策略2: 从 <script> 标签中解析
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    # 使用正则表达式寻找包含 URL 的 JSON-like 数组
                    match = re.search(r'\[\s*\{.*?\"url\"\s*:\s*\"(.*?\.ya?ml)\".*?\}\s*\]', script_content, re.DOTALL | re.IGNORECASE)
                    if match:
                        yaml_url = match.group(1)
                        if not yaml_url.startswith(('http://', 'https://')):
                            yaml_url = requests.compat.urljoin(url, yaml_url)
                        
                        yaml_response = requests.get(yaml_url, headers=headers, timeout=5)
                        if yaml_response.status_code == 200:
                            return yaml_response.text, yaml_url
    except requests.exceptions.RequestException:
        pass
        
    return None, None

def process_links(working_links):
    """第二阶段：处理可用的链接"""
    all_nodes = []
    node_counts = []
    
    # 整理所有待处理的URL，包括直接路径和根目录
    urls_to_process = []
    for link, protocol in working_links.items():
        # 针对每个可用链接，尝试默认文件名
        for config_name in CONFIG_NAMES:
            urls_to_process.append(f"{protocol}://{link}/{config_name}")
        # 也尝试直接访问根目录以触发HTML解析
        urls_to_process.append(f"{protocol}://{link}/")
    
    # 去重
    urls_to_process = list(set(urls_to_process))
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(parse_and_fetch_yaml, url): url for url in urls_to_process}
        
        total_tasks = len(urls_to_process)
        for future in tqdm(as_completed(future_to_url), total=total_tasks, desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        
                        for node in nodes:
                            ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', node.get('server', ''))
                            if ip:
                                ip = ip.group(0)
                                country_code, country_name = geolocator.get_location(ip)
                                if country_name:
                                    node['name'] = country_name
                        
                        all_nodes.extend(nodes)
                        node_counts.append({'url': successful_url, 'count': len(nodes)})
                    else:
                        pass
                except yaml.YAMLError:
                    pass
    
    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    with open(LINKS_FILE, 'r') as f:
        links_to_test = [line.strip() for line in f if line.strip()]

    print("第一阶段：预测试所有链接，优先尝试 HTTPS...")
    working_links = pre_test_links(links_to_test)
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
    unique_nodes = []
    names_count = {}
    for node in all_nodes:
        name = node.get('name')
        if name:
            if name in names_count:
                names_count[name] += 1
                node['name'] = f"{name}_{names_count[name]:02d}"
            else:
                names_count[name] = 1
        
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 保存结果
    print("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': unique_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    print(f"节点已保存到 {OUTPUT_YAML}")
    
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        for item in node_counts:
            writer.writerow([item['url'], item['count']])
    print(f"统计信息已保存到 {OUTPUT_CSV}")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
