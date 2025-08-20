import os
import requests
import yaml
import csv
import re
import random
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from bs4 import BeautifulSoup
import logging
from tenacity import retry, stop_after_attempt, wait_fixed
from urllib.parse import unquote

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
    'config.yaml', 'config.yml', 'clash.yaml', 'clash.yml',
    'clash_proxies.yaml', 'clash_nodes.yaml', 'clash_nodes.yml',
    'all.yaml', 'all.yml', 'mihomo.yaml', 'mihomo.yml',
    'openclash.yaml', 'clash-socket.yaml', 'v2ray.yaml', 'v2ray.yml',
    'proxies.yaml', 'proxies.yml', 'nodes.yaml', 'nodes.yml',
    'new.yaml', 'new.yml', 'sf.yaml', 'sf.yml',
    'sub.yaml', 'sub.yml', 'subscribe.yaml', 'subscribe.yml',
    'subscription.yaml', 'subscription.yml',
    '_clash.yaml', '_clash.yml', 'sub_clash.yaml', 'sub_clash.yml'
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
        response = requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            return link, "https", "html" if 'text/html' in content_type else "yaml"
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTPS 失败，尝试 HTTP
    try:
        response = requests.head(f"http://{link}", headers=get_headers(), timeout=5)
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            return link, "http", "html" if 'text/html' in content_type else "yaml"
    except requests.exceptions.RequestException:
        pass
        
    return None, None, None

def pre_test_links(links):
    """并发预测试所有链接，返回可用链接、协议和内容类型的字典"""
    working_links = {}
    max_workers = min(64, os.cpu_count() * 4) if os.cpu_count() else 32
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(test_connection_and_get_protocol, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result_link, result_protocol, content_type = future.result()
            if result_link:
                working_links[result_link] = {'protocol': result_protocol, 'type': content_type}
    return working_links

def convert_to_clash_node(node_info):
    """将不同协议的节点信息转换为Clash格式"""
    node_type = node_info.get('type', '').lower()
    
    # Vmess
    if node_type == 'vmess':
        return {
            'name': node_info.get('ps', 'vmess_node'),
            'type': 'vmess',
            'server': node_info.get('add'),
            'port': int(node_info.get('port')),
            'uuid': node_info.get('id'),
            'alterId': int(node_info.get('aid')),
            'cipher': node_info.get('scy', 'auto'),
            'network': node_info.get('net'),
            'tls': node_info.get('tls') == 'tls',
            'ws-opts': {
                'path': node_info.get('path', ''),
                'headers': {'Host': node_info.get('host', '')}
            }
        }
    
    # Shadowsocks
    elif node_type == 'ss':
        return {
            'name': node_info.get('ps', 'ss_node'),
            'type': 'ss',
            'server': node_info.get('server'),
            'port': int(node_info.get('port')),
            'password': node_info.get('password'),
            'cipher': node_info.get('method')
        }
    
    # VLESS
    elif node_type == 'vless':
        return {
            'name': node_info.get('ps', 'vless_node'),
            'type': 'vless',
            'server': node_info.get('server'),
            'port': int(node_info.get('port')),
            'uuid': node_info.get('uuid'),
            'network': node_info.get('net'),
            'tls': node_info.get('security') == 'tls',
            'flow': node_info.get('flow', ''),
            'reality-opts': {
                'public-key': node_info.get('pbk', '')
            }
        }
    
    # Trojan
    elif node_type == 'trojan':
        return {
            'name': node_info.get('ps', 'trojan_node'),
            'type': 'trojan',
            'server': node_info.get('server'),
            'port': int(node_info.get('port')),
            'password': node_info.get('password'),
            'sni': node_info.get('sni', node_info.get('server'))
        }

    return None

def parse_base64_nodes(content):
    """解析 Base64 编码的节点列表"""
    try:
        # 尝试 Base64 解码，并忽略非 Base64 字符
        decoded_content = base64.b64decode(content.strip() + '=' * (-len(content.strip()) % 4)).decode('utf-8')
        return parse_plaintext_nodes(decoded_content)
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        logger.warning(f"Base64 解码失败: {e}")
        return None

def parse_plaintext_nodes(content):
    """解析明文节点链接，如 vmess://, ss://"""
    nodes = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Vmess
        if line.startswith('vmess://'):
            try:
                vmess_json = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                vmess_json['type'] = 'vmess'
                nodes.append(convert_to_clash_node(vmess_json))
            except Exception as e:
                logger.warning(f"Vmess 链接解析失败: {line}, 错误: {e}")
                
        # Shadowsocks
        elif line.startswith('ss://'):
            try:
                # 分割 Base64 部分和名称部分
                parts = line[5:].split('#', 1)
                base64_part = parts[0]
                name_part = unquote(parts[1]) if len(parts) > 1 else 'ss_node'
                
                # 自动添加 Base64 填充
                padded_base64 = base64_part + '=' * (-len(base64_part) % 4)
                
                decoded_ss = base64.b64decode(padded_base64).decode('utf-8')
                
                method_and_password, server_and_port = decoded_ss.split('@', 1)
                server, port = server_and_port.rsplit(':', 1)
                
                if ':' in method_and_password:
                    method, password = method_and_password.split(':', 1)
                else:
                    method = method_and_password
                    password = ''
                
                ss_node = {
                    'type': 'ss',
                    'method': method,
                    'password': password,
                    'server': server,
                    'port': int(port),
                    'ps': name_part
                }
                nodes.append(convert_to_clash_node(ss_node))
            except Exception as e:
                logger.warning(f"Shadowsocks 链接解析失败: {line}, 错误: {e}")
                
        # VLESS
        elif line.startswith('vless://'):
            try:
                uuid_and_server = line[8:].split('#', 1)[0]
                uuid, server_info = uuid_and_server.split('@', 1)
                server_part, params_part = server_info.split('?', 1)
                server, port = server_part.rsplit(':', 1)
                params = dict(p.split('=', 1) for p in params_part.split('&'))
                vless_node = {
                    'type': 'vless',
                    'uuid': uuid,
                    'server': server,
                    'port': int(port),
                    'ps': unquote(line.split('#', 1)[1]) if '#' in line else 'vless_node',
                    'net': params.get('type'),
                    'security': params.get('security'),
                    'flow': params.get('flow'),
                    'pbk': params.get('pbk')
                }
                nodes.append(convert_to_clash_node(vless_node))
            except Exception as e:
                logger.warning(f"VLESS 链接解析失败: {line}, 错误: {e}")
        
        # Trojan
        elif line.startswith('trojan://'):
            try:
                password_and_server = line[9:].split('#', 1)[0]
                password, server_info = password_and_server.split('@', 1)
                server, port = server_info.rsplit(':', 1)
                trojan_node = {
                    'type': 'trojan',
                    'password': password,
                    'server': server,
                    'port': int(port),
                    'ps': unquote(line.split('#', 1)[1]) if '#' in line else 'trojan_node'
                }
                nodes.append(convert_to_clash_node(trojan_node))
            except Exception as e:
                logger.warning(f"Trojan 链接解析失败: {line}, 错误: {e}")

    return [node for node in nodes if node is not None]

def is_likely_subscription_url(url):
    """判断一个URL是否可能是订阅链接"""
    keywords = ['clash', 'v2ray', 'mihomo', 'config', 'sub', 'subscribe', 'api/v1/client/subscribe', 'yaml', 'yml', 'txt']
    return any(keyword in url.lower() for keyword in keywords)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def fetch_content(url):
    """通用内容抓取函数，返回原始文本和URL"""
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text, url
        else:
            logger.warning(f"下载失败: {url}, 状态码: {response.status_code}")
            return None, None
    except requests.exceptions.RequestException as e:
        logger.warning(f"下载失败: {url}, 错误: {e}")
        return None, None

def process_subscription_links(links, depth=0):
    """递归处理包含订阅链接的列表"""
    if depth > 3: # 防止无限递归
        logger.warning("达到最大递归深度，停止处理。")
        return []

    all_nodes = []
    processed_links = set()
    
    with ThreadPoolExecutor(max_workers=min(32, os.cpu_count() * 2)) as executor:
        # 过滤掉不可能是订阅链接的URL
        filtered_links = [link for link in links if is_likely_subscription_url(link)]
        
        future_to_url = {executor.submit(fetch_and_parse_content, link, depth + 1): link for link in filtered_links}
        for future in tqdm(as_completed(future_to_url), total=len(filtered_links), desc=f"获取子订阅内容 (深度 {depth})"):
            nodes, successful_url = future.result()
            if nodes and successful_url and successful_url not in processed_links:
                all_nodes.extend(nodes)
                processed_links.add(successful_url)
    return all_nodes

def fetch_and_parse_content(url, depth=0):
    """
    通用内容抓取和解析函数。
    依次尝试解析为 Base64, 明文, 或 YAML。
    """
    content, successful_url = fetch_content(url)
    if not content:
        return [], None
    
    if len(content) == 0:
        logger.warning(f"文件为空 (0 字节): {url}")
        return [], None

    # 尝试解析为 URL 列表
    lines = content.splitlines()
    if all(line.strip().startswith(('http://', 'https://')) for line in lines if line.strip()):
        logger.info(f"检测到订阅链接列表: {url}")
        nodes = process_subscription_links(lines, depth)
        return nodes, successful_url

    # 尝试解析为 YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data:
            return data.get('proxies', []), successful_url
    except yaml.YAMLError:
        pass

    # 尝试解析为 Base64 编码的节点
    base64_nodes = parse_base64_nodes(content)
    if base64_nodes:
        return base64_nodes, successful_url

    # 尝试解析为明文节点
    plaintext_nodes = parse_plaintext_nodes(content)
    if plaintext_nodes:
        return plaintext_nodes, successful_url
        
    logger.warning(f"无法解析内容: {url}")
    return [], None

def parse_and_fetch_from_html(url):
    """
    解析 HTML 页面，批量收集所有可能的订阅文件链接。
    """
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            
            sub_urls = set()
            
            # 策略1: 收集所有以 .yaml, .yml, .txt 结尾的链接
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.lower().endswith(('.yaml', '.yml', '.txt')):
                    full_url = requests.compat.urljoin(url, href)
                    sub_urls.add(full_url)
            
            # 策略2: 寻找包含特定关键字的链接
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and is_likely_subscription_url(href):
                    full_url = requests.compat.urljoin(url, href)
                    sub_urls.add(full_url)
            
            # 策略3: 从 <script> 标签中解析
            for script in soup.find_all('script'):
                script_content = script.string
                if script_content:
                    matches = re.findall(r'\"url\"\s*:\s*\"(.*?)\"', script_content, re.DOTALL | re.IGNORECASE)
                    for match_url in matches:
                        if is_likely_subscription_url(match_url):
                            full_url = requests.compat.urljoin(url, match_url) if not match_url.startswith(('http://', 'https://')) else match_url
                            sub_urls.add(full_url)
            
            return list(sub_urls), url
        return [], None
    except requests.exceptions.RequestException as e:
        logger.warning(f"HTML 解析失败: {url}, 错误: {e}")
        return [], None

def process_links(working_links):
    """第二阶段：处理可用的链接，分批处理"""
    all_nodes = []
    node_counts = []
    processed_links = set()
    
    tasks = []
    for link, info in working_links.items():
        full_url = f"{info['protocol']}://{link}"
        if info['type'] == 'html':
            tasks.append({'type': 'html_parse', 'url': full_url})
        else:
            for config_name in CONFIG_NAMES:
                full_sub_url = f"{full_url}/{config_name}"
                if full_sub_url not in processed_links:
                    tasks.append({'type': 'fetch_and_parse_content', 'url': full_sub_url})
    
    # 将处理 HTML 的任务放在最前面
    tasks.sort(key=lambda x: x['type'] != 'html_parse')
    
    max_workers = min(32, os.cpu_count() * 2) if os.cpu_count() else 16
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {}
        for task in tasks:
            if task['type'] == 'html_parse':
                future = executor.submit(parse_and_fetch_from_html, task['url'])
                future_to_task[future] = task
            else:
                future = executor.submit(fetch_and_parse_content, task['url'])
                future_to_task[future] = task
        
        for future in tqdm(as_completed(future_to_task), total=len(future_to_task), desc="获取节点内容"):
            task = future_to_task[future]
            task_url = task['url']
            
            if task_url in processed_links:
                continue
                
            result = future.result()
            
            if isinstance(result, tuple) and len(result) == 2:
                # 处理 HTML 解析结果，将子链接添加到任务队列
                if task['type'] == 'html_parse':
                    sub_urls, successful_url = result
                    if sub_urls:
                        for sub_url in sub_urls:
                            if sub_url not in processed_links:
                                new_future = executor.submit(fetch_and_parse_content, sub_url)
                                future_to_task[new_future] = {'type': 'fetch_and_parse_content', 'url': sub_url}
                                processed_links.add(sub_url)
                else:
                    # 处理直接获取内容的结果
                    nodes, successful_url = result
                    if nodes and successful_url and successful_url not in processed_links:
                        # 为节点添加地理位置信息
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
                logger.error(f"处理任务 {task_url} 时出错: 结果格式不正确")
                
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
        name_prefix = node.get('name', f"{node.get('server', 'unknown')}_{node.get('port', 'unknown')}")
        name = name_prefix
        if name_prefix in final_names_count:
            final_names_count[name_prefix] += 1
            name = f"{name_prefix}_{final_names_count[name_prefix]:02d}"
        else:
            final_names_count[name_prefix] = 1
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
