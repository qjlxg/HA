import requests
import yaml
import base64
import io
import os
import csv
import json
import re
import random
import concurrent.futures
import socket
import asyncio
from urllib.parse import urlparse, unquote, urljoin, parse_qs
from collections import OrderedDict, defaultdict
from html.parser import HTMLParser
from tqdm import tqdm
from ip_geolocation import GeoLite2Country
import requests_cache
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from playwright.sync_api import sync_playwright
import warnings

# 全局变量
LOG_FILE = "link_processing.log"

# 多样化的User-Agent列表，涵盖多种设备和浏览器
USER_AGENTS = [
    # Windows 10 Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    # Windows 10 Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # macOS Big Sur Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.15 Safari/605.1.15',
    # iPad Pro Safari
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.77 Mobile/15E148 Safari/604.1',
    # iPhone Chrome
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1',
    # Android Chrome
    'Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    # HarmonyOS Chrome (模拟)
    'Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36',
    # Linux Firefox
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
]

# 有效加密方式
VALID_SS_CIPHERS = {
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
}
VALID_VMESS_CIPHERS = {'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'}
VALID_VLESS_NETWORKS = {'tcp', 'ws', 'grpc'}

# 忽略 XMLParsedAsHTMLWarning 警告
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class DirectoryLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.in_pre = True
        if self.in_pre and tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self.links.append(value)

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.in_pre = False

def validate_host(host):
    """验证 Host 字段（域名或 IP）"""
    if not host or not isinstance(host, str):
        return False
    host = unquote(host).strip()
    if not host:
        return False
    try:
        # 使用 getaddrinfo 验证 host 是否有效
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False

def validate_server_port(server, port):
    """验证服务器地址和端口"""
    if not server or not isinstance(port, int) or port < 1 or port > 65535:
        return False
    if not validate_host(server):
        return False
    return True

def parse_vmess(vmess_url):
    try:
        if not vmess_url.startswith('vmess://'): return None
        base64_content = vmess_url.replace('vmess://', '', 1)
        
        # 自动补全 Base64 填充
        padding = len(base64_content) % 4
        if padding > 0:
            base64_content += '=' * (4 - padding)
            
        decoded_json = base64.b64decode(base64_content.encode('utf-8')).decode('utf-8')
        config = json.loads(decoded_json)
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        if not all(field in config for field in required_fields): return None
        
        # 验证加密方式
        cipher = config.get('scy', 'auto')
        if cipher not in VALID_VMESS_CIPHERS:
            return None

        # 验证服务器和端口
        if not validate_server_port(config.get('add'), int(config.get('port'))):
            return None

        node = {
            'name': config.get('ps', 'Unnamed VMess'), 'type': 'vmess', 'server': config.get('add'),
            'port': int(config.get('port')), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)),
            'cipher': cipher, 'network': config.get('net', 'tcp')
        }
        
        # 严格验证 ws-opts.headers.Host 字段
        if node.get('network') == 'ws':
            host = config.get('host') or config.get('add')
            if not validate_host(host):
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"跳过 VMess 节点（无效或缺失 ws-opts.headers[Host]）: {vmess_url[:50]}...\n")
                return None
            
            node['ws-opts'] = {
                'path': config.get('path', '/'),
                'headers': {'Host': host}
            }
        
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 VMess 节点出错: {e}\n")
        return None

def parse_ss(ss_url):
    try:
        if not ss_url.startswith('ss://'): return None
        base64_content = ss_url.replace('ss://', '', 1)
        
        # 自动补全 Base64 填充
        padding = len(base64_content) % 4
        if padding > 0:
            base64_content += '=' * (4 - padding)
            
        if '@' in base64_content:
            part1, part2 = base64_content.split('@', 1)
            decoded_part1 = base64.b64decode(part1.encode('utf-8')).decode('utf-8')
            method, password = decoded_part1.split(':', 1)
        else:
            decoded_content = base64.b64decode(base64_content.encode('utf-8')).decode('utf-8')
            if '@' not in decoded_content: return None
            decoded_part1, part2 = decoded_content.split('@', 1)
            method, password = decoded_part1.split(':', 1)
        server_info, name = part2.split('#', 1) if '#' in part2 else (part2, None)
        server, port = server_info.split(':', 1)

        # 验证加密方式
        if method not in VALID_SS_CIPHERS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（不支持的加密方式: {method}）: {ss_url[:50]}...\n")
            return None
        
        # 验证服务器和端口
        if not validate_server_port(server, int(port)):
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 Shadowsocks 节点（无效服务器/端口）: {ss_url[:50]}...\n")
            return None

        return {
            'name': unquote(name) if name else 'Unnamed SS', 'type': 'ss', 'server': server,
            'port': int(port), 'cipher': method, 'password': password
        }
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Shadowsocks 节点出错: {e}\n")
        return None

def parse_vless(vless_url):
    try:
        if not vless_url.startswith('vless://'): return None
        parsed_url = urlparse(vless_url)
        uuid, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed VLESS'
        
        if not all([uuid, server, port]): return None
        
        # 验证服务器和端口
        if not validate_server_port(server, port):
            return None
            
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        
        # 验证网络类型
        network = params.get('type', 'tcp')
        if network not in VALID_VLESS_NETWORKS:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过 VLESS 节点（不支持的网络类型: {network}）: {vless_url[:50]}...\n")
            return None
        
        node = {
            'name': name, 'type': 'vless', 'server': server, 'port': port, 'uuid': uuid,
            'network': network, 'tls': params.get('security') == 'tls', 'flow': params.get('flow')
        }
        
        # 严格验证 ws-opts.headers.Host 字段
        if network == 'ws':
            host_header = params.get('host', '')
            if not validate_host(host_header):
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"跳过 VLESS 节点（无效或缺失 ws-opts.headers[Host]）: {vless_url[:50]}...\n")
                return None
            node['ws-opts'] = {
                'path': params.get('path'),
                'headers': {'Host': host_header}
            }
        
        return node
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 VLESS 节点出错: {e}\n")
        return None

def parse_trojan(trojan_url):
    try:
        if not trojan_url.startswith('trojan://'): return None
        parsed_url = urlparse(trojan_url)
        password, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed Trojan'
        if not all([password, server, port]): return None

        # 验证服务器和端口
        if not validate_server_port(server, port):
            return None

        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        return {
            'name': name, 'type': 'trojan', 'server': server, 'port': port, 'password': password,
            'sni': params.get('sni'), 'skip-cert-verify': False
        }
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Trojan 节点出错: {e}\n")
        return None

def parse_ssr(ssr_url):
    try:
        if not ssr_url.startswith('ssr://'): return None
        base64_content = ssr_url.replace('ssr://', '', 1)
        
        # 自动补全 Base64 填充
        padding = len(base64_content) % 4
        if padding > 0:
            base64_content += '=' * (4 - padding)
            
        decoded = base64.urlsafe_b64decode(base64_content).decode('utf-8')
        parts = decoded.split(':')
        if len(parts) < 6: return None
        server, port, protocol, method, obfs, password_base64 = parts[:6]
        params = dict(re.findall(r'([^=&]+)=([^=&]*)', decoded.split('#', 1)[1])) if '#' in decoded else {}
        
        # 验证服务器和端口
        if not validate_server_port(server, int(port)):
            return None

        # 自动补全 Base64 填充
        padding = len(password_base64) % 4
        if padding > 0:
            password_base64 += '=' * (4 - padding)
        
        return {
            'name': unquote(params.get('remarks', 'Unnamed SSR')), 'type': 'ssr', 'server': server,
            'port': int(port), 'password': base64.urlsafe_b64decode(password_base64).decode('utf-8'),
            'cipher': method, 'protocol': protocol, 'obfs': obfs,
            'protocol-param': params.get('protoparam'), 'obfs-param': params.get('obfsparam')
        }
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 SSR 节点出错: {e}\n")
        return None

def parse_hy2(hy2_url):
    try:
        if not hy2_url.startswith('hy2://'): return None
        parsed_url = urlparse(hy2_url)
        password, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else 'Unnamed HY2'
        if not all([password, server, port]): return None
        
        # 验证服务器和端口
        if not validate_server_port(server, port):
            return None

        params = dict(re.findall(r'([^=&]+)=([^=&]*)', parsed_url.query))
        return {
            'name': name, 'type': 'hysteria2', 'server': server, 'port': port, 'password': password,
            'up': params.get('up'), 'down': params.get('down'), 'obfs': params.get('obfs'),
            'obfs-password': params.get('obfs-password'), 'fast-open': True
        }
    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"解析 Hysteria2 节点出错: {e}\n")
        return None

def parse_node(link):
    if link.startswith('vmess://'): return parse_vmess(link)
    if link.startswith('ss://'): return parse_ss(link)
    if link.startswith('vless://'): return parse_vless(link)
    if link.startswith('trojan://'): return parse_trojan(link)
    if link.startswith('ssr://'): return parse_ssr(link)
    if link.startswith('hy2://'): return parse_hy2(link)
    return None

def extract_links_from_html(html_content):
    links = []
    # 从 <meta> 标签中提取链接
    # 使用 lxml 解析器以更好地处理潜在的 XML 文档
    soup = BeautifulSoup(html_content, 'lxml')
    meta_description = soup.find('meta', attrs={'name': 'description'})
    og_description = soup.find('meta', attrs={'property': 'og:description'})
    
    if meta_description and meta_description.get('content'):
        links.append(meta_description['content'])
    if og_description and og_description.get('content'):
        links.append(og_description['content'])
        
    # 从 <p> 或 <textarea> 标签中提取链接
    matches = re.findall(r'<p class="config".*?>(.*?)</p>', html_content, re.DOTALL)
    for match in matches:
        cleaned_link = re.sub(r'<[^>]+>', '', match).strip()
        if cleaned_link:
            links.append(cleaned_link)
    
    matches = re.findall(r'<textarea[^>]*>(.*?)</textarea>', html_content, re.DOTALL)
    for match in matches:
        links.extend(match.strip().splitlines())
        
    return links

def extract_links_from_script(html_content):
    links = []
    match = re.search(r'const\s+fileData\s*=\s*(\[[^;]+\]);', html_content, re.DOTALL)
    if match:
        json_str = match.group(1)
        try:
            data = json.loads(json_str)
            for item in data:
                if 'url' in item:
                    links.append(item['url'])
        except json.JSONDecodeError:
            matches = re.findall(r"url\s*:\s*'(.*?)'", json_str)
            for url in matches:
                links.append(url)
    return links

def get_nodes_with_playwright(url):
    """使用 Playwright 渲染页面并提取节点"""
    nodes = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url)
            # 等待所有网络请求都完成，以确保动态内容加载完毕
            page.wait_for_load_state("networkidle")
            content = page.content()
            browser.close()

            # 使用静态解析函数处理渲染后的内容
            html_links = extract_links_from_html(content)
            for link in html_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)

            script_links = extract_links_from_script(content)
            for link in script_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)

            # 再次尝试从纯文本或Base64编码中提取
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'): continue
                
                parsed_node = parse_node(line)
                if parsed_node:
                    nodes.append(parsed_node)
                    continue

                try:
                    decoded_line = base64.b64decode(line.strip().encode('utf-8')).decode('utf-8')
                    parsed_node = parse_node(decoded_line)
                    if parsed_node: nodes.append(parsed_node)
                except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                    pass

    except Exception as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"使用 Playwright 处理 {url} 时发生错误: {e}\n")
    return nodes

def get_nodes_from_url(url):
    schemes = ['https://', 'http://']
    for scheme in schemes:
        full_url = url
        if not full_url.startswith(('http://', 'https://')):
            full_url = f"{scheme}{url}"
        
        try:
            session = requests_cache.CachedSession(
                'link_cache',
                backend='sqlite',
                expire_after=3600 # 缓存1小时
            )
            headers = {
                'User-Agent': random.choice(USER_AGENTS)
            }
            response = session.get(full_url, headers=headers, timeout=5)
            response.raise_for_status()
            content = response.text

            nodes = []
            
            # 1. 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if isinstance(config, dict) and 'proxies' in config:
                    return config['proxies']
            except yaml.YAMLError: pass

            # 2. 尝试解析为纯文本或Base64编码的行
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'): continue
                
                parsed_node = parse_node(line)
                if parsed_node:
                    nodes.append(parsed_node)
                    continue

                try:
                    decoded_line = base64.b64decode(line.strip().encode('utf-8')).decode('utf-8')
                    parsed_node = parse_node(decoded_line)
                    if parsed_node: nodes.append(parsed_node)
                except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                    pass
            
            if nodes: return nodes
            
            # 3. 尝试从HTML中提取链接，包括 meta 标签
            html_links = extract_links_from_html(content)
            for link in html_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)
            
            if nodes: return nodes
            
            # 4. 尝试从JavaScript脚本中提取链接
            script_links = extract_links_from_script(content)
            for link in script_links:
                parsed_node = parse_node(link)
                if parsed_node: nodes.append(parsed_node)
            
            if nodes: return nodes

            # 5. 如果以上都失败，尝试解析为HTML目录页面
            if '<title>Index of /</title>' in content or '<h1>Index of' in content:
                parser = DirectoryLinkParser()
                parser.feed(content)
                
                potential_links = [
                    link for link in parser.links 
                    if link.endswith(('.yaml', '.txt', '.json')) or 'clash' in link.lower() or 'v2ray' in link.lower() or 'subscription' in link.lower()
                ]

                all_sub_nodes = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                    future_to_url = {executor.submit(get_nodes_from_url, urljoin(full_url, link)): link for link in potential_links}
                    for future in concurrent.futures.as_completed(future_to_url):
                        try:
                            sub_nodes = future.result()
                            if sub_nodes:
                                all_sub_nodes.extend(sub_nodes)
                        except Exception:
                            pass
                
                if all_sub_nodes: return all_sub_nodes
            
            # 新增：如果所有静态解析都失败，则使用 Playwright
            if not nodes:
                print(f"使用 Playwright 渲染 {full_url}...")
                nodes = get_nodes_with_playwright(full_url)
                if nodes:
                    print(f"Playwright 成功从 {full_url} 找到 {len(nodes)} 个节点。")
                    return nodes

            return []

        except requests.exceptions.RequestException as e:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"处理 {full_url} 时发生网络错误: {e}\n")
            continue
    
    return []

def get_links_from_local_file(filename="link.txt"):
    links = []
    if os.path.exists(filename):
        print(f"正在从本地文件 {filename} 读取链接...")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        links.append(line)
            print(f"从 {filename} 读取了 {len(links)} 个链接。")
        except IOError as e:
            print(f"无法读取文件 {filename}: {e}")
    else:
        print(f"文件 {filename} 不存在。请创建一个包含链接的 {filename} 文件。")
    return links

def save_to_yaml(data, filename='link.yaml'):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"成功将数据保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

def save_summary_to_csv(summary_data, filename='link.csv'):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['link', 'node_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in summary_data:
                writer.writerow(row)
        print(f"成功将节点数量汇总保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")
        
def generate_unique_name(base_name, name_counts):
    name_counts[base_name] = name_counts.get(base_name, 0) + 1
    return f"{base_name}_{name_counts[base_name]}"

def process_node_with_geolocation(node, geo_locator):
    server = node.get('server')
    country_name = "未知地区" # 默认值
    success = False
    if server:
        try:
            # 尝试将服务器地址解析为 IP 地址，支持 IPv4 和 IPv6
            addrs = socket.getaddrinfo(server, None)
            if addrs:
                ip_address = addrs[0][4][0] # 提取第一个地址的 IP
                _, country_name = geo_locator.get_location(ip_address)
                success = True
        except (socket.gaierror, Exception):
            pass
    node['name'] = country_name
    return node, success

if __name__ == "__main__":
    links = get_links_from_local_file()
    all_nodes = []
    nodes_summary = []
    
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("跳过节点日志\n================\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_nodes_from_url, link): link for link in links}
        
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(links), desc="处理链接"):
            link = futures[future]
            try:
                nodes = future.result()
                if nodes:
                    all_nodes.extend(nodes)
                    nodes_summary.append({'link': link, 'node_count': len(nodes)})
                    print(f"\n[成功] 从 {link} 找到 {len(nodes)} 个节点。")
                else:
                    nodes_summary.append({'link': link, 'node_count': 0})
                    with open(LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"从 {link} 未找到任何节点。\n")
            except Exception as e:
                nodes_summary.append({'link': link, 'node_count': 0})
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"处理 {link} 时发生错误: {e}\n")

    # 对节点进行地理位置识别和重命名
    db_path = "GeoLite2-Country.mmdb"
    if os.path.exists(db_path):
        from ip_geolocation import GeoLite2Country
        success_count = 0
        failure_count = 0
        
        with GeoLite2Country(db_path) as geo_locator:
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
                results = list(tqdm(
                    executor.map(lambda node: process_node_with_geolocation(node, geo_locator), all_nodes),
                    total=len(all_nodes),
                    desc="地理位置识别"
                ))
            
        all_nodes_geolocated = []
        for node, success in results:
            all_nodes_geolocated.append(node)
            if success:
                success_count += 1
            else:
                failure_count += 1
        all_nodes = all_nodes_geolocated
        
        print(f"\n地理位置识别完成：成功 {success_count} 个，失败 {failure_count} 个。")
    else:
        print(f"警告：未找到 {db_path}，无法进行地理位置重命名。")

    seen_nodes = set()
    unique_nodes = []
    name_counts = defaultdict(int)
    
    for node in all_nodes:
        node_type = node.get('type')
        if node_type == 'ss':
            node_key = ('ss', node.get('server'), node.get('port'), node.get('password'))
        elif node_type == 'vmess':
            node_key = ('vmess', node.get('server'), node.get('port'), node.get('uuid'))
        elif node_type == 'vless':
            node_key = ('vless', node.get('server'), node.get('port'), node.get('uuid'))
        elif node_type == 'trojan':
            node_key = ('trojan', node.get('server'), node.get('port'), node.get('password'))
        elif node_type == 'ssr':
            node_key = ('ssr', node.get('server'), node.get('port'), node.get('password'))
        elif node_type == 'hysteria2':
            node_key = ('hysteria2', node.get('server'), node.get('port'), node.get('password'))
        else:
            node_key = str(OrderedDict(sorted(node.items())))
        
        if node_key not in seen_nodes:
            seen_nodes.add(node_key)
            base_name = node.get('name', f"{node_type}-{node.get('server')}-{node.get('port')}")
            node['name'] = generate_unique_name(base_name, name_counts)
            unique_nodes.append(node)
        else:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"跳过重复节点: {node.get('name', '未命名')} ({node_key})\n")

    if unique_nodes:
        save_to_yaml({'proxies': unique_nodes})
        print(f"\n总共找到 {len(all_nodes)} 个节点，去重并验证后剩下 {len(unique_nodes)} 个。")
    else:
        print("\n未找到任何有效节点。")

    if nodes_summary:
        save_summary_to_csv(nodes_summary)
