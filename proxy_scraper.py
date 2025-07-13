import httpx
import asyncio
import re
import os
import csv
import hashlib
import time
from urllib.parse import urlparse, urljoin, unquote, parse_qs
import yaml
import base64
import json
from bs4 import BeautifulSoup
import random

# --- 配置 ---
SOURCES_FILE = 'sources.list'
DATA_DIR = 'data'
CACHE_DIR = 'cache'
CACHE_EXPIRATION_TIME = 3600  # 缓存过期时间（秒），这里设置为1小时
MAX_RECURSION_DEPTH = 3  # 最大递归抓取深度
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/90.0.4430.216 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/90.0.4430.216 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
]

# 确保目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 节点匹配正则 (主要用于初步识别，详细验证在 validate_node 中进行)
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;%=]+"),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9+/=]+"),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;%=]+"),
    "ss": re.compile(r"ss://[a-zA-Z0-9+/=@:.]+"),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9+/=@:.]+"),
    "vless": re.compile(r"vless://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;%=]+"),
}

# --- 辅助函数 ---

def get_cache_filename(url):
    """根据URL生成缓存文件名"""
    return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + '.cache')

def load_cache(url):
    """加载缓存内容"""
    cache_file = get_cache_filename(url)
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            content, timestamp = f.read().split('\n', 1)
            if time.time() - float(timestamp) < CACHE_EXPIRATION_TIME:
                return content
    return None

def save_cache(url, content):
    """保存内容到缓存"""
    cache_file = get_cache_filename(url)
    with open(cache_file, 'w', encoding='utf-8') as f:
        f.write(f"{content}\n{time.time()}")

# --- 节点验证函数 ---

def validate_node(node_url):
    """根据协议官方规范对节点URL进行严格验证。"""
    try:
        # VMess 协议验证 (基于 V2Ray/Xray 规范)
        if node_url.startswith("vmess://"):
            try:
                decoded = base64.b64decode(node_url[8:] + '=' * (-len(node_url[8:]) % 4)).decode('utf-8') # 确保填充
                config = json.loads(decoded)
                
                required_fields = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net']
                if not all(field in config for field in required_fields): return False
                
                if not (isinstance(config['v'], str) and config['v'].startswith('2')): return False
                if not isinstance(config['ps'], str): return False
                if not isinstance(config['add'], str) or not config['add']: return False
                if not (isinstance(config['port'], (int, str)) and 0 < int(config['port']) < 65536): return False
                if not (isinstance(config['id'], str) and re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", config['id'])): return False
                if not (isinstance(config['aid'], (int, str)) and int(config['aid']) >= 0): return False
                supported_nets = ['tcp', 'kcp', 'ws', 'http', 'quic', 'grpc', 'h2']
                if not (isinstance(config['net'], str) and config['net'] in supported_nets): return False

                if config['net'] == 'ws':
                    if 'path' not in config or not isinstance(config['path'], str): return False
                    if 'host' not in config or not isinstance(config['host'], str): return False
                
                if config['net'] == 'grpc':
                    if 'serviceName' not in config or not isinstance(config['serviceName'], str) or not config['serviceName']: return False
                    if 'mode' in config and not (isinstance(config['mode'], str) and config['mode'] in ['multi', 'gun']): return False

                if config.get('tls') == 'tls':
                    if 'sni' not in config or not isinstance(config['sni'], str) or not config['sni']: return False
                    if 'fp' in config and not isinstance(config['fp'], str): return False
                    if 'alpn' in config and not isinstance(config['alpn'], list): return False
                
                return True
            except Exception:
                return False

        # Trojan 协议验证
        elif node_url.startswith("trojan://"):
            parsed_url = urlparse(node_url)
            password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            if not (password and server and port and 0 < port < 65536): return False
            
            # Trojan 通常需要 SNI
            if 'sni' not in query_params or not query_params['sni'][0]: return False
            
            if 'type' in query_params and query_params['type'][0] == 'ws':
                if 'host' not in query_params or not query_params['host'][0]: return False
                if 'path' not in query_params or not query_params['path'][0]: return False

            return True

        # Shadowsocks 协议验证
        elif node_url.startswith("ss://"):
            try:
                decoded_part = node_url[5:]
                decoded_part += '=' * (-len(decoded_part) % 4) # 确保填充
                decoded_str = base64.urlsafe_b64decode(decoded_part).decode('utf-8')
                
                parts = re.match(r"([^:]+):([^@]+)@([^:]+):(\d+)(?:#(.+))?", decoded_str)
                if not parts: return False # 不支持旧版或非标格式

                method = parts.group(1)
                password = parts.group(2)
                server = parts.group(3)
                port = int(parts.group(4))

                if not (method and password and server and 0 < port < 65536): return False
                
                supported_ss_methods = [
                    "aes-256-gcm", "aes-192-gcm", "aes-128-gcm",
                    "chacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                    "none" 
                ]
                if method.lower() not in supported_ss_methods: return False
                
                return True
            except Exception:
                return False

        # ShadowsocksR 协议验证
        elif node_url.startswith("ssr://"):
            try:
                decoded_part = node_url[6:]
                decoded_part += '=' * (-len(decoded_part) % 4)
                decoded_str = base64.urlsafe_b64decode(decoded_part).decode('utf-8')
                
                main_parts_match = re.match(r"([^:]+):(\d+):([^:]+):([^:]+):([^:]+):(.+)", decoded_str)
                if not main_parts_match: return False
                
                server = main_parts_match.group(1)
                port = int(main_parts_match.group(2))
                protocol = main_parts_match.group(3)
                method = main_parts_match.group(4)
                obfs = main_parts_match.group(5)
                password_b64_with_params = main_parts_match.group(6)

                password_b64_parts = password_b64_with_params.split('/?')
                password_b64 = password_b64_parts[0]
                
                if not (server and 0 < port < 65536 and protocol and method and obfs and password_b64): return False
                
                try:
                    password = base64.urlsafe_b64decode(password_b64 + '=' * (-len(password_b64) % 4)).decode('utf-8')
                except Exception: return False

                supported_ssr_protocols = ["origin", "verify_sha1", "verify_sha1_v2", "auth_sha1_v4", "auth_sha1_v4_compatible", "auth_aes128_md5", "auth_aes128_sha1"]
                supported_ssr_methods = ["aes-256-cfb", "aes-192-cfb", "aes-128-cfb", "chacha20", "rc4-md5"] # 常见
                supported_ssr_obfs = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth", "tls1.2_ticket_auth_compatible"]

                if protocol.lower() not in supported_ssr_protocols: return False
                if method.lower() not in supported_ssr_methods: return False
                if obfs.lower() not in supported_ssr_obfs: return False

                if len(password_b64_parts) > 1:
                    params_str = password_b64_parts[1]
                    parsed_params = parse_qs(params_str)
                    if 'obfsparam' in parsed_params:
                        obfs_param_b64 = parsed_params['obfsparam'][0]
                        obfs_param_b64 += '=' * (-len(obfs_param_b64) % 4)
                        obfs_param = base64.urlsafe_b64decode(obfs_param_b64).decode('utf-8')
                        if obfs.lower().startswith('http') and not (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", obfs_param) or re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", obfs_param)):
                             return False

                return True
            except Exception:
                return False

        # VLESS 协议验证
        elif node_url.startswith("vless://"):
            parsed_url = urlparse(node_url)
            uuid = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            if not (uuid and server and port and 0 < port < 65536): return False
            if not re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid): return False
            
            if 'type' not in query_params or not query_params['type'][0]: return False
            
            transport_type = query_params['type'][0].lower()

            if transport_type == 'ws':
                if 'path' not in query_params or not query_params['path'][0]: return False
                if 'host' not in query_params or not query_params['host'][0]: return False
            elif transport_type == 'grpc':
                if 'serviceName' not in query_params or not query_params['serviceName'][0]: return False
                if 'mode' in query_params and query_params['mode'][0] not in ['multi', 'gun']: return False
            
            # TLS/XTLS/Reality 检查
            security = query_params.get('security', [''])[0].lower()
            if security in ['tls', 'xtls', 'reality']:
                if 'sni' not in query_params or not query_params['sni'][0]: return False
                if security in ['xtls', 'reality']: # Reality/XTLS 额外要求
                    if 'pbk' not in query_params or not query_params['pbk'][0]: return False
                    if 'fp' not in query_params or not query_params['fp'][0]: return False
            
            return True

        # Hysteria2 协议验证
        elif node_url.startswith("hysteria2://"):
            parsed_url = urlparse(node_url)
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            if not (server and port and 0 < port < 65536): return False
            
            # Hysteria2 必须有 auth 或证书验证方式
            if 'auth' not in query_params and ('pin' not in query_params or not query_params['pin'][0]):
                return False

            if 'auth' in query_params and not query_params['auth'][0]: return False
            if 'pin' in query_params and not query_params['pin'][0]: return False # certificate pin SHA256
            if 'fastopen' in query_params and query_params['fastopen'][0].lower() not in ['true', 'false']: return False
            if 'up_mbps' in query_params and not query_params['up_mbps'][0].isdigit(): return False
            if 'down_mbps' in query_params and not query_params['down_mbps'][0].isdigit(): return False
            if 'sni' in query_params and not query_params['sni'][0]: return False # 通常需要SNI

            return True

        return False # 不支持的协议类型或无法识别的链接
    except Exception:
        return False

# --- 节点解析函数 ---

def parse_nodes(content):
    """从内容中解析并提取所有支持的节点类型。"""
    nodes = set()

    def _recursive_find_nodes(data):
        """辅助函数：递归查找 JSON/YAML/字符串中的节点"""
        if isinstance(data, str):
            # 尝试 Base64 解码并递归
            try:
                # 尝试 Base64 解码，处理可能缺少的填充符
                b64_decoded_data = data
                if len(b64_decoded_data) % 4 != 0:
                    b64_decoded_data += '=' * (4 - len(b64_decoded_data) % 4)
                
                decoded_str = base64.urlsafe_b64decode(b64_decoded_data).decode('utf-8')
                if decoded_str and decoded_str != data: # 避免无限循环
                    _recursive_find_nodes(decoded_str)
            except Exception:
                pass # 不是有效的Base64

            # 直接匹配明文节点
            for pattern_name, pattern_regex in NODE_PATTERNS.items():
                for match in pattern_regex.finditer(data):
                    node = match.group(0)
                    if validate_node(node):
                        nodes.add(node)

            # 尝试 JSON/YAML 解析 (如果字符串本身就是 JSON/YAML)
            try:
                parsed_inner = json.loads(data)
                _recursive_find_nodes(parsed_inner)
            except json.JSONDecodeError:
                try:
                    parsed_inner = yaml.safe_load(data)
                    _recursive_find_nodes(parsed_inner)
                except yaml.YAMLError:
                    pass

        elif isinstance(data, dict):
            # 尝试从 Clash/V2RayN 等配置结构中提取
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        node_url = None
                        if proxy['type'].lower() == 'ss' and all(k in proxy for k in ['cipher', 'password', 'server', 'port']):
                            ss_payload = f"{proxy['cipher']}:{proxy['password']}@{proxy['server']}:{proxy['port']}"
                            encoded_ss = base64.urlsafe_b64encode(ss_payload.encode()).decode().rstrip('=')
                            node_url = f"ss://{encoded_ss}"
                            if 'name' in proxy and proxy['name']: node_url += f"#{proxy['name']}"
                        elif proxy['type'].lower() == 'vmess' and all(k in proxy for k in ['uuid', 'server', 'port']):
                            vmess_config = {
                                'v': '2', 'ps': proxy.get('name', 'vmess_node'),
                                'add': proxy['server'], 'port': proxy['port'],
                                'id': proxy['uuid'], 'aid': proxy.get('alterId', 0),
                                'net': proxy.get('network', 'tcp'),
                                'type': proxy.get('type', ''),
                                'host': proxy.get('servername', '') or proxy.get('ws-headers', {}).get('Host', ''),
                                'path': proxy.get('ws-path', ''),
                                'tls': 'tls' if proxy.get('tls', False) else '',
                                'sni': proxy.get('servername', ''),
                                'fp': proxy.get('fingerprint', ''),
                                'alpn': proxy.get('alpn', []),
                                'scy': proxy.get('cipher', ''),
                                'grpcServiceName': proxy.get('grpc-service-name', ''),
                                'flow': proxy.get('flow', ''),
                            }
                            vmess_config = {k: v for k, v in vmess_config.items() if v or k in ['aid']} # aid 可以为0
                            encoded_vmess = base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode()).decode().rstrip('=')
                            node_url = f"vmess://{encoded_vmess}"
                        elif proxy['type'].lower() == 'trojan' and all(k in proxy for k in ['password', 'server', 'port']):
                            node_url = f"trojan://{proxy['password']}@{proxy['server']}:{proxy['port']}"
                            params = []
                            if 'sni' in proxy and proxy['sni']: params.append(f"sni={proxy['sni']}")
                            if proxy.get('skip-cert-verify'): params.append("allowInsecure=1")
                            if proxy.get('network') == 'ws':
                                params.append("type=ws")
                                if proxy.get('ws-path'): params.append(f"path={proxy['ws-path']}")
                                if proxy.get('ws-headers', {}).get('Host'): params.append(f"host={proxy['ws-headers']['Host']}")
                            if params: node_url += "?" + "&".join(params)
                            if 'name' in proxy and proxy['name']: node_url += f"#{proxy['name']}"
                        elif proxy['type'].lower() == 'vless' and all(k in proxy for k in ['uuid', 'server', 'port']):
                            node_url = f"vless://{proxy['uuid']}@{proxy['server']}:{proxy['port']}"
                            params = [f"type={proxy.get('network', 'tcp')}"]
                            if proxy.get('tls'): params.append("security=tls")
                            if proxy.get('servername'): params.append(f"sni={proxy['servername']}")
                            if proxy.get('flow'): params.append(f"flow={proxy['flow']}")
                            if proxy.get('fingerprint'): params.append(f"fp={proxy['fingerprint']}")
                            if proxy.get('alpn'): params.append(f"alpn={','.join(proxy['alpn'])}")
                            if proxy.get('reality-publickey'): params.append(f"pbk={proxy['reality-publickey']}")
                            if proxy.get('reality-shortid'): params.append(f"sid={proxy['reality-shortid']}")
                            if proxy.get('network') == 'ws':
                                if proxy.get('ws-path'): params.append(f"path={proxy['ws-path']}")
                                if proxy.get('ws-headers', {}).get('Host'): params.append(f"host={proxy['ws-headers']['Host']}")
                            elif proxy.get('network') == 'grpc':
                                if proxy.get('grpc-service-name'): params.append(f"serviceName={proxy['grpc-service-name']}")
                                if proxy.get('grpc-mode'): params.append(f"mode={proxy['grpc-mode']}")
                            if params: node_url += "?" + "&".join(params)
                            if 'name' in proxy and proxy['name']: node_url += f"#{proxy['name']}"
                        elif proxy['type'].lower() == 'hysteria2' and all(k in proxy for k in ['server', 'port']):
                            node_url = f"hysteria2://{proxy['server']}:{proxy['port']}"
                            params = []
                            if proxy.get('password'): params.append(f"auth={proxy['password']}")
                            if not proxy.get('tls', True): params.append("insecure=true")
                            if proxy.get('tls-cert-pin'): params.append(f"pin={proxy['tls-cert-pin']}")
                            if proxy.get('sni'): params.append(f"sni={proxy['sni']}")
                            if proxy.get('fast-open'): params.append("fastopen=true")
                            if proxy.get('up'): params.append(f"up_mbps={proxy['up']}")
                            if proxy.get('down'): params.append(f"down_mbps={proxy['down']}")
                            if params: node_url += "?" + "&".join(params)
                            if 'name' in proxy and proxy['name']: node_url += f"#{proxy['name']}"

                        if node_url and validate_node(node_url):
                            nodes.add(node_url)
            # 递归处理字典中的其他值
            for value in data.values():
                _recursive_find_nodes(value)
        elif isinstance(data, list):
            # 递归处理列表中的每个元素
            for item in data:
                _recursive_find_nodes(item)
    
    # 开始解析
    _recursive_find_nodes(content) # 尝试直接作为字符串解析
    
    # 尝试解析为 JSON 或 YAML 结构
    try:
        parsed_data = json.loads(content)
        _recursive_find_nodes(parsed_data)
    except json.JSONDecodeError:
        try:
            parsed_data = yaml.safe_load(content)
            _recursive_find_nodes(parsed_data)
        except yaml.YAMLError:
            pass
            
    return list(nodes)

# --- 异步 HTTP 请求与递归抓取 ---

async def fetch_url(client, url, depth=0):
    """
    异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    同时解析页面中的其他链接。
    """
    if depth > MAX_RECURSION_DEPTH:
        return "", []

    print(f"Fetching: {url} (Depth: {depth})")
    
    cached_content = load_cache(url)
    if cached_content:
        print(f"Loaded from cache: {url}")
        return cached_content, []

    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    content = ""
    target_url = url # 记录实际访问的 URL

    # 规范化 URL：确保有协议头
    if not url.startswith("http://") and not url.startswith("https://"):
        test_urls = [f"http://{url}", f"https://{url}"]
    else:
        test_urls = [url]
        if url.startswith("http://"):
            test_urls.append(url.replace("http://", "https://"))
        elif url.startswith("https://"):
            test_urls.append(url.replace("https://", "http://"))
    
    for current_test_url in test_urls:
        try:
            response = await client.get(current_test_url, headers=headers, follow_redirects=True, timeout=10)
            response.raise_for_status() # 抛出 HTTPStatusError (4xx/5xx)
            content = response.text
            target_url = current_test_url
            print(f"Successfully fetched: {target_test_url}")
            break # 成功获取后跳出循环
        except httpx.RequestError as e:
            print(f"Request failed for {current_test_url}: {e}")
        except httpx.HTTPStatusError as e:
            print(f"HTTP status error for {current_test_url}: {e.response.status_code}")
    else: # 所有尝试都失败
        print(f"All attempts failed for {url}. Skipping this URL.")
        return "", []

    save_cache(url, content) # 缓存使用原始 URL 作为键

    # 提取页面中的其他链接
    soup = BeautifulSoup(content, 'html.parser')
    found_urls = []
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        full_url = urljoin(target_url, href)
        parsed_full_url = urlparse(full_url)
        
        # 过滤非 HTTP/HTTPS 链接
        if parsed_full_url.scheme not in ['http', 'https']:
            continue

        original_parsed = urlparse(f"http://{url}" if not url.startswith("http") else url)
        
        # 过滤条件：
        # 1. 链接与原始 URL 域名相同
        # 2. 链接指向常见配置文件类型（即使域名不同）
        if parsed_full_url.netloc == original_parsed.netloc or \
           any(ext in parsed_full_url.path.lower() for ext in ['.txt', '.yaml', '.yml', '.json', '.conf', '.ini', '.sub']): # 增加了 .sub
            found_urls.append(full_url)
    
    return content, found_urls

async def process_url(client, url):
    """处理单个原始 URL 及其递归抓取过程。"""
    all_nodes_for_url = set()
    visited_urls = set()
    urls_to_visit = [(url, 0)] # (url, depth)
    
    original_domain_parsed = urlparse(f"http://{url}" if not url.startswith("http") else url)
    original_domain = original_domain_parsed.netloc

    while urls_to_visit:
        current_url, current_depth = urls_to_visit.pop(0)
        
        if current_url in visited_urls:
            continue
        
        visited_urls.add(current_url)
        
        content, new_urls = await fetch_url(client, current_url, current_depth)
        
        if content:
            nodes = parse_nodes(content)
            for node in nodes:
                all_nodes_for_url.add(node)
            
            for nu in new_urls:
                new_domain = urlparse(nu).netloc
                # 递归条件：深度允许 且 (同域名 或 配置文件类型) 且 未访问过
                if current_depth + 1 <= MAX_RECURSION_DEPTH and \
                   (new_domain == original_domain or any(ext in urlparse(nu).path.lower() for ext in ['.txt', '.yaml', '.yml', '.json', '.conf', '.ini', '.sub'])) \
                   and nu not in visited_urls:
                    urls_to_visit.append((nu, current_depth + 1))

    return url, list(all_nodes_for_url)

# --- 主程序 ---

async def main():
    """主函数：读取 sources.list，并行抓取并保存结果。"""
    urls = []
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    urls.append(stripped_line)
    except FileNotFoundError:
        print(f"Error: {SOURCES_FILE} not found.")
        return

    all_results = []
    total_nodes_collected = 0

    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    timeout = httpx.Timeout(15.0, connect=10.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        tasks = [process_url(client, url) for url in urls]
        results = await asyncio.gather(*tasks)

        for original_url, nodes_collected in results:
            cleaned_url_name = re.sub(r'[^a-zA-Z0-9.\-_]', '_', original_url).replace('http___', '').replace('https___', '')
            output_filename = os.path.join(DATA_DIR, f"{cleaned_url_name}.txt")
            
            valid_nodes_processed = []
            for node in nodes_collected:
                node_with_truncated_name = node
                
                # 尝试提取和截断备注名
                # 1. `#` 后面的部分 (Trojan, VLESS, SS/SSR 的 tag)
                if "#" in node:
                    parts = node.split('#', 1)
                    tag = unquote(parts[1]) # 解码 URL 编码的标签
                    if len(tag) > 5:
                        node_with_truncated_name = f"{parts[0]}#{tag[:5]}"
                # 2. `ps=` 参数 (VMess)
                elif "ps=" in node:
                    # 使用正则表达式安全替换 ps 参数的值
                    match_ps = re.search(r'(ps=)([^&]+)', node)
                    if match_ps:
                        param_value = match_ps.group(2)
                        decoded_param_value = unquote(param_value) # 解码 URL 编码
                        if len(decoded_param_value) > 5:
                            truncated_value = decoded_param_value[:5]
                            # 替换捕获组2的值
                            node_with_truncated_name = re.sub(r'(ps=)[^&]+', r'\g<1>' + truncated_value, node, 1)
                
                valid_nodes_processed.append(node_with_truncated_name)

            if valid_nodes_processed:
                valid_nodes_sorted = sorted(list(set(valid_nodes_processed))) # 去重并排序
                with open(output_filename, 'w', encoding='utf-8') as f:
                    for node in valid_nodes_sorted:
                        f.write(node + '\n')
                print(f"Saved {len(valid_nodes_sorted)} valid nodes from {original_url} to {output_filename}")
                all_results.append({'url': original_url, 'node_count': len(valid_nodes_sorted)})
                total_nodes_collected += len(valid_nodes_sorted)
            else:
                print(f"No valid nodes found for {original_url}")
                all_results.append({'url': original_url, 'node_count': 0})

    # 生成 CSV 统计文件
    csv_filename = os.path.join(DATA_DIR, 'node_counts.csv')
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url', 'node_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    
    print(f"\nNode statistics saved to {csv_filename}")
    print(f"Total valid nodes collected: {total_nodes_collected}")

if __name__ == "__main__":
    asyncio.run(main())
