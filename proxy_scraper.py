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
SOURCES_FILE = 'sources.list'  # 存放订阅源URL的文件
DATA_DIR = 'data'              # 存储抓取到的节点数据目录
CACHE_DIR = 'cache'            # 存储网页内容缓存的目录
CACHE_EXPIRATION_TIME = 3600   # 缓存过期时间（秒），这里设置为1小时
MAX_RECURSION_DEPTH = 3        # 最大递归抓取深度
USER_AGENTS = [                # 模拟浏览器访问的User-Agent列表
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/90.0.4430.216 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/90.0.4430.216 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
]

# 确保必要的目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 节点匹配正则表达式 (主要用于初步识别，详细验证在 validate_node 中进行)
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
    """根据URL生成缓存文件名，使用MD5哈希确保唯一性"""
    return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + '.cache')

def load_cache(url):
    """从缓存中加载内容，如果缓存存在且未过期则返回内容"""
    cache_file = get_cache_filename(url)
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                content_lines = f.readlines()
                if len(content_lines) < 2: # 确保至少有内容和时间戳两行
                    return None
                timestamp = float(content_lines[-1].strip()) # 最后一行是时间戳
                content = "".join(content_lines[:-1]) # 之前所有行是内容
                if time.time() - timestamp < CACHE_EXPIRATION_TIME:
                    return content
        except Exception as e:
            print(f"加载缓存文件 {cache_file} 失败: {e}")
            return None
    return None

def save_cache(url, content):
    """将内容保存到缓存文件，并记录当前时间戳"""
    cache_file = get_cache_filename(url)
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            f.write(f"{content}\n{time.time()}")
    except Exception as e:
        print(f"保存缓存文件 {cache_file} 失败: {e}")

# --- 节点验证函数 ---

def validate_node(node_url):
    """根据协议官方规范对节点URL进行严格验证。"""
    try:
        # VMess 协议验证 (基于 V2Ray/Xray 规范)
        if node_url.startswith("vmess://"):
            try:
                # 确保Base64字符串有正确的填充符
                decoded = base64.b64decode(node_url[8:] + '=' * (-len(node_url[8:]) % 4)).decode('utf-8')
                config = json.loads(decoded)
                
                required_fields = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net']
                if not all(field in config for field in required_fields): return False
                
                if not (isinstance(config['v'], str) and config['v'].startswith('2')): return False
                if not isinstance(config['ps'], str): return False
                if not isinstance(config['add'], str) or not config['add']: return False
                if not (isinstance(config['port'], (int, str)) and 0 < int(config['port']) < 65536): return False
                # UUID格式验证
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
                if 'path' not in query_params or not query_params['path'][0]: return False
                if 'host' not in query_params or not query_params['host'][0]: return False

            return True

        # Shadowsocks 协议验证
        elif node_url.startswith("ss://"):
            try:
                decoded_part = node_url[5:]
                decoded_part += '=' * (-len(decoded_part) % 4) # 确保填充
                decoded_str = base64.urlsafe_b64decode(decoded_part).decode('utf-8')
                
                # 正则匹配 'method:password@server:port' 格式
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
                
                # SSR链接格式解析: server:port:protocol:method:obfs:password_base64/?params
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
                except Exception: return False # 密码部分无法解码

                supported_ssr_protocols = ["origin", "verify_sha1", "verify_sha1_v2", "auth_sha1_v4", "auth_sha1_v4_compatible", "auth_aes128_md5", "auth_aes128_sha1"]
                supported_ssr_methods = ["aes-256-cfb", "aes-192-cfb", "aes-128-cfb", "chacha20", "rc4-md5"] # 常见方法
                supported_ssr_obfs = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth", "tls1.2_ticket_auth_compatible"]

                if protocol.lower() not in supported_ssr_protocols: return False
                if method.lower() not in supported_ssr_methods: return False
                if obfs.lower() not in supported_ssr_obfs: return False

                if len(password_b64_parts) > 1: # 处理可选参数
                    params_str = password_b64_parts[1]
                    parsed_params = parse_qs(params_str)
                    if 'obfsparam' in parsed_params:
                        obfs_param_b64 = parsed_params['obfsparam'][0]
                        obfs_param_b64 += '=' * (-len(obfs_param_b64) % 4)
                        obfs_param = base64.urlsafe_b64decode(obfs_param_b64).decode('utf-8')
                        # 混淆参数的简单验证，例如HTTP混淆通常是域名或IP
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
            if not re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid): return False # UUID格式

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
    # 增加一个通用Base64识别模式，用于可能包含Base64编码内容的URL
    # 识别长字符串（至少20个字符），且字符集符合Base64特征
    # [a-zA-Z0-9+/=] 匹配Base64字符，{20,} 匹配至少20个字符
    # (?:={1,3})? 匹配可选的填充符
    # \s* 可选的空白字符
    # 确保不匹配明显的URL或者其他协议头，避免重复处理
    # 过滤掉过短的（如Base64编码的3个字符）或看起来不像真实Base64的字符串
    base64_pattern = re.compile(r'\b[a-zA-Z0-9+/]{20,}={0,3}\b')


    def _recursive_find_nodes(data):
        """辅助函数：递归查找 JSON/YAML/字符串中的节点"""
        if isinstance(data, str):
            # --- 优化点：更积极地尝试Base64解码并递归 ---
            # 首先，尝试匹配并解码独立的Base64字符串
            for match in base64_pattern.finditer(data):
                b64_string = match.group(0)
                try:
                    # 尝试URL安全Base64解码
                    decoded_str = base64.urlsafe_b64decode(b64_string + '=' * (-len(b64_string) % 4)).decode('utf-8')
                    if decoded_str and decoded_str != data:
                        _recursive_find_nodes(decoded_str)
                except Exception:
                    try: # 尝试普通Base64解码
                        decoded_str = base64.b64decode(b64_string + '=' * (-len(b64_string) % 4)).decode('utf-8')
                        if decoded_str and decoded_str != data:
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
                        # SS协议转换
                        if proxy['type'].lower() == 'ss' and all(k in proxy for k in ['cipher', 'password', 'server', 'port']):
                            ss_payload = f"{proxy['cipher']}:{proxy['password']}@{proxy['server']}:{proxy['port']}"
                            encoded_ss = base64.urlsafe_b64encode(ss_payload.encode()).decode().rstrip('=')
                            node_url = f"ss://{encoded_ss}"
                            if 'name' in proxy and proxy['name']: node_url += f"#{proxy['name']}"
                        # VMess协议转换
                        elif proxy['type'].lower() == 'vmess' and all(k in proxy for k in ['uuid', 'server', 'port']):
                            vmess_config = {
                                'v': '2', 'ps': proxy.get('name', 'vmess_node'), # 备注名
                                'add': proxy['server'], 'port': proxy['port'],
                                'id': proxy['uuid'], 'aid': proxy.get('alterId', 0), # alterId默认为0
                                'net': proxy.get('network', 'tcp'),
                                'type': proxy.get('type', ''), # TCP传输层类型（例如 none, http, kcp, ws, h2, quic, grpc）
                                'host': proxy.get('servername', '') or proxy.get('ws-headers', {}).get('Host', ''),
                                'path': proxy.get('ws-path', ''),
                                'tls': 'tls' if proxy.get('tls', False) else '',
                                'sni': proxy.get('servername', ''),
                                'fp': proxy.get('fingerprint', ''), # TLS指纹
                                'alpn': proxy.get('alpn', []),
                                'scy': proxy.get('cipher', ''), # 加密方式
                                'grpcServiceName': proxy.get('grpc-service-name', ''),
                                'flow': proxy.get('flow', ''), # XTLS流控
                            }
                            # 过滤掉值为None或空字符串的键，aid为0可以保留
                            vmess_config = {k: v for k, v in vmess_config.items() if v or k in ['aid']}
                            encoded_vmess = base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode()).decode().rstrip('=')
                            node_url = f"vmess://{encoded_vmess}"
                        # Trojan协议转换
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
                        # VLESS协议转换
                        elif proxy['type'].lower() == 'vless' and all(k in proxy for k in ['uuid', 'server', 'port']):
                            node_url = f"vless://{proxy['uuid']}@{proxy['server']}:{proxy['port']}"
                            params = [f"type={proxy.get('network', 'tcp')}"] # 传输类型是必需的
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
                        # Hysteria2协议转换
                        elif proxy['type'].lower() == 'hysteria2' and all(k in proxy for k in ['server', 'port']):
                            node_url = f"hysteria2://{proxy['server']}:{proxy['port']}"
                            params = []
                            if proxy.get('password'): params.append(f"auth={proxy['password']}")
                            if not proxy.get('tls', True): params.append("insecure=true") # 默认tls为true，如果明确设为false则加insecure
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
    
    # 开始解析：首先尝试作为原始字符串解析，再尝试JSON/YAML
    _recursive_find_nodes(content)
    
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
        print(f"达到最大递归深度，跳过 {url}")
        return "", []

    print(f"正在抓取: {url} (深度: {depth})")
    
    cached_content = load_cache(url)
    if cached_content:
        print(f"从缓存加载: {url}")
        return cached_content, []

    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    content = ""
    target_url = url # 记录实际访问的 URL

    # 规范化 URL：确保有协议头
    test_urls = [url]
    if url.startswith("http://"):
        test_urls.append(url.replace("http://", "https://"))
    elif url.startswith("https://"):
        test_urls.append(url.replace("https://", "http://"))
    
    for current_test_url in test_urls:
        try:
            # 增加 verify=False 以忽略 SSL 证书验证错误，但请注意这会降低安全性
            response = await client.get(current_test_url, headers=headers, follow_redirects=True, timeout=15, verify=False) 
            response.raise_for_status() # 抛出 HTTPStatusError (4xx/5xx)
            content = response.text
            target_url = current_test_url
            print(f"成功抓取: {current_test_url}")
            break # 成功获取后跳出循环
        except httpx.RequestError as e:
            print(f"请求 {current_test_url} 失败: {e}")
        except httpx.HTTPStatusError as e:
            print(f"HTTP状态码错误 {current_test_url}: {e.response.status_code}")
        except Exception as e: # 捕获其他未知异常
            print(f"抓取 {current_test_url} 时发生未知错误: {e}")
    else: # 所有尝试都失败
        print(f"所有尝试均失败，跳过此URL: {url}")
        return "", []

    save_cache(url, content) # 缓存使用原始 URL 作为键

    # --- 增强点：提取页面中的其他链接和隐藏节点 ---
    soup = BeautifulSoup(content, 'html.parser')
    found_urls = []
    
    # 查找 <base href="..."> 标签，以正确解析相对路径
    base_tag = soup.find('base', href=True)
    base_href = base_tag['href'] if base_tag else None

    # 扫描所有标签的常见URL属性
    # 增加了 'src', 'data-url', 'link', 'value' 等
    for tag in soup.find_all(True): # 查找所有标签
        for attr in ['href', 'src', 'data-url', 'content', 'link', 'value']: # 扩展属性列表
            value = tag.get(attr)
            if value and isinstance(value, str):
                # 尝试解析 URL
                potential_url = urljoin(base_href if base_href else target_url, value) # 使用 base_href 或当前URL作为基准
                parsed_potential_url = urlparse(potential_url)
                
                if parsed_potential_url.scheme in ['http', 'https']:
                    # 过滤条件与 process_url 中的递归条件保持一致
                    original_parsed = urlparse(url) # 使用最初传入的url进行域名比较
                    if parsed_potential_url.netloc == original_parsed.netloc or \
                       any(ext in parsed_potential_url.path.lower() for ext in ['.txt', '.yaml', '.yml', '.json', '.conf', '.ini', '.sub', '.html', '.htm', '/']):
                        found_urls.append(potential_url)
    
    # 从 <script> 标签中提取 JavaScript 代码并尝试解析其中的 URL 或 Base64 字符串
    for script_tag in soup.find_all('script'):
        script_content = script_tag.string
        if script_content:
            # 匹配常见的 URL 字符串（双引号或单引号）
            url_matches = re.findall(r'["\'](https?://[^"\']+?)["\']', script_content)
            for match_url in url_matches:
                full_script_url = urljoin(base_href if base_href else target_url, match_url)
                parsed_script_url = urlparse(full_script_url)
                if parsed_script_url.scheme in ['http', 'https']:
                    original_parsed = urlparse(url)
                    if parsed_script_url.netloc == original_parsed.netloc or \
                       any(ext in parsed_script_url.path.lower() for ext in ['.txt', '.yaml', '.yml', '.json', '.conf', '.ini', '.sub', '.html', '.htm', '/']):
                        found_urls.append(full_script_url)
            
            # 尝试从JavaScript内容中直接解析节点或Base64编码的字符串
            # 这是为了捕获那些直接在JS变量里存放订阅内容的情况
            nodes_in_js = parse_nodes(script_content)
            for node_from_js in nodes_in_js:
                # 这些节点会直接被添加到 all_nodes_for_url，而不是作为新的URL进行递归抓取
                pass # parse_nodes 已经在_recursive_find_nodes中处理了

    return content, found_urls

async def process_url(client, url):
    """处理单个原始 URL 及其递归抓取过程。"""
    all_nodes_for_url = set()
    visited_urls = set()
    urls_to_visit = [(url, 0)] # (url, depth)
    
    # 确保 original_domain_parsed 的 URL 带有协议头，以便正确解析域名
    original_parsed = urlparse(url)
    original_domain = original_parsed.netloc

    while urls_to_visit:
        current_url, current_depth = urls_to_visit.pop(0)
        
        if current_url in visited_urls:
            continue
        
        visited_urls.add(current_url)
        
        content, new_urls = await fetch_url(client, current_url, current_depth)
        
        if content:
            nodes = parse_nodes(content) # 在这里解析内容中的所有节点
            for node in nodes:
                all_nodes_for_url.add(node)
            
            for nu in new_urls:
                new_domain = urlparse(nu).netloc
                # 递归条件：深度允许 且 (同域名 或 配置文件类型) 且 未访问过
                if current_depth + 1 <= MAX_RECURSION_DEPTH and \
                   (new_domain == original_domain or any(ext in urlparse(nu).path.lower() for ext in ['.txt', '.yaml', '.yml', '.json', '.conf', '.ini', '.sub', '.html', '.htm', '/'])) \
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
                if not stripped_line or stripped_line.startswith('#'): # 忽略空行和注释行
                    continue

                normalized_url = stripped_line
                # 检查并添加协议头，如果缺失且看起来像一个域名
                if not re.match(r"^(http|https)://", stripped_line):
                    # 检查是否是一个有效的域名格式（简单检查，包含至少一个点且不含空格）
                    if '.' in stripped_line and not ' ' in stripped_line:
                        normalized_url = f"https://{stripped_line}" # 默认优先尝试 HTTPS
                        print(f"规范化URL: {stripped_line} -> {normalized_url}")
                    else:
                        print(f"跳过可疑或无效的URL格式: {stripped_line}")
                        continue
                
                urls.append(normalized_url)
    except FileNotFoundError:
        print(f"错误: {SOURCES_FILE} 文件未找到。")
        return
    except Exception as e:
        print(f"读取 {SOURCES_FILE} 文件时发生错误: {e}")
        return

    all_results = []
    total_nodes_collected = 0

    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    timeout = httpx.Timeout(15.0, connect=10.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        tasks = [process_url(client, url) for url in urls]
        results = await asyncio.gather(*tasks)

        for original_url, nodes_collected in results:
            # 清理URL名称用于文件名，替换非法字符
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
                    if len(tag) > 5: # 如果标签长度大于5，则截断
                        node_with_truncated_name = f"{parts[0]}#{tag[:5]}"
                    else:
                        node_with_truncated_name = f"{parts[0]}#{tag}" # 如果不长，则保留
                # 2. `ps=` 参数 (VMess)
                elif "ps=" in node:
                    # 使用正则表达式安全替换 ps 参数的值
                    match_ps = re.search(r'(ps=)([^&]+)', node)
                    if match_ps:
                        param_value = match_ps.group(2)
                        decoded_param_value = unquote(param_value) # 解码 URL 编码
                        if len(decoded_param_value) > 5: # 如果参数值长度大于5，则截断
                            truncated_value = decoded_param_value[:5]
                            # 替换捕获组2的值
                            node_with_truncated_name = re.sub(r'(ps=)[^&]+', r'\g<1>' + truncated_value, node, 1)
                        # else: 如果不长，则保留原样，无需替换
                
                valid_nodes_processed.append(node_with_truncated_name)

            if valid_nodes_processed:
                valid_nodes_sorted = sorted(list(set(valid_nodes_processed))) # 去重并排序
                with open(output_filename, 'w', encoding='utf-8') as f:
                    for node in valid_nodes_sorted:
                        f.write(node + '\n')
                print(f"从 {original_url} 成功保存 {len(valid_nodes_sorted)} 个有效节点到 {output_filename}")
                all_results.append({'url': original_url, 'node_count': len(valid_nodes_sorted)})
                total_nodes_collected += len(valid_nodes_sorted)
            else:
                print(f"从 {original_url} 未找到有效节点。")
                all_results.append({'url': original_url, 'node_count': 0})

    # 生成 CSV 统计文件
    csv_filename = os.path.join(DATA_DIR, 'node_counts.csv')
    try:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['url', 'node_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n节点统计信息已保存到 {csv_filename}")
    except Exception as e:
        print(f"保存节点统计信息到 {csv_filename} 失败: {e}")
    
    print(f"总共收集到的有效节点数量: {total_nodes_collected}")

if __name__ == "__main__":
    asyncio.run(main())
