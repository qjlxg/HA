import os
import re
import requests
import json
import yaml
import base64
import socket
from urllib.parse import urlparse, parse_qs, unquote
from tqdm import tqdm
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import geoip2.database
import sys
from datetime import datetime

# 全局集合用于去重
used_names = set()
used_node_fingerprints = set()

# 全局计数器
total_links = 0
successful_nodes = 0
skipped_links = 0
duplicate_links = 0

# 支持的 Shadowsocks 加密方法列表（官方标准）
SS_SUPPORTED_CIPHERS = [
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305"
]

# 为 ShadowsocksR 单独定义支持的加密方法（官方标准）
SSR_SUPPORTED_CIPHERS = [
    "none", "table", "rc4", "rc4-md5", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
    "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb",
    "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
    "salsa20", "chacha20", "chacha20-ietf"
]

# 支持的 ShadowsocksR 协议（protocol）
SSR_SUPPORTED_PROTOCOLS = [
    "origin", "verify_deflate", "auth_sha1_v4",
    "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a",
    "auth_chain_b"
]

# 支持的 ShadowsocksR 混淆（obfs）
SSR_SUPPORTED_OBFS = [
    "plain", "http_simple", "http_post", "random_head",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"
]

# 支持的 Hysteria2 混淆类型
HYSTERIA2_SUPPORTED_OBFS = ["none", "salamander"]

def is_base64(s):
    """检查字符串是否为有效的 Base64 编码。"""
    try:
        s = s.replace('<br/>', '').replace('\n', '').strip()
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def normalize_name(name):
    """
    规范化节点名称：
    1. 移除表情符号和特殊字符。
    2. 如果名称重复，添加序号以确保唯一性。
    """
    name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
    name = name.replace('<br/>', '').replace('\n', '').strip()
    name = re.sub(r'[^\u4e00-\u9fa5\w\s-]', '', name)
    name = re.sub(r'\s+', ' ', name).strip()
    
    truncated_name = name
    original_name = truncated_name
    counter = 1
    while truncated_name in used_names:
        match = re.match(r'\[(\w+)\]', original_name, re.IGNORECASE)
        if match:
            country_code = match.group(1).lower()
            truncated_name = f"{country_code}_{counter:02d}"
        else:
            truncated_name = f"{original_name}-{counter:02d}"
        counter += 1
    used_names.add(truncated_name)
    return truncated_name

# ====================
# 重构后的去重指纹函数
# ====================
def get_vmess_fingerprint(data):
    """Vmess指纹：server, port, uuid, network, tls, servername (或ws host), path (如果ws)"""
    tls = data.get('tls', False)
    network = data.get('network', 'tcp')
    servername = data.get('servername', data.get('server'))
    path = ""
    
    if network == 'ws':
        ws_opts = data.get('ws-opts', {})
        host = ws_opts.get('headers', {}).get('Host')
        servername = host if host else servername
        path = ws_opts.get('path', '/')
    
    return (
        "vmess",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        network,
        tls,
        servername,
        path
    )

def get_vless_fingerprint(data):
    """Vless指纹：server, port, uuid, network, tls, servername, flow, path (如果ws)"""
    tls = data.get('tls', False)
    network = data.get('network', 'tcp')
    servername = data.get('servername', data.get('server'))
    path = ""
    
    if network == 'ws':
        ws_opts = data.get('ws-opts', {})
        host = ws_opts.get('headers', {}).get('Host')
        servername = host if host else servername
        path = ws_opts.get('path', '/')
    
    return (
        "vless",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        network,
        tls,
        servername,
        data.get('flow', ''),
        path
    )

def get_ss_fingerprint(data):
    """SS指纹：server, port, cipher, password"""
    return (
        "ss",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("cipher"),
        data.get("password")
    )

def get_trojan_fingerprint(data):
    """Trojan指纹：server, port, password, sni, network, serviceName (如果grpc)"""
    network = data.get('network', 'tcp')
    service_name = ""
    if network == 'grpc':
        grpc_opts = data.get('grpc-opts', {})
        service_name = grpc_opts.get('serviceName', '') if grpc_opts else ''
    
    return (
        "trojan",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("password"),
        data.get("sni", data.get("server")),
        network,
        service_name
    )

def get_ssr_fingerprint(data):
    """SSR指纹：server, port, cipher, password, protocol, obfs, obfs-param, protocol-param"""
    return (
        "ssr",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("cipher"),
        data.get("password"),
        data.get("protocol"),
        data.get("obfs"),
        data.get("obfs-param", ""),
        data.get("protocol-param", "")
    )

def get_hysteria2_fingerprint(data):
    """Hysteria2指纹：server, port, password, obfs, obfs-password, sni"""
    return (
        "hysteria2",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("password"),
        data.get("obfs", "none"),
        data.get("obfs-password", ""),
        data.get("sni", data.get("server"))
    )

# ====================
# 严格解析函数
# ====================
def parse_vmess(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("vmess://"):
            skipped_links += 1
            print(f"跳过无效 Vmess URI: {uri[:30]}...")
            return None
        encoded_data = uri[8:].replace('<br/>', '').replace('\n', '').strip()
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        
        required_keys = ["add", "port", "id", "net"]
        if not all(key in data for key in required_keys):
            skipped_links += 1
            print(f"跳过 Vmess 节点: 缺少必需参数 {required_keys}")
            return None
        
        try:
            port = int(data["port"])
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 Vmess 节点: 无效端口 {data.get('port')}")
            return None
        
        uuid = data.get("id")
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uuid, re.I):
            skipped_links += 1
            print(f"跳过 Vmess 节点: 无效 UUID {uuid}")
            return None
        
        network = data["net"]
        if network not in ["tcp", "ws", "http", "grpc", "kcp", "quic"]:
            skipped_links += 1
            print(f"跳过 Vmess 节点: 无效网络类型 {network}")
            return None
        
        node = {
            "name": data.get("ps", "Unnamed Vmess Node"),
            "type": "vmess",
            "server": data["add"],
            "port": port,
            "uuid": uuid,
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": network
        }
        
        if data.get("tls") == "tls":
            node["tls"] = True
            node["servername"] = data.get("sni", data["add"])
            if not node["servername"]:
                skipped_links += 1
                print(f"跳过 Vmess 节点: TLS 启用但缺少 servername")
                return None
        
        if network == "ws":
            node["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", node["server"])}
            }
            if not node["ws-opts"]["path"]:
                skipped_links += 1
                print(f"跳过 Vmess 节点: WebSocket 缺少 path")
                return None
        
        fingerprint = get_vmess_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 Vmess 节点: 解析错误 {str(e)}")
        return None

def parse_vless(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("vless://"):
            skipped_links += 1
            print(f"跳过无效 Vless URI: {uri[:30]}...")
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if not (parsed.username and parsed.hostname and parsed.port):
            skipped_links += 1
            print(f"跳过 Vless 节点: 缺少 uuid, server 或 port")
            return None
        
        try:
            port = int(parsed.port)
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 Vless 节点: 无效端口 {parsed.port}")
            return None
        
        uuid = parsed.username
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uuid, re.I):
            skipped_links += 1
            print(f"跳过 Vless 节点: 无效 UUID {uuid}")
            return None
        
        network = params.get('type', ['tcp'])[0]
        if network not in ["tcp", "ws", "http", "grpc"]:
            skipped_links += 1
            print(f"跳过 Vless 节点: 无效网络类型 {network}")
            return None
        
        security = params.get('security', ['none'])[0]
        tls = security == 'tls'
        
        node = {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Vless Node",
            "type": "vless",
            "server": parsed.hostname,
            "port": port,
            "uuid": uuid,
            "network": network,
            "tls": tls
        }
        
        if tls:
            node["servername"] = params.get('sni', [parsed.hostname])[0]
            if not node["servername"]:
                skipped_links += 1
                print(f"跳过 Vless 节点: TLS 启用但缺少 servername")
                return None
            node["flow"] = params.get('flow', [''])[0]
        
        if network == 'ws':
            node['ws-opts'] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [parsed.hostname])[0]}
            }
            if not node['ws-opts']['path']:
                skipped_links += 1
                print(f"跳过 Vless 节点: WebSocket 缺少 path")
                return None
        
        fingerprint = get_vless_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 Vless 节点: 解析错误 {str(e)}")
        return None

def parse_ss(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("ss://"):
            skipped_links += 1
            print(f"跳过无效 SS URI: {uri[:30]}...")
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        
        if not (parsed.hostname and parsed.port and '@' in uri):
            skipped_links += 1
            print(f"跳过 SS 节点: 缺少 cipher, password, server 或 port")
            return None
        
        try:
            port = int(parsed.port)
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 SS 节点: 无效端口 {parsed.port}")
            return None
        
        core_part = parsed.netloc.split('@')[0]
        decoded_core = base64.b64decode(core_part + '=' * (-len(core_part) % 4)).decode('utf-8')
        parts = decoded_core.split(':', 1)
        if len(parts) != 2:
            skipped_links += 1
            print(f"跳过 SS 节点: 无效 cipher:password 格式")
            return None
        
        cipher, password = parts
        
        if cipher not in SS_SUPPORTED_CIPHERS:
            skipped_links += 1
            print(f"跳过 SS 节点: 不支持的加密方法 {cipher}")
            return None
        
        node = {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node",
            "type": "ss",
            "server": parsed.hostname,
            "port": port,
            "cipher": cipher,
            "password": password
        }
        
        fingerprint = get_ss_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 SS 节点: 解析错误 {str(e)}")
        return None

def parse_ssr(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("ssr://"):
            skipped_links += 1
            print(f"跳过无效 SSR URI: {uri[:30]}...")
            return None
        uri_part = uri[6:].replace('<br/>', '').replace('\n', '').strip()
        
        decoded_data = base64.b64decode(uri_part + '=' * (-len(uri_part) % 4)).decode('utf-8') if is_base64(uri_part) else uri_part
        
        if '/?' not in decoded_data:
            main_part = decoded_data
            params = {}
        else:
            main_part, params_part = decoded_data.split('/?', 1)
            params = parse_qs(params_part)
        
        parts = main_part.split(':')
        if len(parts) < 6:
            skipped_links += 1
            print(f"跳过 SSR 节点: 缺少必需参数")
            return None
        
        server, port_str, protocol, cipher, obfs, password_encoded = parts[:6]
        
        try:
            port = int(port_str)
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 SSR 节点: 无效端口 {port_str}")
            return None
        
        try:
            password = base64.b64decode(password_encoded + '=' * (-len(password_encoded) % 4)).decode('utf-8')
        except Exception:
            skipped_links += 1
            print(f"跳过 SSR 节点: 无效密码编码")
            return None
        
        if cipher not in SSR_SUPPORTED_CIPHERS or protocol not in SSR_SUPPORTED_PROTOCOLS or obfs not in SSR_SUPPORTED_OBFS:
            skipped_links += 1
            print(f"跳过 SSR 节点: 不支持的 cipher={cipher}, protocol={protocol}, 或 obfs={obfs}")
            return None
        
        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = base64.b64decode(obfs_param_encoded + '=' * (-len(obfs_param_encoded) % 4)).decode('utf-8') if obfs_param_encoded else ""
        
        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = base64.b64decode(protocol_param_encoded + '=' * (-len(protocol_param_encoded) % 4)).decode('utf-8') if protocol_param_encoded else ""
        
        remarks_encoded = params.get('remarks', [''])[0]
        name = base64.b64decode(remarks_encoded + '=' * (-len(remarks_encoded) % 4)).decode('utf-8') if remarks_encoded else "Unnamed SSR Node"
        
        node = {
            "name": name,
            "type": "ssr",
            "server": server,
            "port": port,
            "password": password,
            "cipher": cipher,
            "protocol": protocol,
            "obfs": obfs,
            "obfs-param": obfs_param,
            "protocol-param": protocol_param
        }
        
        fingerprint = get_ssr_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 SSR 节点: 解析错误 {str(e)}")
        return None

def parse_trojan(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("trojan://"):
            skipped_links += 1
            print(f"跳过无效 Trojan URI: {uri[:30]}...")
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if not (parsed.username and parsed.hostname and parsed.port):
            skipped_links += 1
            print(f"跳过 Trojan 节点: 缺少 password, server 或 port")
            return None
        
        try:
            port = int(parsed.port)
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 Trojan 节点: 无效端口 {parsed.port}")
            return None
        
        network = params.get("type", ["tcp"])[0]
        if network not in ["tcp", "grpc"]:
            skipped_links += 1
            print(f"跳过 Trojan 节点: 无效网络类型 {network}")
            return None
        
        node = {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node",
            "type": "trojan",
            "server": parsed.hostname,
            "port": port,
            "password": parsed.username,
            "network": network,
            "sni": params.get("sni", [parsed.hostname])[0]
        }
        
        if not node["sni"]:
            skipped_links += 1
            print(f"跳过 Trojan 节点: 缺少 sni")
            return None
        
        if network == "grpc":
            node["grpc-opts"] = {"serviceName": params.get('serviceName', [''])[0]}
            if not node["grpc-opts"]["serviceName"]:
                skipped_links += 1
                print(f"跳过 Trojan 节点: gRPC 缺少 serviceName")
                return None
        
        fingerprint = get_trojan_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 Trojan 节点: 解析错误 {str(e)}")
        return None

def parse_hysteria2(uri):
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("hysteria2://"):
            skipped_links += 1
            print(f"跳过无效 Hysteria2 URI: {uri[:30]}...")
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        
        if not (parsed.username and parsed.hostname and parsed.port):
            skipped_links += 1
            print(f"跳过 Hysteria2 节点: 缺少 password, server 或 port")
            return None
        
        try:
            port = int(parsed.port)
            if not (1 <= port <= 65535): raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            print(f"跳过 Hysteria2 节点: 无效端口 {parsed.port}")
            return None
        
        obfs = params.get('obfs', ['none'])[0]
        if obfs not in HYSTERIA2_SUPPORTED_OBFS:
            skipped_links += 1
            print(f"跳过 Hysteria2 节点: 无效 obfs 类型 {obfs}")
            return None
        
        password = parsed.username
        if not password:
            skipped_links += 1
            print(f"跳过 Hysteria2 节点: 缺少 password")
            return None
        
        sni = params.get('sni', [parsed.hostname])[0]
        if not sni:
            skipped_links += 1
            print(f"跳过 Hysteria2 节点: 缺少 sni")
            return None
        
        node = {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node",
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": port,
            "password": password,
            "obfs": obfs,
            "sni": sni
        }
        
        obfs_password = params.get('obfs-password', [''])[0]
        # 修复逻辑：只有当obfs不是none时，才添加obfs-password字段
        if obfs != "none":
            if not obfs_password:
                skipped_links += 1
                print(f"跳过 Hysteria2 节点: obfs={obfs} 但缺少或为空 obfs-password, URI: {uri[:50]}...")
                return None
            node["obfs-password"] = obfs_password

        fingerprint = get_hysteria2_fingerprint(node)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return node
    except Exception as e:
        skipped_links += 1
        print(f"跳过 Hysteria2 节点: 解析错误 {str(e)}, URI: {uri[:50]}...")
        return None

def get_country_name(host, reader):
    try:
        ip_address = socket.gethostbyname(host)
        response = reader.country(ip_address)
        return response.country.iso_code
    except (socket.gaierror, geoip2.errors.AddressNotFoundError):
        return None
    except Exception as e:
        print(f"错误：查询 IP {host} 时出错：{e}")
        return None

def download_url(url, timeout=(15, 60)):
    headers = {
        'User-Agent': 'ClashforWindows/0.20.25'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout, stream=True)
        response.raise_for_status()
        
        content_chunks = []
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                content_chunks.append(chunk)
        
        return b''.join(content_chunks)
    except requests.exceptions.Timeout:
        print(f"警告：下载 {url} 超时。")
    except requests.exceptions.ConnectionError:
        print(f"警告：连接到 {url} 失败。")
    except requests.exceptions.RequestException as e:
        print(f"警告：下载 {url} 时发生错误: {e}")
    return None

def download_and_parse_url(url):
    global total_links, successful_nodes, skipped_links, duplicate_links
    content_bytes = download_url(url)
    if not content_bytes:
        return []
    
    all_nodes = []
    
    try:
        try:
            decoded_content = base64.b64decode(content_bytes).decode('utf-8')
            lines = decoded_content.strip().split('\n')
        except (base64.binascii.Error, UnicodeDecodeError): # 修复：将 UnicodeDecode1Error 更改为 UnicodeDecodeError
            decoded_content = content_bytes.decode('utf-8', errors='ignore')
            lines = decoded_content.strip().split('\n')

        total_links += len(lines)

        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            node_type = line.split('://')[0]
            node = None
            if node_type == 'vmess': node = parse_vmess(line)
            elif node_type == 'vless': node = parse_vless(line)
            elif node_type == 'ss': node = parse_ss(line)
            elif node_type == 'ssr': node = parse_ssr(line)
            elif node_type == 'trojan': node = parse_trojan(line)
            elif node_type == 'hysteria2': node = parse_hysteria2(line)
            else:
                print(f"跳过未知协议节点: {line[:30]}...")
                skipped_links += 1
            
            if node and node != "duplicate":
                all_nodes.append(node)
            
    except Exception as e:
        skipped_links += 1
        print(f"错误：解析订阅 {url} 时发生错误: {e}")
    
    return all_nodes

def process_node_with_location(node_and_reader):
    node, reader = node_and_reader
    host = node.get('server')
    country_code = None
    if reader and host:
        country_code = get_country_name(host, reader)
    
    base_name = f"[{country_code}]" if country_code else "Unnamed Node"
    
    node['name'] = normalize_name(base_name)
    return node

def write_to_yaml(nodes, filename='config.yaml'):
    """将节点列表和 Clash 配置写入 YAML 文件。"""
    config_data = {
        "#": f"Generated by Node Converter at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "proxies": nodes,
        "proxy-groups": [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": [p["name"] for p in nodes]
            }
        ],
        "rules": [
            "MATCH,Proxy"
        ]
    }
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config_data, f, allow_unicode=True, sort_keys=False)

def main():
    global total_links, successful_nodes, skipped_links, duplicate_links, used_names, used_node_fingerprints
    
    sources_str = os.environ.get('SOURCES')
    if not sources_str:
        print("错误：未找到环境变量 'SOURCES'。")
        sys.exit(1)

    sources = [s.strip() for s in sources_str.split(',') if s.strip()]
    if not sources:
        print("错误：'SOURCES' 环境变量为空。")
        sys.exit(1)

    all_nodes = []
    
    used_names.clear()
    used_node_fingerprints.clear()
    total_links = 0
    successful_nodes = 0
    skipped_links = 0
    duplicate_links = 0

    print("--- 启动节点转换工具 ---")
    print(f"将处理 {len(sources)} 个来源。")

    for source_url in tqdm(sources, desc="下载并解析订阅链接"):
        downloaded_nodes = download_and_parse_url(source_url)
        all_nodes.extend(downloaded_nodes)

    if not all_nodes:
        print("\n没有找到任何节点，无法生成配置文件。")
        sys.exit(1)
        
    print("\n--- 正在使用 GeoLite2-Country.mmdb 进行节点地理位置查询和重命名（多线程）---")
    try:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
    except Exception as e:
        print(f"错误：加载 GeoLite2-Country.mmdb 失败：{e}")
        print("将使用原始节点名称。")
        reader = None

    final_nodes = []
    
    if reader:
        with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            future_to_node = {executor.submit(process_node_with_location, (node, reader)): node for node in all_nodes}
            for future in tqdm(as_completed(future_to_node), total=len(all_nodes), desc="处理节点"):
                result_node = future.result()
                if result_node:
                    final_nodes.append(result_node)
    else:
        for node in all_nodes:
            node['name'] = normalize_name(node.get('name', 'Unnamed Node'))
            final_nodes.append(node)

    if final_nodes:
        write_to_yaml(final_nodes)
        print("\n" + "="*40)
        print("✅ 转换完成！")
        print(f"📝 成功转换并去重后节点数量: {len(final_nodes)}")
        print(f"🔄 因节点内容重复被跳过数量: {duplicate_links}")
        print(f"❌ 解析失败或不符合格式的行数: {skipped_links}")
        print(f"📊 总计处理行数: {total_links}")
        print("📄 配置文件已保存到 config.yaml")
        print("="*40)
    else:
        print("\n" + "="*40)
        print("⚠️ 未找到任何有效节点，未生成配置文件。")
        print("="*40)

if __name__ == "__main__":
    main()
