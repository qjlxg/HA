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

# 全局集合用于去重
used_names = set()
used_node_fingerprints = set()

# 全局计数器
total_links = 0
successful_nodes = 0
skipped_links = 0
duplicate_links = 0

# 支持的 Shadowsocks 加密方法列表
SS_SUPPORTED_CIPHERS = [
    "aes-256-gcm", "aes-192-gcm", "aes-128-gcm",
    "aes-256-cfb", "aes-192-cfb", "aes-128-cfb",
    "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "xchacha20",
    "aes-256-ctr", "aes-192-ctr", "aes-128-ctr",
    "camellia-256-cfb", "camellia-192-cfb", "camellia-128-cfb",
    "rc4-md5",
    "chacha20-ietf"
]

# 为 ShadowsocksR 单独定义支持的加密方法
SSR_SUPPORTED_CIPHERS = [
    "auth_aes128_md5", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d"
]

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
        # 使用 us_01, us_02 格式
        # 匹配方括号内的国家代码，例如 "[US]"
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
    """为 Vmess 节点生成唯一指纹，用于去重。
    - 只使用核心参数：uuid, server, port, network, tls, servername
    """
    tls = data.get('tls', False)
    network = data.get('network', 'tcp')
    servername = data.get('servername')
    
    # 增加对 ws-opts headers.Host 的处理
    if network == 'ws':
        ws_opts = data.get('ws-opts', {})
        host_header = ws_opts.get('headers', {}).get('Host')
        servername = host_header if host_header else servername

    return (
        data.get("type", "vmess"),
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        network,
        tls,
        servername
    )

def get_vless_fingerprint(data):
    """为 Vless 节点生成唯一指纹，用于去重。
    - 只使用核心参数：uuid, server, port, network, tls, servername
    """
    tls = data.get('tls', False)
    network = data.get('network', 'tcp')
    servername = data.get('servername', data.get('server'))
    
    # 增加对 ws-opts headers.Host 的处理
    if network == 'ws':
        ws_opts = data.get('ws-opts', {})
        host_header = ws_opts.get('headers', {}).get('Host')
        servername = host_header if host_header else servername

    return (
        "vless",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        network,
        tls,
        servername
    )

def get_ss_fingerprint(data):
    """为 Shadowsocks 节点生成唯一指纹，用于去重。
    - 只使用核心参数：server, port, cipher, password
    """
    return (
        "ss",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("cipher"),
        data.get("password")
    )

def get_trojan_fingerprint(data):
    """为 Trojan 节点生成唯一指纹，用于去重。
    - 只使用核心参数：server, port, password, sni, network
    """
    return (
        "trojan",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("password"),
        data.get("sni", data.get("server")),
        data.get("network", "tcp")
    )
    
def get_ssr_fingerprint(data):
    """为 ShadowsocksR 节点生成唯一指纹，用于去重。
    - 只使用核心参数：server, port, cipher, password, protocol, obfs
    """
    return (
        "ssr",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("cipher"),
        data.get("password"),
        data.get("protocol"),
        data.get("obfs")
    )
    
def get_hysteria2_fingerprint(data):
    """为 Hysteria2 节点生成唯一指纹，用于去重。
    - 只使用核心参数：server, port, password, obfs, obfs-password, sni
    """
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
# 原始解析函数，未修改
# ====================

def parse_vmess(uri):
    """
    严格解析 Vmess 链接。
    - 检查必需参数：'add' (server), 'port', 'id' (uuid)。
    - 检查 'port' 是否为有效数字。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("vmess://"):
            skipped_links += 1
            return None
        encoded_data = uri[8:]
        encoded_data = encoded_data.replace('<br/>', '').replace('\n', '').strip()
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        
        # ⚠️ 严格模式：检查必需参数
        required_keys = ["add", "port", "id"]
        if not all(key in data for key in required_keys):
            skipped_links += 1
            return None
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(data.get("port"))
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        node_data = {
            "type": "vmess",
            "server": data.get("add"),
            "port": port,
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": data.get("net", "tcp")
        }
        
        fingerprint = get_vmess_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        node = {
            "name": data.get("ps", "Unnamed Vmess Node"),
            "type": "vmess",
            "server": data.get("add"),
            "port": port,
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": data.get("net", "tcp")
        }
        
        if data.get("tls", "") == "tls":
            node["tls"] = True
            if "sni" in data:
                node["servername"] = data["sni"]

        if node["network"] == "ws":
            node["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", node["server"])}
            }
        
        successful_nodes += 1
        return node
    except Exception:
        skipped_links += 1
        return None

def parse_vless(uri):
    """
    严格解析 Vless 链接。
    - 检查必需参数：'hostname', 'port', 'username' (uuid)。
    - 检查 'port' 是否为有效数字。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("vless://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        # ⚠️ 严格模式：检查必需参数
        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(parsed.port)
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        node_data = {
            "type": "vless",
            "server": parsed.hostname,
            "port": port,
            "uuid": parsed.username,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', [''])[0] == 'tls',
            "servername": params.get('sni', [parsed.hostname])[0]
        }
        fingerprint = get_vless_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        vless_node = {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Vless Node",
            "type": "vless",
            "server": parsed.hostname,
            "port": port,
            "uuid": parsed.username,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', [''])[0] == 'tls'
        }
        if vless_node['network'] == 'ws':
            vless_node['ws-opts'] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [parsed.hostname])[0]}
            }
        if vless_node['tls']:
            vless_node['servername'] = params.get('sni', [parsed.hostname])[0]
            vless_node['flow'] = params.get('flow', [''])[0]
            vless_node['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'
        
        successful_nodes += 1
        return vless_node
    except Exception:
        skipped_links += 1
        return None

def parse_ss(uri):
    """
    严格解析 ShadowSocks 链接。
    - 检查必需参数：'hostname', 'port'。
    - 检查链接中的 'method' 和 'password' 是否存在。
    - 检查 'port' 是否为有效数字。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("ss://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        
        # ⚠️ 严格模式：检查必需参数
        if not all([parsed.hostname, parsed.port, '@' in uri]):
            skipped_links += 1
            return None
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(parsed.port)
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        core_part = parsed.netloc.split('@')[0]
        decoded_core = None
        try:
            decoded_core = base64.b64decode(core_part + '=' * (-len(core_part) % 4)).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            skipped_links += 1
            return None

        parts = decoded_core.split(':', 1)
        if len(parts) != 2:
            skipped_links += 1
            return None

        method, password = parts
        
        # 严格模式：检查 method 是否在支持列表中
        if method.lower() not in SS_SUPPORTED_CIPHERS:
            skipped_links += 1
            return None

        node_data = {"type": "ss", "server": parsed.hostname, "port": port, "cipher": method, "password": password}
        fingerprint = get_ss_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node",
            "type": "ss",
            "server": parsed.hostname,
            "port": port,
            "cipher": method,
            "password": password
        }
    except Exception:
        skipped_links += 1
        return None

def parse_ssr(uri):
    """
    严格解析 ShadowsocksR 链接。
    - 检查必需参数：server, port, protocol, method, obfs, password。
    - 检查 'port' 是否为有效数字。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("ssr://"):
            skipped_links += 1
            return None
        uri_part = uri[6:].replace('<br/>', '').replace('\n', '').strip()
        
        if is_base64(uri_part):
            decoded_data = base64.b64decode(uri_part + '=' * (-len(uri_part) % 4)).decode('utf-8')
        else:
            decoded_data = uri_part

        if '/?' not in decoded_data:
            main_part = decoded_data
            params = {}
        else:
            main_part, params_part = decoded_data.split('/?', 1)
            params = parse_qs(params_part)

        parts = main_part.split(':')
        
        # ⚠️ 严格模式：检查必需参数
        if len(parts) < 6:
            skipped_links += 1
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(port)
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        # 严格模式：检查密码是否有效
        try:
            password_decoded = base64.b64decode(password + '=' * (-len(password) % 4)).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            skipped_links += 1
            return None
        
        remarks_encoded = params.get('remarks', [''])[0]
        
        node_data = {
            "type": "ssr",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password_decoded,
            "protocol": protocol,
            "obfs": obfs
        }
        fingerprint = get_ssr_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)

        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = base64.b64decode(obfs_param_encoded + '=' * (-len(obfs_param_encoded) % 4)).decode('utf-8') if obfs_param_encoded else ""
        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = base64.b64decode(protocol_param_encoded + '=' * (-len(protocol_param_encoded) % 4)).decode('utf-8') if protocol_param_encoded else ""
        
        successful_nodes += 1
        return {
            "name": unquote(base64.b64decode(remarks_encoded + '=' * (-len(remarks_encoded) % 4)).decode('utf-8')) if remarks_encoded else "Unnamed SSR Node",
            "type": "ssr",
            "server": server,
            "port": port,
            "password": password_decoded,
            "cipher": method,
            "protocol": protocol,
            "obfs": obfs,
            "obfs-param": obfs_param,
            "protocol-param": protocol_param
        }
    except Exception as e:
        skipped_links += 1
        return None

def parse_trojan(uri):
    """
    严格解析 Trojan 链接。
    - 检查必需参数：'hostname', 'port', 'username' (password)。
    - 检查 'port' 是否为有效数字。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("trojan://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        # ⚠️ 严格模式：检查必需参数
        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(parsed.port)
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        node_data = {
            "type": "trojan",
            "server": parsed.hostname,
            "port": port,
            "password": parsed.username,
            "sni": params.get("sni", [parsed.hostname])[0]
        }
        fingerprint = get_trojan_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node",
            "type": "trojan",
            "server": parsed.hostname,
            "port": port,
            "password": parsed.username,
            "network": params.get("type", ["tcp"])[0],
            "sni": params.get("sni", [parsed.hostname])[0],
            "skip-cert-verify": params.get('allowInsecure', ['0'])[0] == '1',
            "grpc-opts": {
                "serviceName": params.get('serviceName', [''])[0]
            } if params.get('type', [''])[0] == 'grpc' else None
        }
    except Exception:
        skipped_links += 1
        return None

def parse_hysteria2(uri):
    """
    严格解析 Hysteria2 链接。
    - 检查必需参数：'hostname', 'port', 'username' (password)。
    - 检查 'port' 是否为有效数字。
    - 如果 'obfs' 存在且不为 'none'，则强制要求 'obfs-password'。
    - 如果缺少任何必需参数或格式不正确，直接返回 None。
    """
    global successful_nodes, duplicate_links, skipped_links
    try:
        if not uri.startswith("hysteria2://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        
        # ⚠️ 严格模式：检查必需参数
        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        
        # 严格模式：检查端口是否为有效数字
        try:
            port = int(parsed.port)
            if port <= 0 or port > 65535: raise ValueError
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        params = parse_qs(parsed.query)
        password = parsed.username
        obfs_type = params.get('obfs', ['none'])[0]
        obfs_password = params.get('obfs-password', [''])[0]
        
        # ⚠️ 严格模式：强制检查 obfs-password
        if obfs_type != "none" and not obfs_password:
            skipped_links += 1
            return None
        
        node_data = {
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": port,
            "password": password,
            "obfs": obfs_type,
            "obfs-password": obfs_password,
            "sni": params.get('sni', [parsed.hostname])[0]
        }
        fingerprint = get_hysteria2_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        successful_nodes += 1
        return {
            "name": unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node",
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": port,
            "password": password,
            "obfs": obfs_type,
            "obfs-password": obfs_password,
            "sni": params.get('sni', [parsed.hostname])[0]
        }
    except Exception:
        skipped_links += 1
        return None

# 以下代码保持原样，未进行修改
def get_country_name(host, reader):
    """
    使用 geoip2 获取给定 IP 地址或域名的国家/地区 ISO 代码。
    """
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
    """
    下载 URL 内容，并使用流式处理以应对大文件。
    返回原始内容的二进制数据或 None。
    """
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
    """下载并解析 URL 内容中的节点。"""
    
    global total_links
    content_bytes = download_url(url)
    if not content_bytes:
        return []
    
    all_nodes = []
    
    try:
        try:
            decoded_content = base64.b64decode(content_bytes).decode('utf-8')
            lines = decoded_content.strip().split('\n')
        except (base64.binascii.Error, UnicodeDecodeError):
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
            
            if node and node != "duplicate":
                all_nodes.append(node)
            
    except Exception as e:
        print(f"错误：解析订阅 {url} 时发生错误: {e}")
    
    return all_nodes

def process_node_with_location(node_and_reader):
    node, reader = node_and_reader
    host = node.get('server')
    country_code = None
    if reader and host:
        country_code = get_country_name(host, reader)
    
    # 确定用于重命名的基础名称
    base_name = f"[{country_code}]" if country_code else "Unnamed Node"
    
    # 规范化并重新命名节点
    node['name'] = normalize_name(base_name)
    return node

def write_to_yaml(nodes, filename='config.yaml'):
    """将节点列表和 Clash 配置写入 YAML 文件。"""
    config_data = {
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
    """主函数，负责执行整个工作流。"""
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
    
    # 重置全局状态
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
    
    # 使用多线程加速地理位置查询
    if reader:
        with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            future_to_node = {executor.submit(process_node_with_location, (node, reader)): node for node in all_nodes}
            for future in tqdm(as_completed(future_to_node), total=len(all_nodes), desc="处理节点"):
                result_node = future.result()
                if result_node:
                    final_nodes.append(result_node)
    else:
        # 如果没有 reader，则跳过多线程处理
        for node in all_nodes:
            # 在没有地理位置信息时，仍调用 normalize_name 进行去重和名称规范化
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
