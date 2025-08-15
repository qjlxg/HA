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
successful_links = 0
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
        truncated_name = f"{original_name}-{counter}"
        counter += 1
    used_names.add(truncated_name)
    return truncated_name

def get_vmess_fingerprint(data):
    """为 Vmess 节点生成唯一指纹，用于去重。"""
    return (
        data.get("type", "vmess"),
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        int(data.get("alterId", 0)),
        data.get("network", "tcp")
    )

def get_vless_fingerprint(data):
    """为 Vless 节点生成唯一指纹，用于去重。"""
    return (
        "vless",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("uuid"),
        data.get('network', 'tcp'),
        data.get('tls', False),
        data.get('servername', data.get('server'))
    )

def get_ss_fingerprint(data):
    """为 Shadowsocks 节点生成唯一指纹，用于去重。"""
    return (
        "ss",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("cipher"),
        data.get("password")
    )

def get_trojan_fingerprint(data):
    """为 Trojan 节点生成唯一指纹，用于去重。"""
    return (
        "trojan",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("password"),
        data.get("sni", data.get("server"))
    )
    
def get_ssr_fingerprint(data):
    """为 ShadowsocksR 节点生成唯一指纹，用于去重。"""
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
    """为 Hysteria2 节点生成唯一指纹，用于去重。"""
    return (
        "hysteria2",
        data.get("server"),
        int(data.get("port", 0)),
        data.get("password"),
        data.get("obfs", "none"),
        data.get("sni", data.get("server"))
    )

def parse_vmess(uri):
    """解析 Vmess 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
    try:
        if not uri.startswith("vmess://"):
            skipped_links += 1
            return None
        encoded_data = uri[8:]
        encoded_data = encoded_data.replace('<br/>', '').replace('\n', '').strip()
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        
        if not isinstance(data, dict):
            skipped_links += 1
            return None
        if not all(key in data for key in ["add", "port", "id"]):
            skipped_links += 1
            return None
        
        try: port = int(data.get("port"))
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
        
        name = normalize_name(data.get("ps", "Unnamed Vmess Node"))
        node = {
            "name": name,
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
        
        successful_links += 1
        return node
    except Exception:
        skipped_links += 1
        return None

def parse_vless(uri):
    """解析 Vless 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
    try:
        if not uri.startswith("vless://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        try: port = int(parsed.port)
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
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Vless Node")
        vless_node = {
            "name": name,
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
        
        successful_links += 1
        return vless_node
    except Exception:
        skipped_links += 1
        return None

def parse_ss(uri):
    """解析 ShadowSocks 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
    try:
        if not uri.startswith("ss://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        if '@' not in uri:
            skipped_links += 1
            return None
        if not all([parsed.hostname, parsed.port]):
            skipped_links += 1
            return None
        try: port = int(parsed.port)
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
        
        if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', method):
            skipped_links += 1
            return None
        
        if method.lower() not in SS_SUPPORTED_CIPHERS:
            skipped_links += 1
            return None

        node_data = {"type": "ss", "server": parsed.hostname, "port": port, "cipher": method, "password": password}
        fingerprint = get_ss_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node")
        
        successful_links += 1
        return {
            "name": name,
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
    """解析 ShadowsocksR 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
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
        if len(parts) < 6:
            skipped_links += 1
            return None
        server, port, protocol, method, obfs, password = parts[:6]

        try: port = int(port)
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        
        password_decoded = base64.b64decode(password + '=' * (-len(password) % 4)).decode('utf-8')
        
        remarks_encoded = params.get('remarks', [''])[0]
        name = normalize_name(unquote(base64.b64decode(remarks_encoded + '=' * (-len(remarks_encoded) % 4)).decode('utf-8')) if remarks_encoded else "Unnamed SSR Node")

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
        
        successful_links += 1
        return {
            "name": name,
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
    """解析 Trojan 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
    try:
        if not uri.startswith("trojan://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        try: port = int(parsed.port)
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
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node")
        
        successful_links += 1
        return {
            "name": name,
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
    """解析 Hysteria2 链接，返回节点配置字典或 None。"""
    global successful_links, duplicate_links, skipped_links
    try:
        if not uri.startswith("hysteria2://"):
            skipped_links += 1
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        if not all([parsed.hostname, parsed.port, parsed.username]):
            skipped_links += 1
            return None
        try: port = int(parsed.port)
        except (ValueError, TypeError):
            skipped_links += 1
            return None
        params = parse_qs(parsed.query)
        password = parsed.username
        
        node_data = {
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": port,
            "password": password,
            "obfs": params.get('obfs', ['none'])[0],
            "sni": params.get('sni', [parsed.hostname])[0]
        }
        fingerprint = get_hysteria2_fingerprint(node_data)
        if fingerprint in used_node_fingerprints:
            duplicate_links += 1
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node")
        
        successful_links += 1
        return {
            "name": name,
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": port,
            "password": password,
            "obfs": params.get('obfs', ['none'])[0],
            "obfs-password": params.get('obfs-password', [''])[0],
            "sni": params.get('sni', [parsed.hostname])[0]
        }
    except Exception:
        skipped_links += 1
        return None
    
def get_location_info(server):
    """根据 IP 地址获取地理位置信息。"""
    try:
        ip = socket.gethostbyname(server)
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
            country = response.country.names.get('zh-CN', response.country.name)
            city = response.city.names.get('zh-CN', response.city.name)
            return f"[{country}-{city}]"
    except Exception:
        return "[Unknown]"

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

def process_and_combine_nodes(nodes, max_workers=50):
    """使用多线程处理节点并合并。"""
    processed_nodes = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {executor.submit(add_node_details, node): node for node in nodes}
        for future in tqdm(as_completed(future_to_node), total=len(nodes), desc="处理节点"):
            node = future_to_node[future]
            try:
                result = future.result()
                if result:
                    processed_nodes.append(result)
            except Exception as e:
                print(f"处理节点 {node.get('name', 'N/A')} 时发生错误: {e}")

    return processed_nodes

def add_node_details(node):
    """为单个节点添加额外信息，如地理位置。"""
    if node:
        name_prefix = get_location_info(node['server'])
        node['name'] = f"{name_prefix}{node['name']}"
        return node
    return None

def write_to_yaml(nodes, filename='config.yaml'):
    """将节点列表写入 YAML 文件。"""
    config = {
        'proxies': nodes
    }
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config, f, allow_unicode=True)

def main():
    """主函数，负责执行整个工作流。"""
    global total_links, successful_links, skipped_links, duplicate_links
    
    sources_str = os.environ.get('SOURCES')
    if not sources_str:
        print("错误：未找到环境变量 'SOURCES'。")
        sys.exit(1)

    sources = [s.strip() for s in sources_str.split(',') if s.strip()]
    if not sources:
        print("错误：'SOURCES' 环境变量为空。")
        sys.exit(1)

    all_nodes = []
    for source_url in tqdm(sources, desc="下载并解析订阅链接"):
        all_nodes.extend(download_and_parse_url(source_url))

    if not all_nodes:
        print("\n没有找到任何节点，无法生成配置文件。")
        sys.exit(1)
        
    final_nodes = process_and_combine_nodes(all_nodes)
    
    if final_nodes:
        write_to_yaml(final_nodes)
        print("\n--- 脚本执行完成，生成报告 ---")
        print(f"总链接数: {total_links}")
        print(f"成功解析的节点数: {successful_links}")
        print(f"因重复而跳过的节点数: {duplicate_links}")
        print(f"因格式错误而跳过的链接数: {skipped_links}")
        print(f"最终写入 config.yaml 的节点数: {len(final_nodes)}")
        print("-------------------------------")
    else:
        print("\n没有可用的有效节点来生成配置文件。")

if __name__ == "__main__":
    main()
