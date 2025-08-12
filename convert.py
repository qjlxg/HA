import os
import re
import yaml
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
from tqdm import tqdm

# 全局变量用于存储已使用的节点名称和节点指纹，以便去重
used_names = set()
used_node_fingerprints = set()

# 支持的 ShadowSocks 和 ShadowsocksR 加密方法列表
SS_SUPPORTED_CIPHERS = [
    "aes-256-gcm", "aes-192-gcm", "aes-128-gcm",
    "aes-256-cfb", "aes-192-cfb", "aes-128-cfb",
    "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "xchacha20",
    "aes-256-ctr", "aes-192-ctr", "aes-128-ctr",
    "camellia-256-cfb", "camellia-192-cfb", "camellia-128-cfb",
]

def normalize_name(name):
    """
    规范化节点名称：
    1. 移除表情符号和特殊字符
    2. 保留前3个字符
    3. 如果名称重复，添加序号
    """
    name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
    name = name.replace('<br/>', '').replace('\n', '').strip()
    name = re.sub(r'[^\u4e00-\u9fa5\w\s-]', '', name)
    name = re.sub(r'\s+', ' ', name).strip()
    
    # 保留前3个字符
    truncated_name = name[:3] if len(name) >= 3 else name
    
    original_name = truncated_name
    counter = 1
    while truncated_name in used_names:
        truncated_name = f"{original_name}-{counter}"
        counter += 1
    used_names.add(truncated_name)
    return truncated_name

def get_vmess_fingerprint(data):
    """为 Vmess 节点生成唯一指纹"""
    return (
        data.get("type", "vmess"),
        data.get("add"),
        int(data.get("port", 0)),
        data.get("id"),
        int(data.get("aid", 0)),
        data.get("net", "tcp")
    )

def get_vless_fingerprint(parsed, params):
    """为 Vless 节点生成唯一指纹"""
    return (
        "vless",
        parsed.hostname,
        parsed.port,
        parsed.username,
        params.get('type', ['tcp'])[0],
        params.get('security', [''])[0],
        params.get('sni', [parsed.hostname])[0]
    )

def get_ss_fingerprint(parsed, method, password):
    """为 ShadowSocks 节点生成唯一指纹"""
    return (
        "ss",
        parsed.hostname,
        parsed.port,
        method,
        password
    )

def get_trojan_fingerprint(parsed, params):
    """为 Trojan 节点生成唯一指纹"""
    return (
        "trojan",
        parsed.hostname,
        parsed.port,
        parsed.username,
        params.get("sni", [parsed.hostname])[0]
    )
    
def get_ssr_fingerprint(server, port, method, password, protocol, obfs):
    """为 ShadowsocksR 节点生成唯一指纹"""
    return (
        "ssr",
        server,
        int(port),
        method,
        password,
        protocol,
        obfs
    )
    
def get_hysteria2_fingerprint(parsed, params):
    """为 Hysteria2 节点生成唯一指纹"""
    return (
        "hysteria2",
        parsed.hostname,
        parsed.port,
        parsed.username,
        params.get("obfs", ["none"])[0],
        params.get("sni", [parsed.hostname])[0]
    )

def parse_vmess(uri):
    """解析 Vmess 节点"""
    try:
        if not uri.startswith("vmess://"):
            return None
        encoded_data = uri[8:]
        encoded_data = encoded_data.replace('<br/>', '').replace('\n', '').strip()
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        
        if not isinstance(data, dict):
            return None

        # 检查关键字段
        if not all(key in data for key in ["add", "port", "id"]):
            return None

        fingerprint = get_vmess_fingerprint(data)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(data.get("ps", "Unnamed Vmess Node"))
        server = data.get("add")
        port = int(data.get("port"))
        uuid = data.get("id")
        alterId = int(data.get("aid", 0))
        cipher = data.get("scy", "auto")
        tls = data.get("tls", "") == "tls"
        network = data.get("net", "tcp")
        
        node = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": alterId,
            "cipher": cipher,
            "tls": tls,
            "network": network,
        }
        
        if network == "ws":
            node["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {
                    "Host": data.get("host", server)
                }
            }
        if tls and "sni" in data:
            node["servername"] = data["sni"]
        
        return node
    except Exception:
        return None

def parse_vless(uri):
    """解析 Vless 节点"""
    try:
        if not uri.startswith("vless://"):
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        # 检查关键字段
        if not all([parsed.hostname, parsed.port, parsed.username]):
            return None

        fingerprint = get_vless_fingerprint(parsed, params)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Vless Node")
        
        vless_node = {
            "name": name,
            "type": "vless",
            "server": parsed.hostname,
            "port": parsed.port,
            "uuid": parsed.username,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', [''])[0] == 'tls'
        }

        if vless_node['network'] == 'ws':
            vless_node['ws-opts'] = {
                "path": params.get("path", ["/"])[0],
                "headers": {
                    "Host": params.get("host", [parsed.hostname])[0]
                }
            }
        
        if vless_node['tls']:
            vless_node['servername'] = params.get('sni', [parsed.hostname])[0]
            vless_node['flow'] = params.get('flow', [''])[0]
            vless_node['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'
        
        return vless_node
    except Exception:
        return None

def parse_ss(uri):
    """解析 ShadowSocks 节点"""
    try:
        if not uri.startswith("ss://"):
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        
        if '@' not in uri:
            return None
        
        # 检查关键字段
        if not all([parsed.hostname, parsed.port]):
            return None
        
        core_part = parsed.netloc.split('@')[0]
        decoded_core = base64.b64decode(core_part + '=' * (-len(core_part) % 4)).decode('utf-8')
        method, password = decoded_core.split(':', 1)
        
        # 检查加密方法是否支持
        if method.lower() not in SS_SUPPORTED_CIPHERS:
            return None

        fingerprint = get_ss_fingerprint(parsed, method, password)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node")
        
        return {
            "name": name,
            "type": "ss",
            "server": parsed.hostname,
            "port": parsed.port,
            "cipher": method,
            "password": password
        }
    except Exception:
        return None

def parse_trojan(uri):
    """解析 Trojan 节点"""
    try:
        if not uri.startswith("trojan://"):
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        # 检查关键字段
        if not all([parsed.hostname, parsed.port, parsed.username]):
            return None

        fingerprint = get_trojan_fingerprint(parsed, params)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node")

        return {
            "name": name,
            "type": "trojan",
            "server": parsed.hostname,
            "port": parsed.port,
            "password": parsed.username,
            "network": params.get("type", ["tcp"])[0],
            "sni": params.get("sni", [parsed.hostname])[0],
            "skip-cert-verify": params.get('allowInsecure', ['0'])[0] == '1',
            "grpc-opts": {
                "serviceName": params.get('serviceName', [''])[0]
            } if params.get('type', [''])[0] == 'grpc' else None
        }
    except Exception:
        return None

def parse_ssr(uri):
    """解析 ShadowsocksR 节点"""
    try:
        if not uri.startswith("ssr://"):
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        encoded_data = uri[6:]
        decoded_data = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
        
        main_part, params_part = decoded_data.split('/?', 1)
        server, port, protocol, method, obfs, password = main_part.split(':')
        
        password_decoded = base64.b64decode(password + '=' * (-len(password) % 4)).decode('utf-8')

        # 检查加密方法是否支持
        if method.lower() not in SS_SUPPORTED_CIPHERS:
            return None

        fingerprint = get_ssr_fingerprint(server, port, method, password_decoded, protocol, obfs)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        params = parse_qs(params_part)
        name_encoded = params.get('remarks', [''])[0]
        name = normalize_name(unquote(base64.b64decode(name_encoded + '=' * (-len(name_encoded) % 4)).decode('utf-8')) if name_encoded else "Unnamed SSR Node")

        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = base64.b64decode(obfs_param_encoded + '=' * (-len(obfs_param_encoded) % 4)).decode('utf-8') if obfs_param_encoded else ""

        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = base64.b64decode(protocol_param_encoded + '=' * (-len(protocol_param_encoded) % 4)).decode('utf-8') if protocol_param_encoded else ""
        
        return {
            "name": name,
            "type": "ssr",
            "server": server,
            "port": int(port),
            "password": password_decoded,
            "cipher": method,
            "protocol": protocol,
            "obfs": obfs,
            "obfs-param": obfs_param,
            "protocol-param": protocol_param
        }
    except Exception:
        return None

def parse_hysteria2(uri):
    """解析 Hysteria2 节点"""
    try:
        if not uri.startswith("hysteria2://"):
            return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        password = parsed.username
        params = parse_qs(parsed.query)

        # 检查关键字段
        if not all([parsed.hostname, parsed.port, password]):
            return None

        # 检查混淆密码
        obfs_type = params.get("obfs", ["none"])[0]
        obfs_password = params.get("obfs-password", [""])[0]
        if obfs_type != "none" and not obfs_password:
            return None

        fingerprint = get_hysteria2_fingerprint(parsed, params)
        if fingerprint in used_node_fingerprints:
            return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node")
        
        return {
            "name": name,
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": parsed.port,
            "password": password,
            "alpn": [ "h3" ],
            "obfs": obfs_type,
            "obfs-password": obfs_password,
            "sni": params.get("sni", [parsed.hostname])[0],
            "skip-cert-verify": params.get('insecure', ['0'])[0] == '1',
            "up": "100mbps",
            "down": "100mbps"
        }
    except Exception:
        return None

def main():
    global used_names, used_node_fingerprints
    input_file = "ss.txt"
    output_file = "config.yaml"

    if not os.path.exists(input_file):
        print(f"文件 {input_file} 不存在，跳过转换。")
        return

    with open(input_file, "r", encoding="utf-8", errors='ignore') as f:
        lines = f.readlines()
    
    proxies = []
    failed_count = 0
    duplicate_count = 0
    total_lines = len(lines)
    
    used_names.clear()
    used_node_fingerprints.clear()

    print(f"开始处理 {total_lines} 行节点...")
    
    for line in tqdm(lines, desc="解析节点"):
        line = line.strip()
        if not line:
            failed_count += 1
            continue

        parsed_node = None
        if line.startswith("vmess://"):
            parsed_node = parse_vmess(line)
        elif line.startswith("vless://"):
            parsed_node = parse_vless(line)
        elif line.startswith("ss://"):
            parsed_node = parse_ss(line)
        elif line.startswith("trojan://"):
            parsed_node = parse_trojan(line)
        elif line.startswith("ssr://"):
            parsed_node = parse_ssr(line)
        elif line.startswith("hysteria2://"):
            parsed_node = parse_hysteria2(line)
        else:
            failed_count += 1
            continue
        
        if parsed_node == "duplicate":
            duplicate_count += 1
        elif parsed_node:
            proxies.append(parsed_node)
        else:
            failed_count += 1

    if proxies:
        config_data = {
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "Proxy",
                    "type": "select",
                    "proxies": [p["name"] for p in proxies]
                }
            ],
            "rules": [
                "MATCH,Proxy"
            ]
        }
        
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, allow_unicode=True, sort_keys=False)
        print("\n" + "="*30)
        print("转换完成！")
        print(f"成功转换并去重后节点数量: {len(proxies)}")
        print(f"因节点内容重复被跳过数量: {duplicate_count}")
        print(f"解析失败或不符合格式的行数: {failed_count}")
        print(f"总计处理行数: {total_lines}")
        print(f"配置文件已保存到 {output_file}")
    else:
        print("\n" + "="*30)
        print("未找到任何有效节点，未生成配置文件。")

if __name__ == "__main__":
    main()
