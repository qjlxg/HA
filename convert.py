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

# 为 ShadowsocksR 单独定义支持的加密方法，因为它不支持 ss-aead 相关的加密方法
SSR_SUPPORTED_CIPHERS = [
    "aes-256-cfb", "aes-192-cfb", "aes-128-cfb",
    "chacha20-ietf",
    "camellia-256-cfb", "camellia-192-cfb", "camellia-128-cfb",
    "rc4-md5"
]

def normalize_name(name):
    """
    规范化节点名称：
    1. 移除表情符号和特殊字符。
    2. 保留前3个字符作为基础名称。
    3. 如果名称重复，添加序号以确保唯一性。
    """
    # 移除表情符号和换行符
    name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
    name = name.replace('<br/>', '').replace('\n', '').strip()
    # 移除除中文、英文、数字、空格和横杠外的所有字符
    name = re.sub(r'[^\u4e00-\u9fa5\w\s-]', '', name)
    # 将多个空格替换为单个空格
    name = re.sub(r'\s+', ' ', name).strip()
    
    truncated_name = name[:3] if len(name) >= 3 else name
    
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
    try:
        if not uri.startswith("vmess://"): return None
        encoded_data = uri[8:]
        encoded_data = encoded_data.replace('<br/>', '').replace('\n', '').strip()
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        
        if not isinstance(data, dict): return None
        if not all(key in data for key in ["add", "port", "id"]): return None
        
        try: port = int(data.get("port"))
        except (ValueError, TypeError): return None
        
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
        if fingerprint in used_node_fingerprints: return "duplicate"
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
            "network": data.get("net", "tcp"),
            "tls": data.get("tls", "") == "tls"
        }
        
        if node["network"] == "ws":
            node["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", node["server"])}
            }
        if node["tls"] and "sni" in data:
            node["servername"] = data["sni"]
        
        return node
    except Exception: return None

def parse_vless(uri):
    """解析 Vless 链接，返回节点配置字典或 None。"""
    try:
        if not uri.startswith("vless://"): return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        if not all([parsed.hostname, parsed.port, parsed.username]): return None
        try: port = int(parsed.port)
        except (ValueError, TypeError): return None
        
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
        if fingerprint in used_node_fingerprints: return "duplicate"
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
        return vless_node
    except Exception: return None

def parse_ss(uri):
    """解析 ShadowSocks 链接，返回节点配置字典或 None。"""
    try:
        if not uri.startswith("ss://"): return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        if '@' not in uri: return None
        if not all([parsed.hostname, parsed.port]): return None
        try: port = int(parsed.port)
        except (ValueError, TypeError): return None
        
        core_part = parsed.netloc.split('@')[0]
        decoded_core = base64.b64decode(core_part + '=' * (-len(core_part) % 4)).decode('utf-8')
        method, password = decoded_core.split(':', 1)
        
        if method.lower() not in SS_SUPPORTED_CIPHERS: return None

        node_data = {"type": "ss", "server": parsed.hostname, "port": port, "cipher": method, "password": password}
        fingerprint = get_ss_fingerprint(node_data)
        if fingerprint in used_node_fingerprints: return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node")
        return {
            "name": name,
            "type": "ss",
            "server": parsed.hostname,
            "port": port,
            "cipher": method,
            "password": password
        }
    except Exception: return None

def parse_trojan(uri):
    """解析 Trojan 链接，返回节点配置字典或 None。"""
    try:
        if not uri.startswith("trojan://"): return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        if not all([parsed.hostname, parsed.port, parsed.username]): return None
        try: port = int(parsed.port)
        except (ValueError, TypeError): return None
        
        node_data = {
            "type": "trojan",
            "server": parsed.hostname,
            "port": port,
            "password": parsed.username,
            "sni": params.get("sni", [parsed.hostname])[0]
        }
        fingerprint = get_trojan_fingerprint(node_data)
        if fingerprint in used_node_fingerprints: return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node")
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
    except Exception: return None

def parse_ssr(uri):
    """解析 ShadowsocksR 链接，返回节点配置字典或 None。"""
    try:
        if not uri.startswith("ssr://"): return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        encoded_data = uri[6:]
        decoded_data = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
        
        if '/?' not in decoded_data: return None

        main_part, params_part = decoded_data.split('/?', 1)
        server, port, protocol, method, obfs, password = main_part.split(':')
        try: port = int(port)
        except (ValueError, TypeError): return None
        
        password_decoded = base64.b64decode(password + '=' * (-len(password) % 4)).decode('utf-8')
        
        # 检查加密方法是否在SSR支持列表中
        if method.lower() not in SSR_SUPPORTED_CIPHERS:
            print(f"警告：跳过不支持的 SSR 加密方法：{method}")
            return None

        node_data = {
            "type": "ssr", "server": server, "port": port, "cipher": method, 
            "password": password_decoded, "protocol": protocol, "obfs": obfs
        }
        fingerprint = get_ssr_fingerprint(node_data)
        if fingerprint in used_node_fingerprints: return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        params = parse_qs(params_part)
        name_encoded = params.get('remarks', [''])[0]
        name = normalize_name(unquote(base64.b64decode(name_encoded + '=' * (-len(name_encoded) % 4)).decode('utf-8')) if name_encoded else "Unnamed SSR Node")
        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = base64.b64decode(obfs_param_encoded + '=' * (-len(obfs_param_encoded) % 4)).decode('utf-8') if obfs_param_encoded else ""
        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = base64.b64decode(protocol_param_encoded + '=' * (-len(protocol_param_encoded) % 4)).decode('utf-8') if protocol_param_encoded else ""
        
        return {
            "name": name, "type": "ssr", "server": server, "port": port, 
            "password": password_decoded, "cipher": method, "protocol": protocol, 
            "obfs": obfs, "obfs-param": obfs_param, "protocol-param": protocol_param
        }
    except Exception: return None

def parse_hysteria2(uri):
    """解析 Hysteria2 链接，返回节点配置字典或 None。"""
    try:
        if not uri.startswith("hysteria2://"): return None
        uri = uri.replace('<br/>', '').replace('\n', '').strip()
        parsed = urlparse(uri)
        password = parsed.username
        params = parse_qs(parsed.query)

        if not all([parsed.hostname, parsed.port, password]): return None
        try: port = int(parsed.port)
        except (ValueError, TypeError): return None
        
        obfs_type = params.get("obfs", ["none"])[0]
        obfs_password = params.get("obfs-password", [""])[0]
        if obfs_type != "none" and not obfs_password: return None
        
        node_data = {
            "type": "hysteria2", "server": parsed.hostname, "port": port, 
            "password": password, "obfs": obfs_type, 
            "sni": params.get("sni", [parsed.hostname])[0]
        }
        fingerprint = get_hysteria2_fingerprint(node_data)
        if fingerprint in used_node_fingerprints: return "duplicate"
        used_node_fingerprints.add(fingerprint)
        
        name = normalize_name(unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node")
        return {
            "name": name, "type": "hysteria2", "server": parsed.hostname, 
            "port": port, "password": password, "alpn": [ "h3" ], 
            "obfs": obfs_type, "obfs-password": obfs_password, 
            "sni": params.get("sni", [parsed.hostname])[0], 
            "skip-cert-verify": params.get('insecure', ['0'])[0] == '1', 
            "up": "100mbps", "down": "100mbps"
        }
    except Exception: return None

def get_yaml_fingerprint(node):
    """根据节点类型，为 YAML 节点生成唯一指纹，用于去重。"""
    node_type = node.get("type")
    if node_type == "vmess":
        return get_vmess_fingerprint(node)
    elif node_type == "vless":
        return get_vless_fingerprint(node)
    elif node_type == "ss":
        return get_ss_fingerprint(node)
    elif node_type == "trojan":
        return get_trojan_fingerprint(node)
    elif node_type == "ssr":
        return get_ssr_fingerprint(node)
    elif node_type == "hysteria2":
        return get_hysteria2_fingerprint(node)
    return None

def process_yaml_file(filepath, proxies_list, encoding):
    """
    一个内部使用的辅助函数，用于处理 YAML 文件的核心逻辑。
    将解析和节点处理的逻辑从主函数中提取出来，以减少代码重复。
    """
    current_file_proxies = []
    current_duplicates = 0
    total_file_nodes = 0
    yaml_data = {}
    
    try:
        with open(filepath, "r", encoding=encoding, errors='ignore') as f:
            content = f.read().strip()
            if not content:
                print(f"错误：文件 {filepath} 为空，跳过处理。")
                return 0, 0, 0
        
        try:
            yaml_data = yaml.safe_load(content)
        except yaml.YAMLError as ye:
            print(f"YAML 解析错误 ({filepath}, 编码: {encoding})：{ye}")
            lines = content.splitlines()
            error_line = getattr(ye, 'problem_mark', None)
            if error_line:
                line_number = error_line.line + 1
                start_line = max(0, line_number - 3)
                end_line = min(len(lines), line_number + 2)
                print(f"错误发生在第 {line_number} 行附近，以下是相关内容：")
                for i in range(start_line, end_line):
                    print(f"  行 {i + 1}: {lines[i]}")
            return 0, 0, 0
        
        if not isinstance(yaml_data, dict) or "proxies" not in yaml_data or not isinstance(yaml_data["proxies"], list):
            print(f"警告：文件 {filepath} 格式不正确或缺少 'proxies' 列表。")
            return 0, 0, 0

        total_file_nodes = len(yaml_data["proxies"])
        for node in tqdm(yaml_data["proxies"], desc=f"解析 {filepath}"):
            if not isinstance(node, dict) or "type" not in node:
                print(f"警告：跳过无效节点，节点内容：{node}")
                continue

            fingerprint = get_yaml_fingerprint(node)
            if fingerprint and fingerprint in used_node_fingerprints:
                current_duplicates += 1
                continue
            
            used_node_fingerprints.add(fingerprint)
            
            node_type = node.get("type")
            if node_type == "ss":
                cipher = node.get("cipher")
                if cipher not in SS_SUPPORTED_CIPHERS:
                    print(f"警告：跳过不支持的SS加密方法，节点：{node.get('name', '未知')}，加密方法：{cipher}")
                    continue
            
            node["name"] = normalize_name(node.get("name", "Unnamed YAML Node"))
            current_file_proxies.append(node)
    
    except Exception as e:
        print(f"处理文件 {filepath} 时出错：{e}")
        return 0, 0, total_file_nodes
    
    proxies_list.extend(current_file_proxies)
    return len(current_file_proxies), current_duplicates, total_file_nodes

def parse_yaml_proxies(filepath, proxies_list):
    """尝试使用不同编码解析 YAML 文件。"""
    success_count, duplicates, total_file_nodes = process_yaml_file(filepath, proxies_list, "utf-8")
    
    if success_count == 0 and total_file_nodes == 0:
        # 如果 UTF-8 解析失败，尝试 latin1
        print(f"UTF-8 解析失败，尝试以 latin1 编码重新读取文件 {filepath}...")
        return process_yaml_file(filepath, proxies_list, "latin1")
    
    return success_count, duplicates, total_file_nodes

def main():
    """主函数，负责文件处理流程和结果输出。"""
    global used_names, used_node_fingerprints
    
    input_files = ["merged_configs.txt", "all_unique_nodes.txt","base.txt"]
    output_file = "config.yaml"

    proxies = []
    failed_count = 0
    duplicate_count = 0
    total_lines = 0
    
    used_names.clear()
    used_node_fingerprints.clear()

    print("--- 启动节点转换工具 ---")
    print(f"将处理以下文件: {input_files}")

    for input_file in input_files:
        if not os.path.exists(input_file):
            print(f"文件 {input_file} 不存在，跳过处理。")
            continue
        
        # 处理 YAML 文件
        if input_file.endswith(('.yaml', '.yml')):
            success_count, duplicates, total_file_nodes = parse_yaml_proxies(input_file, proxies)
            total_lines += total_file_nodes
            duplicate_count += duplicates
            failed_count += (total_file_nodes - success_count - duplicates)
            continue
        
        # 处理非 YAML 文件
        lines_to_process = []
        try:
            with open(input_file, "r", encoding="utf-8", errors='ignore') as f:
                content = f.read().strip()
                # 检查是否为 Base64 编码
                if not content.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')):
                    decoded_content = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
                    lines_to_process = decoded_content.splitlines()
                    print(f"\n文件 {input_file} 似乎是 Base64 编码，已成功解码。")
                else:
                    lines_to_process = content.splitlines()
        except Exception as e:
            print(f"警告：文件 {input_file} 不是有效的 Base64 或链接格式，按普通文本处理。错误：{e}")
            with open(input_file, "r", encoding="utf-8", errors='ignore') as f:
                lines_to_process = f.readlines()
        
        current_file_lines = len(lines_to_process)
        total_lines += current_file_lines
        print(f"开始处理文件 {input_file} 中的 {current_file_lines} 行节点...")

        for line in tqdm(lines_to_process, desc=f"解析 {input_file}"):
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
        
        print("\n" + "="*40)
        print("✅ 转换完成！")
        print(f"📝 成功转换并去重后节点数量: {len(proxies)}")
        print(f"🔄 因节点内容重复被跳过数量: {duplicate_count}")
        print(f"❌ 解析失败或不符合格式的行数: {failed_count}")
        print(f"📊 总计处理行数: {total_lines}")
        print(f"📄 配置文件已保存到 {output_file}")
    else:
        print("\n" + "="*40)
        print("⚠️ 未找到任何有效节点，未生成配置文件。")

if __name__ == "__main__":
    main()
