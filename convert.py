import os
import re
import yaml
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
from tqdm import tqdm

def parse_vmess(uri):
    """解析 Vmess 节点"""
    try:
        if not uri.startswith("vmess://"):
            return None
        encoded_data = uri[8:]
        data = json.loads(base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8'))
        return {
            "name": data.get("ps", "Unnamed Vmess Node"),
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": "auto",
            "tls": data.get("tls", "") == "tls",
            "network": data.get("net", "tcp"),
            "ws-opts": {
                "path": data.get("path", "/"),
                "headers": {
                    "Host": data.get("host", data.get("add"))
                }
            }
        }
    except Exception:
        return None

def parse_vless(uri):
    """解析 Vless 节点"""
    try:
        if not uri.startswith("vless://"):
            return None
        parsed = urlparse(uri)
        name = unquote(parsed.fragment) if parsed.fragment else "Unnamed Vless Node"
        params = parse_qs(parsed.query)

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
        parsed = urlparse(uri)
        name = unquote(parsed.fragment) if parsed.fragment else "Unnamed SS Node"
        if '@' not in uri:
            return None
        
        core_part = parsed.netloc.split('@')[0]
        decoded_core = base64.b64decode(core_part + '=' * (-len(core_part) % 4)).decode('utf-8')
        method, password = decoded_core.split(':', 1)
        
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
        parsed = urlparse(uri)
        name = unquote(parsed.fragment) if parsed.fragment else "Unnamed Trojan Node"
        params = parse_qs(parsed.query)

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
        encoded_data = uri[6:]
        decoded_data = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
        
        main_part, params_part = decoded_data.split('/?', 1)
        server, port, protocol, method, obfs, password = main_part.split(':')
        
        params = parse_qs(params_part)
        name_encoded = params.get('remarks', [''])[0]
        name = unquote(base64.b64decode(name_encoded + '=' * (-len(name_encoded) % 4)).decode('utf-8')) if name_encoded else "Unnamed SSR Node"

        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = base64.b64decode(obfs_param_encoded + '=' * (-len(obfs_param_encoded) % 4)).decode('utf-8') if obfs_param_encoded else ""

        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = base64.b64decode(protocol_param_encoded + '=' * (-len(protocol_param_encoded) % 4)).decode('utf-8') if protocol_param_encoded else ""

        password_decoded = base64.b64decode(password + '=' * (-len(password) % 4)).decode('utf-8')

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
        parsed = urlparse(uri)
        password = parsed.username
        name = unquote(parsed.fragment) if parsed.fragment else "Unnamed Hysteria2 Node"
        params = parse_qs(parsed.query)
        
        return {
            "name": name,
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": parsed.port,
            "password": password,
            "alpn": [ "h3" ],
            "obfs": params.get("obfs", ["none"])[0],
            "obfs-password": params.get("obfs-password", [""])[0],
            "sni": params.get("sni", [parsed.hostname])[0],
            "skip-cert-verify": params.get('insecure', ['0'])[0] == '1',
            "up": "100mbps",
            "down": "100mbps"
        }
    except Exception:
        return None

def main():
    input_file = "ss.txt"
    output_file = "config.yaml"

    if not os.path.exists(input_file):
        print(f"文件 {input_file} 不存在，跳过转换。")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    proxies = []
    failed_count = 0

    print(f"开始处理 {len(lines)} 行节点...")
    
    for line in tqdm(lines, desc="解析节点"):
        line = line.strip()
        if not line:
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
        
        if parsed_node:
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
        print(f"成功转换节点数量: {len(proxies)}")
        print(f"跳过或失败节点数量: {failed_count}")
        print(f"总计处理行数: {len(lines)}")
        print(f"配置文件已保存到 {output_file}")
    else:
        print("\n" + "="*30)
        print("未找到任何有效节点，未生成配置文件。")

if __name__ == "__main__":
    main()
