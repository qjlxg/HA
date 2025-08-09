# deduplicator.py
import os
import yaml
import hashlib
import urllib.parse
import base64
import json
import re

def write_proxies_to_yaml(all_proxies, output_file):
    """
    将代理节点列表写入YAML文件。
    已修改为以更紧凑的单行流式格式输出每个节点。
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('proxies:\n')
        # 遍历所有代理节点，并以单行流式格式写入
        for proxy in all_proxies:
            # 强制使用流式风格 (flow style) 输出字典，即单行
            dumped_proxy = yaml.dump(proxy, default_flow_style=True, allow_unicode=True).strip()
            f.write(f' - {dumped_proxy}\n')
            
# --- 核心去重逻辑 ---
def get_node_key(proxy):
    """
    根据代理节点的关键信息生成一个唯一的哈希键。
    已优化，综合考虑VLESS/VMess节点的多个核心参数进行去重。
    """
    if not isinstance(proxy, dict):
        return None
    
    # 针对 VLESS 和 VMess 节点，使用一个综合的哈希键来处理去重
    if proxy.get('type') in ['vless', 'vmess']:
        key_components = [
            proxy.get('type'),
            proxy.get('server'),
            str(proxy.get('port')),
            proxy.get('uuid'),
            proxy.get('network'),
        ]

        if proxy.get('tls'):
            key_components.append('tls')
            key_components.append(proxy.get('servername', ''))
            key_components.append(proxy.get('flow', ''))
        
        if proxy.get('network') == 'ws':
            ws_path = proxy.get('ws-path', '')
            ws_headers = proxy.get('ws-headers', {}).get('Host', '')
            key_components.append(ws_path)
            key_components.append(ws_headers)
        
        key_string = ":".join(str(c) for c in key_components if c is not None)
    
    # 对于其他节点类型 (SS, Trojan 等)，使用原有的去重逻辑
    else:
        key_components = [
            proxy.get('server'),
            str(proxy.get('port')),
            proxy.get('type')
        ]
        
        if proxy.get('type') == 'trojan':
            key_components.append(proxy.get('password'))
        elif proxy.get('type') == 'ss':
            key_components.append(proxy.get('cipher'))
            key_components.append(proxy.get('password'))
            if proxy.get('plugin'):
                key_components.append(proxy.get('plugin'))
                key_components.append(str(proxy.get('plugin-opts')))
        
        key_string = ":".join(str(c) for c in key_components if c is not None)
    
    return hashlib.sha256(key_string.encode('utf-8')).hexdigest()

def parse_ss_link(link):
    """
    解析ss链接并转换为Clash代理节点格式。
    支持插件，如 obfs 和 v2ray-plugin。
    """
    if not link.startswith('ss://'):
        return None
    
    try:
        pattern = re.compile(r'ss://(?P<base64_part>[^#?]+)(?:\?plugin=(?P<plugin>[^#]+))?(?:#(?P<name>.+))?')
        match = pattern.match(link)
        if not match:
            return None
        
        b64_part = match.group('base64_part')
        plugin_part = match.group('plugin')
        name_part = match.group('name')

        b64_content = b64_part.encode('utf-8')
        decoded = base64.b64decode(b64_content + b'==').decode('utf-8')
        cipher_password, server_port = decoded.split('@')
        cipher, password = cipher_password.split(':')
        server, port = server_port.split(':')

        proxy_node = {
            'name': urllib.parse.unquote(name_part) if name_part else f"ss-{server}-{port}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': cipher,
            'password': password
        }

        if plugin_part:
            proxy_node['plugin'] = plugin_part.split(';')[0]
            plugin_opts = {}
            for opt in plugin_part.split(';')[1:]:
                if '=' in opt:
                    key, value = opt.split('=', 1)
                    plugin_opts[key] = value
            if plugin_opts:
                proxy_node['plugin-opts'] = plugin_opts
                
        return proxy_node
    except Exception as e:
        print(f"解析ss链接失败: {link}, 错误: {e}")
        return None

def parse_vless_link(link):
    """
    解析vless链接并转换为Clash代理节点格式。
    """
    if not link.startswith('vless://'):
        return None
    
    try:
        uuid = link[8:].split('@')[0]
        parts = link.split('?')
        server_info = parts[0].split('@')[1]
        server, port = server_info.split(':')
        
        name_part = parts[-1].split('#')
        name = urllib.parse.unquote(name_part[-1]) if len(name_part) > 1 else f"VLESS-{server}-{port}"
        
        query_params = urllib.parse.parse_qs(parts[1].split('#')[0])

        proxy_node = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'cipher': 'auto',
            'udp': True,
        }

        if 'security' in query_params:
            security = query_params['security'][0]
            if security == 'tls':
                proxy_node['tls'] = True
            elif security == 'xtls':
                proxy_node['tls'] = True
                proxy_node['flow'] = query_params['flow'][0] if 'flow' in query_params else 'xtls-rprx-vision'

        if 'encryption' in query_params:
            proxy_node['cipher'] = query_params['encryption'][0]

        if 'fp' in query_params:
            proxy_node['fp'] = query_params['fp'][0]
        
        if 'sni' in query_params:
            proxy_node['servername'] = query_params['sni'][0]
        
        if 'type' in query_params and query_params['type'][0] == 'ws':
            proxy_node['network'] = 'ws'
            proxy_node['ws-path'] = query_params['path'][0]
            if 'host' in query_params:
                proxy_node['ws-headers'] = {'Host': query_params['host'][0]}
            
        return proxy_node
    except Exception as e:
        print(f"解析vless链接失败: {link}, 错误: {e}")
        return None
        
def process_link_file(file_path, all_proxies, seen_nodes):
    """
    读取包含链接的文件，解析链接，并添加不重复的节点。
    """
    if not os.path.exists(file_path):
        print(f"文件不存在，跳过: {file_path}")
        return

    print(f"正在处理链接文件: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            node = None
            if line.startswith('ss://'):
                node = parse_ss_link(line)
            elif line.startswith('vless://'):
                node = parse_vless_link(line)

            if node:
                key = get_node_key(node)
                if key and key not in seen_nodes:
                    all_proxies.append(node)
                    seen_nodes.add(key)
                else:
                    pass

def process_yaml_file(file_path, all_proxies, seen_nodes):
    """
    读取包含YAML格式节点的文件，解析并添加不重复的节点。
    """
    if not os.path.exists(file_path):
        print(f"文件不存在，跳过: {file_path}")
        return

    print(f"正在处理YAML文件: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if config and 'proxies' in config and isinstance(config['proxies'], list):
                for node in config['proxies']:
                    key = get_node_key(node)
                    if key and key not in seen_nodes:
                        all_proxies.append(node)
                        seen_nodes.add(key)
                    else:
                        pass
    except Exception as e:
        print(f"处理YAML文件 {file_path} 时出错: {e}")

def main():
    merged_file = 'merged_configs.txt'
    unique_file = 'all_unique_nodes.txt'
    clash_proxies_file = 'sc/clash_proxies.yaml'
    output_dir = 'sc'
    output_file = os.path.join(output_dir, 'all.yaml')

    os.makedirs(output_dir, exist_ok=True)
    
    all_proxies = []
    seen_nodes = set()
    
    process_link_file(merged_file, all_proxies, seen_nodes)
    process_link_file(unique_file, all_proxies, seen_nodes)
    process_yaml_file(clash_proxies_file, all_proxies, seen_nodes)

    if all_proxies:
        write_proxies_to_yaml(all_proxies, output_file)
        print(f"\n✅ 所有找到的代理节点（已去重）已成功合并并写入 {output_file}")
        print(f"   最终节点总数：{len(all_proxies)}")
    else:
        print("\n⚠️ 未找到任何有效的代理节点。")

if __name__ == '__main__':
    main()
