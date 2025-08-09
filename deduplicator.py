# deduplicator.py
import os
import yaml
import hashlib
import urllib.parse
import base64
import json

# --- 核心去重逻辑 ---
def get_node_key(proxy):
    """
    根据代理节点的关键信息生成一个唯一的哈希键。
    """
    if not isinstance(proxy, dict):
        return None
    
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
    elif proxy.get('type') == 'vmess':
        # Vmess key can be more complex, we'll use a simpler one for this example
        key_components.append(proxy.get('uuid'))
    elif proxy.get('type') == 'vless':
        key_components.append(proxy.get('uuid'))

    key_string = ":".join(str(c) for c in key_components if c is not None)
    
    return hashlib.sha256(key_string.encode('utf-8')).hexdigest()

def parse_ss_link(link):
    """
    解析ss链接并转换为Clash代理节点格式。
    """
    if not link.startswith('ss://'):
        return None
    
    try:
        # 去除 'ss://' 并解码 base64
        b64_content = link[5:].split('#')[0]
        decoded = base64.b64decode(b64_content + '==').decode('utf-8')
        
        # 提取密码、加密方式、服务器和端口
        password, rest = decoded.split('@')
        cipher, password = password.split(':')
        server, port = rest.split(':')

        # 尝试获取节点名称
        name = link.split('#')[-1]
        name = urllib.parse.unquote(name)

        return {
            'name': name if name != link else f"{cipher}-{server}-{port}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': cipher,
            'password': password
        }
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
        # 提取UUID
        uuid = link[8:].split('@')[0]
        # 提取其余部分
        parts = link.split('?')
        server_info = parts[0].split('@')[1]
        server, port = server_info.split(':')
        query_params = urllib.parse.parse_qs(parts[1])

        # 尝试获取节点名称
        name_part = parts[-1].split('#')
        name = urllib.parse.unquote(name_part[-1]) if len(name_part) > 1 else f"VLESS-{server}-{port}"

        # 组装代理字典
        proxy_node = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'cipher': 'auto',
            'udp': True,
        }

        # 处理可选参数
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
            proxy_node['ws-headers'] = {'Host': query_params['host'][0]}
            
        return proxy_node
    except Exception as e:
        print(f"解析vless链接失败: {link}, 错误: {e}")
        return None

def process_file(file_path, all_proxies, seen_nodes):
    """
    读取文件，解析链接，并添加不重复的节点。
    """
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return

    print(f"正在处理文件: {file_path}")
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
                    print(f"  - 添加新节点: {node['name']}")
                else:
                    print(f"  - 跳过重复节点: {node['name']}")


def main():
    merged_file = 'merged_configs.txt'
    unique_file = 'all_unique_nodes.txt'
    output_dir = 'sc'
    output_file = os.path.join(output_dir, 'all.yaml')

    os.makedirs(output_dir, exist_ok=True)
    
    all_proxies = []
    seen_nodes = set()
    
    # 处理第一个文件
    process_file(merged_file, all_proxies, seen_nodes)
    
    # 处理第二个文件
    process_file(unique_file, all_proxies, seen_nodes)

    if all_proxies:
        final_config = {'proxies': all_proxies}
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)
        print(f"\n✅ 所有找到的代理节点（已去重）已成功合并并写入 {output_file}")
        print(f"   最终节点总数：{len(all_proxies)}")
    else:
        print("\n⚠️ 未找到任何有效的代理节点。")

if __name__ == '__main__':
    main()
