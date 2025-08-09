# deduplicator.py
import os
import yaml
import hashlib
import json
import re

def write_proxies_to_yaml(all_proxies, output_file):
    """
    将代理节点列表写入YAML文件，确保每个节点以紧凑的单行流式格式输出。
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入顶层 'proxies' 键
        f.write('proxies:\n')
        
        # 逐个代理节点写入，并强制单行流式输出
        for proxy in all_proxies:
            # 使用 yaml.dump 将单个字典转换为单行字符串
            # default_flow_style=True 强制流式输出
            # width 参数设置一个足够大的值以防止自动换行
            # indent=2 和 ---\n 确保格式兼容，但这里我们只取一行
            proxy_yaml_string = yaml.dump(
                proxy, 
                allow_unicode=True, 
                sort_keys=False, 
                default_flow_style=True, 
                width=4096
            ).strip()
            
            # 写入 YAML 列表项的标志 '- ' 和格式化后的字符串
            f.write(f'- {proxy_yaml_string}\n')

def get_canonical_key(proxy):
    """
    对代理节点配置进行规范化并生成一个稳定的哈希键。
    """
    if not isinstance(proxy, dict):
        return None
    
    node = proxy.copy()
    node.pop('name', None)
    
    def sort_dict(d):
        if not isinstance(d, dict):
            return d
        return {k: sort_dict(d[k]) for k in sorted(d)}

    node = sort_dict(node)

    if node.get('type') in ['vless', 'vmess']:
        if 'ws-opts' in node and 'path' in node['ws-opts'] and isinstance(node['ws-opts']['path'], str):
            node['ws-opts']['path'] = re.sub(r'\?ed=\d+', '', node['ws-opts']['path'])
            node['ws-opts']['path'] = node['ws-opts']['path'].lower()
            
        if 'ws-opts' in node and 'headers' in node['ws-opts'] and 'Host' in node['ws-opts']['headers']:
            node['ws-opts']['headers']['Host'] = node['ws-opts']['headers']['Host'].lower()

        if 'servername' in node and isinstance(node['servername'], str):
            node['servername'] = node['servername'].lower()
            
        key_components = [
            node.get('type'),
            node.get('server'),
            str(node.get('port')),
            node.get('uuid'),
            node.get('network'),
            node.get('tls'),
            node.get('flow'),
            node.get('servername'),
            node.get('ws-opts', {}).get('path'),
            json.dumps(node.get('ws-opts', {}).get('headers', {}), sort_keys=True)
        ]
        
    else:
        key_components = [
            node.get('server'),
            str(node.get('port')),
            node.get('type'),
            node.get('password'),
            node.get('cipher')
        ]
        if node.get('plugin'):
            key_components.append(node.get('plugin'))
            key_components.append(json.dumps(node.get('plugin-opts', {}), sort_keys=True))
            
    key_string = ":".join(str(c) for c in key_components if c is not None)
    return hashlib.sha256(key_string.encode('utf-8')).hexdigest()

def process_file(file_path, all_proxies, seen_nodes):
    """
    处理文件，解析并添加不重复的节点。
    """
    if not os.path.exists(file_path):
        print(f"文件不存在，跳过: {file_path}")
        return

    print(f"正在处理文件: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            nodes_to_process = []
            
            try:
                config = yaml.safe_load(content)
                if config and 'proxies' in config and isinstance(config['proxies'], list):
                    nodes_to_process = config['proxies']
            except yaml.YAMLError:
                pass

            for node in nodes_to_process:
                key = get_canonical_key(node)
                if key and key not in seen_nodes:
                    all_proxies.append(node)
                    seen_nodes.add(key)
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")

def main():
    merged_file = 'merged_configs.txt'
    unique_file = 'all_unique_nodes.txt'
    clash_proxies_file = 'sc/clash_proxies.yaml'
    output_dir = 'sc'
    output_file = os.path.join(output_dir, 'all.yaml')

    os.makedirs(output_dir, exist_ok=True)
    
    all_proxies = []
    seen_nodes = set()
    
    process_file(merged_file, all_proxies, seen_nodes)
    process_file(unique_file, all_proxies, seen_nodes)
    process_file(clash_proxies_file, all_proxies, seen_nodes)

    if all_proxies:
        write_proxies_to_yaml(all_proxies, output_file)
        print(f"\n✅ 所有找到的代理节点（已去重）已成功合并并写入 {output_file}")
        print(f"   最终节点总数：{len(all_proxies)}")
    else:
        print("\n⚠️ 未找到任何有效的代理节点。")

if __name__ == '__main__':
    main()
