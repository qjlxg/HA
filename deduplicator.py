# deduplicator.py
import os
import yaml
import hashlib
import json
import re

def write_proxies_to_yaml(all_proxies, output_file):
    """
    将代理节点列表写入YAML文件，以紧凑的单行流式格式输出每个节点。
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('proxies:\n')
        # 遍历所有代理节点，并以单行流式格式写入
        for proxy in all_proxies:
            # 强制使用流式风格 (flow style) 输出字典，即单行
            dumped_proxy = yaml.dump(proxy, default_flow_style=True, allow_unicode=True).strip()
            f.write(f' - {dumped_proxy}\n')
            
def get_canonical_key(proxy):
    """
    对代理节点配置进行规范化并生成一个稳定的哈希键。
    这个函数是去重的核心，它确保了只有真正相同的节点才会被视为重复。
    """
    if not isinstance(proxy, dict):
        return None
    
    # 移除非去重关键字段，防止它们影响哈希值
    node = proxy.copy()
    node.pop('name', None)
    
    # 对字典进行深度排序，确保键的顺序一致，以便生成稳定的哈希值
    def sort_dict(d):
        if not isinstance(d, dict):
            return d
        return {k: sort_dict(d[k]) for k in sorted(d)}

    node = sort_dict(node)

    # 专门处理VLESS/VMess节点的去重逻辑
    if node.get('type') in ['vless', 'vmess']:
        # 清洗ws-path中的动态参数
        if 'ws-path' in node:
            node['ws-path'] = re.sub(r'\?ed=\d+', '', node['ws-path'])
            # 将路径统一为小写
            node['ws-path'] = node['ws-path'].lower()
            
        # 清洗ws-headers中的Host字段
        if 'ws-headers' in node and 'Host' in node['ws-headers']:
            node['ws-headers']['Host'] = node['ws-headers']['Host'].lower()
            
        # 清洗servername
        if 'servername' in node:
            node['servername'] = node['servername'].lower()
            
        # 针对VLESS/VMess，哈希键只包含核心连接参数
        key_components = [
            node.get('type'),
            node.get('server'),
            str(node.get('port')),
            node.get('uuid'),
            node.get('network'),
            node.get('tls'),
            node.get('flow'),
            node.get('servername'),
            node.get('ws-path'),
            json.dumps(node.get('ws-headers', {}), sort_keys=True)
        ]
        
    # 其他节点类型，使用原有逻辑
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
            
    # 将所有关键组件组合成一个字符串并生成哈希值
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
            # 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if config and 'proxies' in config and isinstance(config['proxies'], list):
                    nodes_to_process = config['proxies']
                else:
                    nodes_to_process = []
            except yaml.YAMLError:
                # 如果不是有效的YAML，尝试按行解析链接
                nodes_to_process = []
                from_link = True
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('ss://'):
                        from_link = True
                        # 假设存在 parse_ss_link 函数
                        # node = parse_ss_link(line)
                        # if node: nodes_to_process.append(node)
                    elif line.startswith('vless://'):
                        from_link = True
                        # 假设存在 parse_vless_link 函数
                        # node = parse_vless_link(line)
                        # if node: nodes_to_process.append(node)
                    elif 'proxies' in line and from_link:
                         from_link = False

            # 对解析出的节点进行去重
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
    
    # 按照指定的优先级处理文件
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
