
import os
import glob
import urllib.parse
import base64

def parse_url_essential(url):
    """
    解析 URL，提取连接必需的核心参数。
    返回 (protocol, essential_components) 用于去重。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        essential = {'scheme': scheme}

        if scheme == 'hysteria2':
            # 用户信息（UUID 或密码）
            user_info = parsed.username or ''
            if user_info:
                essential['id'] = user_info
            # 主机和端口
            essential['host'] = parsed.hostname
            essential['port'] = parsed.port or 443
            # 解析查询参数
            query = urllib.parse.parse_qs(parsed.query)
            # 保留必要的查询参数
            for key in ['insecure', 'sni', 'obfs', 'obfs-password']:
                if key in query:
                    essential[key] = query[key][0]
        elif scheme == 'ss':
            # Shadowsocks: 提取加密方法和密码
            user_info = parsed.username or ''
            if '@' in user_info:
                essential['method'], essential['password'] = user_info.split(':', 1)
            else:
                # 尝试解码 Base64 编码的 user_info
                try:
                    decoded = base64.b64decode(user_info + '==' * (-len(user_info) % 4)).decode('utf-8')
                    essential['method'], essential['password'] = decoded.split(':', 1)
                except:
                    return None
            essential['host'] = parsed.hostname
            essential['port'] = parsed.port or 8388
            # 保留必要的查询参数
            query = urllib.parse.parse_qs(parsed.query)
            for key in ['sni', 'security', 'type']:
                if key in query:
                    essential[key] = query[key][0]
        else:
            return None  # 不支持的协议

        return (scheme, tuple(sorted(essential.items())))
    except Exception:
        return None

def format_simplified_url(node_data, index):
    """
    格式化简化的节点，命名为 节点X，保留必要参数。
    """
    scheme, components = node_data
    components_dict = dict(components)
    
    if scheme == 'hysteria2':
        query_parts = []
        for key in ['insecure', 'sni', 'obfs', 'obfs-password']:
            if key in components_dict:
                query_parts.append(f"{key}={urllib.parse.quote(components_dict[key])}")
        query = '&'.join(query_parts) if query_parts else ''
        return f"{scheme}://{components_dict['id']}@{components_dict['host']}:{components_dict['port']}{'?'+query if query else ''}#节点{index}"
    elif scheme == 'ss':
        user_info = f"{components_dict['method']}:{components_dict['password']}"
        # Base64 编码 user_info
        user_info_b64 = base64.b64encode(user_info.encode('utf-8')).decode('utf-8').rstrip('=')
        query_parts = []
        for key in ['sni', 'security', 'type']:
            if key in components_dict:
                query_parts.append(f"{key}={urllib.parse.quote(components_dict[key])}")
        query = '&'.join(query_parts) if query_parts else ''
        return f"{scheme}://{user_info_b64}@{components_dict['host']}:{components_dict['port']}{'?'+query if query else ''}#节点{index}"
    return None

def deduplicate_nodes(data_dir="data/", output_file="data/proxy_nodes_deduplicated.txt"):
    """
    去重节点：
    1. 提取核心参数
    2. 基于核心参数去重
    3. 统一命名为 节点X
    4. 输出简化后的节点到文件
    """
    unique_nodes = {}  # 核心参数到原始行的映射
    input_files = sorted(glob.glob(os.path.join(data_dir, "proxy_nodes_*.txt")))

    for file_path in input_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    parsed = parse_url_essential(stripped_line)
                    if parsed and parsed not in unique_nodes:
                        unique_nodes[parsed] = stripped_line
        except Exception as e:
            print(f"读取文件 {file_path} 出错: {e}")

    # 格式化节点，分配顺序编号
    ordered_nodes = []
    for index, node_data in enumerate(unique_nodes.keys(), 1):
        formatted = format_simplified_url(node_data, index)
        if formatted:
            ordered_nodes.append(formatted)

    # 写入输出文件
    try:
        os.makedirs(data_dir, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for node_line in ordered_nodes:
                f.write(node_line + '\n')
        print(f"去重完成。{len(ordered_nodes)} 个唯一节点已写入 {output_file}")
    except Exception as e:
        print(f"写入输出文件 {output_file} 出错: {e}")

if __name__ == "__main__":
    deduplicate_nodes()
