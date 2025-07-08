# deduplicate_nodes.py
import os
import glob
import urllib.parse
import base64
import json

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
            user_info = parsed.username or ''
            if user_info:
                essential['id'] = user_info
            essential['host'] = parsed.hostname
            essential['port'] = parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            for key in ['insecure', 'sni', 'obfs', 'obfs-password']:
                if key in query:
                    essential[key] = query[key][0]
        elif scheme == 'ss':
            user_info = parsed.username or ''
            if '@' in user_info: # Old format method:password@host:port
                parts = user_info.split('@', 1)
                if len(parts) == 2:
                    essential['method'], essential['password'] = parts[0].split(':', 1)
                else: # New format base64_encoded_method_password@host:port
                    try:
                        decoded = base64.b64decode(user_info + '==' * (-len(user_info) % 4)).decode('utf-8')
                        if ':' in decoded:
                            essential['method'], essential['password'] = decoded.split(':', 1)
                        else: # Fallback for malformed or non-standard ss-libev/v2ray-plugin
                            essential['method'] = decoded # might just be password, or id
                            essential['password'] = ''
                    except Exception:
                        return None # Invalid Base64
            else: # Must be base64 encoded
                try:
                    decoded = base64.b64decode(user_info + '==' * (-len(user_info) % 4)).decode('utf-8')
                    if ':' in decoded:
                        essential['method'], essential['password'] = decoded.split(':', 1)
                    else:
                        essential['method'] = decoded
                        essential['password'] = ''
                except Exception:
                    return None
            
            essential['host'] = parsed.hostname
            essential['port'] = parsed.port or 8388
            query = urllib.parse.parse_qs(parsed.query)
            for key in ['sni', 'security', 'type', 'plugin', 'path', 'host']: # Added path, host for plugins
                if key in query:
                    essential[key] = query[key][0]
            
            # Handle plugin specific parameters if 'plugin' is present
            if 'plugin' in essential:
                plugin_query_str = url.split('?', 1)[-1] if '?' in url else ''
                plugin_query = urllib.parse.parse_qs(plugin_query_str)
                # For ss, a plugin may have its own options, consider them essential if critical
                # e.g., obfs-host for simple-obfs
                if 'obfs-host' in plugin_query: essential['obfs-host'] = plugin_query['obfs-host'][0]
                if 'obfs-path' in plugin_query: essential['obfs-path'] = plugin_query['obfs-path'][0]

        elif scheme in ['vless', 'vmess']:
            # For vless, vmess, the userinfo part is typically UUID (vless) or base64 encoded JSON (vmess)
            if scheme == 'vless':
                essential['id'] = parsed.username # UUID
                essential['host'] = parsed.hostname
                essential['port'] = parsed.port or 443
                query = urllib.parse.parse_qs(parsed.query)
                for key in ['security', 'encryption', 'sni', 'flow', 'fp', 'alpn', 'type', 'path', 'host', 'serviceName']:
                    if key in query:
                        essential[key] = query[key][0]
            elif scheme == 'vmess':
                # VMess links are base64 encoded JSON
                try:
                    # Add padding back if necessary
                    encoded_config = parsed.netloc
                    decoded_config = base64.b64decode(encoded_config + '===').decode('utf-8')
                    config = json.loads(decoded_config)
                    # Extract essential VMess parameters
                    essential['id'] = config.get('id')
                    essential['host'] = config.get('add')
                    essential['port'] = config.get('port')
                    essential['encryption'] = config.get('scy') # security
                    essential['security'] = config.get('tls') # tls/xtls/reality
                    essential['type'] = config.get('net') # network type (tcp, ws, grpc, etc.)
                    essential['sni'] = config.get('host') # SNI for tls, often same as host
                    
                    if essential['type'] == 'ws':
                        ws_path = config.get('path')
                        ws_headers_host = config.get('host') # HTTP Host header for WS
                        if ws_path: essential['path'] = ws_path
                        if ws_headers_host and ws_headers_host != essential['host']: essential['ws_host'] = ws_headers_host
                    elif essential['type'] == 'grpc':
                        grpc_serviceName = config.get('path') # For gRPC, path often means serviceName
                        if grpc_serviceName: essential['serviceName'] = grpc_serviceName

                    # Some additional VLESS/VMess common parameters that might be essential
                    if config.get('flow'): essential['flow'] = config['flow']
                    if config.get('fp'): essential['fp'] = config['fp']
                    if config.get('alpn'): essential['alpn'] = config['alpn']

                except (base64.binascii.Error, json.JSONDecodeError, KeyError):
                    return None # Invalid VMess link

        else:
            return None  # 不支持的协议

        # Sort items to ensure consistent representation for set hashing
        return (scheme, tuple(sorted(essential.items())))
    except Exception:
        return None

def format_simplified_url(node_data, index):
    """
    格式化简化的节点，命名为 节点X，保留必要参数。
    """
    scheme, components = node_data
    components_dict = dict(components)
    
    node_name = f"节点{index}"

    if scheme == 'hysteria2':
        query_parts = []
        for key in ['insecure', 'sni', 'obfs', 'obfs-password']:
            if key in components_dict:
                query_parts.append(f"{key}={urllib.parse.quote(str(components_dict[key]))}")
        query = '&'.join(query_parts) if query_parts else ''
        return f"{scheme}://{components_dict.get('id', '')}@{components_dict.get('host', '')}:{components_dict.get('port', 443)}{('?' + query) if query else ''}#{node_name}"
    
    elif scheme == 'ss':
        user_info = f"{components_dict.get('method', '')}:{components_dict.get('password', '')}"
        user_info_b64 = base64.b64encode(user_info.encode('utf-8')).decode('utf-8').rstrip('=')
        
        query_parts = []
        for key in ['sni', 'security', 'type', 'plugin', 'path', 'host', 'obfs-host', 'obfs-path']:
            if key in components_dict:
                query_parts.append(f"{key}={urllib.parse.quote(str(components_dict[key]))}")
        query = '&'.join(query_parts) if query_parts else ''
        return f"{scheme}://{user_info_b64}@{components_dict.get('host', '')}:{components_dict.get('port', 8388)}{('?' + query) if query else ''}#{node_name}"
    
    elif scheme == 'vless':
        query_parts = []
        # Essential VLESS query parameters
        for key in ['security', 'encryption', 'sni', 'flow', 'fp', 'alpn', 'type', 'path', 'host', 'serviceName']:
            if key in components_dict:
                query_parts.append(f"{key}={urllib.parse.quote(str(components_dict[key]))}")
        query = '&'.join(query_parts) if query_parts else ''
        return f"{scheme}://{components_dict.get('id', '')}@{components_dict.get('host', '')}:{components_dict.get('port', 443)}{('?' + query) if query else ''}#{node_name}"

    elif scheme == 'vmess':
        # Reconstruct VMess JSON config for base64 encoding
        config = {
            "v": "2", # VMess version
            "ps": node_name, # Pseudo name from index
            "id": components_dict.get('id', ''),
            "add": components_dict.get('host', ''),
            "port": components_dict.get('port', 0),
            "scy": components_dict.get('encryption', ''), # security method
            "tls": components_dict.get('security', ''), # tls/xtls/reality
            "net": components_dict.get('type', ''), # network type
            "host": components_dict.get('sni', components_dict.get('host', '')), # SNI / HTTP host header
        }
        if 'path' in components_dict: config['path'] = components_dict['path']
        if 'ws_host' in components_dict: config['host'] = components_dict['ws_host'] # Specific HTTP host header for WS if different from SNI
        if 'serviceName' in components_dict: config['path'] = components_dict['serviceName'] # grpc serviceName is path in vmess json

        # Add optional essential parameters if present in parsed data
        if 'flow' in components_dict: config['flow'] = components_dict['flow']
        if 'fp' in components_dict: config['fp'] = components_dict['fp']
        if 'alpn' in components_dict: config['alpn'] = components_dict['alpn']
        
        encoded_config = base64.b64encode(json.dumps(config, ensure_ascii=False).encode('utf-8')).decode('utf-8')
        return f"{scheme}://{encoded_config}#{node_name}"
    
    return None

def deduplicate_nodes(data_dir="data/", output_file="data/proxy_nodes_deduplicated_simplified.txt"):
    """
    去重节点：
    1. 提取核心参数
    2. 基于核心参数去重
    3. 统一命名为 节点X
    4. 输出简化后的节点到文件
    """
    unique_nodes = {}  # 核心参数到原始行的映射 (键为解析后的元组，值可忽略或用于调试)
    input_files = sorted(glob.glob(os.path.join(data_dir, "proxy_nodes_*.txt")))

    for file_path in input_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    parsed = parse_url_essential(stripped_line)
                    if parsed and parsed not in unique_nodes: # Only add if not already present
                        unique_nodes[parsed] = stripped_line # Store for the order if needed, but the key is what matters for uniqueness
        except Exception as e:
            print(f"读取文件 {file_path} 出错: {e}")

    # 格式化节点，分配顺序编号
    ordered_nodes = []
    # Sort the unique_nodes by their essential components for consistent output order
    # (Optional, but makes the output predictable)
    sorted_unique_keys = sorted(unique_nodes.keys()) 
    for index, node_data_key in enumerate(sorted_unique_keys, 1):
        formatted = format_simplified_url(node_data_key, index)
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
