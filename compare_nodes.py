import os
import re
import base64
import json
import hashlib

# ================================================
# 1. 节点解析函数 - 用于提取关键特征
# ================================================

def parse_ss_node_full(node_str):
    """Parses a Shadowsocks (ss://) node string for full deduplication features."""
    try:
        if '://' in node_str:
            main_part_with_remark = node_str.split('://', 1)[1]
            main_part = main_part_with_remark.split('#', 1)[0] # Remove remark for core features

            if '@' in main_part:
                cred_b64, addr_port = main_part.split('@', 1)
                try:
                    # Best attempt to decode credential, adding padding for base64 if needed
                    decoded_cred = base64.b64decode(cred_b64 + '==').decode('utf-8')
                except Exception:
                    decoded_cred = cred_b64 # Fallback if not pure base64 or incomplete

                address_parts = addr_port.split(':')
                address = address_parts[0]
                port = address_parts[1] if len(address_parts) > 1 else None

                return {
                    "type": "ss",
                    "credential": decoded_cred, # e.g., "method:password"
                    "address": address,
                    "port": port
                }
            else:
                # Handle ss://base64(method:password@address:port) or simpler ss://address:port
                # This format is less common for standard deduplication, usually the cred is separate.
                # If it's a direct base64 of the whole string, it's treated as a raw string for now
                try:
                    decoded_main = base64.b64decode(main_part + '==').decode('utf-8')
                    # If this succeeds, it might be a complex SS format, we'll use a generic key
                    return {"type": "ss", "raw_decoded": decoded_main, "raw": node_str}
                except Exception:
                    # It might just be ss://address:port or some other simple form
                    parts = main_part.split(':')
                    return {
                        "type": "ss",
                        "address": parts[0],
                        "port": parts[1] if len(parts) > 1 else None,
                        "credential": "" # No explicit credential
                    }
    except Exception:
        pass
    return {"type": "ss", "raw": node_str} # Fallback to raw if parsing fails

def parse_vmess_node_full(node_str):
    """Parses a Vmess (vmess://) node string for full deduplication features."""
    try:
        b64_data = node_str.split('vmess://', 1)[1]
        decoded_data = base64.b64decode(b64_data).decode('utf-8')
        node_json = json.loads(decoded_data)
        return {
            "type": "vmess",
            "address": node_json.get("add"),
            "port": node_json.get("port"),
            "id": node_json.get("id"), # UUID
            "net": node_json.get("net"), # network type (tcp, ws, http, quic)
            # "tls": node_json.get("tls"), # Can be considered for more strict uniqueness
            # "host": node_json.get("host"), # SNI or custom host
            # "path": node_json.get("path"), # ws path
        }
    except Exception:
        pass
    return {"type": "vmess", "raw": node_str}

def parse_trojan_node_full(node_str):
    """Parses a Trojan (trojan://) node string for full deduplication features."""
    try:
        # Format: trojan://password@address:port?params#remark
        parts = node_str.split('trojan://', 1)[1].split('@', 1)
        if len(parts) == 2:
            password = parts[0]
            addr_port_params_remark = parts[1]
            
            addr_port_params = addr_port_params_remark.split('#', 1)[0] # Remove remark
            addr_port_parts = addr_port_params.split('?', 1)
            
            address_port = addr_port_parts[0]
            params_str = addr_port_parts[1] if len(addr_port_parts) > 1 else ''

            address_parts = address_port.split(':')
            address = address_parts[0]
            port = address_parts[1] if len(address_parts) > 1 else None

            # Parse query parameters (e.g., security=tls, type=ws, host=...)
            params = {}
            for param_pair in params_str.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    params[key] = value

            return {
                "type": "trojan",
                "password": password,
                "address": address,
                "port": port,
                "params": params # Store params for potential future use or stricter matching
            }
    except Exception:
        pass
    return {"type": "trojan", "raw": node_str}

def parse_vless_node_full(node_str):
    """Parses a Vless (vless://) node string for full deduplication features."""
    try:
        # Format: vless://uuid@address:port?params#remark
        parts = node_str.split('vless://', 1)[1].split('@', 1)
        if len(parts) == 2:
            uuid = parts[0]
            addr_port_params_remark = parts[1]
            
            addr_port_params = addr_port_params_remark.split('#', 1)[0] # Remove remark
            addr_port_parts = addr_port_params.split('?', 1)
            
            address_port = addr_port_parts[0]
            params_str = addr_port_parts[1] if len(addr_port_parts) > 1 else ''

            address_parts = address_port.split(':')
            address = address_parts[0]
            port = address_parts[1] if len(address_parts) > 1 else None

            params = {}
            for param_pair in params_str.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    params[key] = value

            return {
                "type": "vless",
                "id": uuid,
                "address": address,
                "port": port,
                "params": params
            }
    except Exception:
        pass
    return {"type": "vless", "raw": node_str}

def get_node_dedup_key(node_str):
    """
    根据节点类型和关键特征生成去重键。
    这个键将用于判断两个节点是否重复。
    """
    node_str = node_str.strip()
    
    if node_str.startswith("ss://"):
        parsed = parse_ss_node_full(node_str)
        if parsed and parsed.get("address") and parsed.get("port") and parsed.get("credential") is not None:
            # SS key: type_credential@address:port
            return f"ss_{parsed['credential']}@{parsed['address']}:{parsed['port']}"
    
    elif node_str.startswith("vmess://"):
        parsed = parse_vmess_node_full(node_str)
        if parsed and parsed.get("id") and parsed.get("address") and parsed.get("port") and parsed.get("net"):
            # VMess key: type_id@address:port_net
            return f"vmess_{parsed['id']}@{parsed['address']}:{parsed['port']}_{parsed['net']}"
    
    elif node_str.startswith("trojan://"):
        parsed = parse_trojan_node_full(node_str)
        if parsed and parsed.get("password") and parsed.get("address") and parsed.get("port"):
            # Trojan key: type_password@address:port
            # For stricter Trojan dedup, consider params if they affect connection uniqueness
            return f"trojan_{parsed['password']}@{parsed['address']}:{parsed['port']}"
    
    elif node_str.startswith("vless://"):
        parsed = parse_vless_node_full(node_str)
        if parsed and parsed.get("id") and parsed.get("address") and parsed.get("port"):
            # VLESS key: type_id@address:port_params_hash
            # Parameters can be important for VLESS uniqueness (e.g., flow, security)
            # Hash sorted params to ensure consistent key
            param_string = ""
            if parsed.get("params"):
                sorted_params = sorted(parsed["params"].items())
                param_string = "&".join([f"{k}={v}" for k, v in sorted_params])
            
            params_hash = hashlib.md5(param_string.encode('utf-8')).hexdigest()
            return f"vless_{parsed['id']}@{parsed['address']}:{parsed['port']}_{params_hash}"
    
    # Fallback for unknown/unparsed formats: use full raw string
    return f"raw_{node_str}"

# ================================================
# 2. 去重函数
# ================================================

def deduplicate_nodes(input_nodes_content):
    """
    根据提取的特征对节点进行去重。

    参数:
        input_nodes_content (str): 包含原始节点列表的字符串内容。

    返回:
        list: 去重后的唯一节点列表。
    """
    unique_keys = set()
    deduplicated_nodes = []
    
    lines = input_nodes_content.splitlines()
    for line in lines:
        clean_line = line.strip()
        if not clean_line: # Skip empty lines
            continue

        dedup_key = get_node_dedup_key(clean_line)
        
        if dedup_key not in unique_keys:
            unique_keys.add(dedup_key)
            deduplicated_nodes.append(clean_line)
        # else:
        #     print(f"Skipping duplicate: {clean_line} (key: {dedup_key})") # 可以选择打印被移除的节点

    return deduplicated_nodes

# ================================================
# 3. 实际应用 (假设你从文件中读取内容)
# ================================================

if __name__ == "__main__":
    # 请确保 'all_unique_nodes.txt' 文件位于 'data/' 目录下
    original_nodes_file_path = os.path.join("data", "all_unique_nodes.txt")
    
    try:
        with open(original_nodes_file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
    except FileNotFoundError:
        print(f"错误: 原始节点文件未找到: {original_nodes_file_path}")
        exit(1)

    # 执行去重
    final_unique_nodes = deduplicate_nodes(original_content)

    # 将去重结果输出到文件
    output_dir = "data"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_file_path = os.path.join(output_dir, "deduplicated_output.txt")
    with open(output_file_path, "w", encoding='utf-8') as f:
        for node in final_unique_nodes:
            f.write(node + "\n")

    print(f"去重完成！唯一节点已保存到: {output_file_path}")
    print(f"原始节点数量: {len(original_content.splitlines())}")
    print(f"去重后节点数量: {len(final_unique_nodes)}")
