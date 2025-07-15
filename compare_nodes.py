import os
import re
import base64
import json
import hashlib
import logging
from functools import lru_cache
from typing import Dict, Optional, List, Tuple
from urllib.parse import parse_qs, urlparse

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ================================================
# 1. 通用解析函数和协议处理器
# ================================================

@lru_cache(maxsize=1000)
def parse_node(node_str: str) -> Dict[str, Optional[str]]:
    """通用节点解析函数，根据协议调用特定的解析器。"""
    node_str = node_str.strip()
    if not node_str:
        return {"type": "invalid", "raw": node_str}

    protocol = node_str.split("://", 1)[0].lower()
    handler = PROTOCOL_HANDLERS.get(protocol, lambda x: {"type": protocol, "raw": x})
    try:
        parsed = handler(node_str)
        return parsed
    except Exception as e:
        logger.error(f"解析节点失败 {node_str}: {str(e)}")
        return {"type": protocol, "raw": node_str}

def parse_ss_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Shadowsocks 节点。"""
    try:
        main_part = node_str.split("://", 1)[1].split("#", 1)[0]
        if "@" in main_part:
            cred_b64, addr_port = main_part.split("@", 1)
            try:
                # Add padding for base64 if needed, then decode
                decoded_cred = base64.b64decode(cred_b64 + '==').decode("utf-8")
            except Exception:
                decoded_cred = cred_b64 # Fallback if not pure base64 or incomplete
            address, port = addr_port.rsplit(":", 1)
            return {
                "type": "ss",
                "credential": decoded_cred,
                "address": address,
                "port": port
            }
        else:
            # Handle ss://base64(method:password@address:port) or simpler ss://address:port
            try:
                decoded = base64.b64decode(main_part + '==').decode("utf-8")
                # If it decodes to something like "method:password@address:port"
                if '@' in decoded and ':' in decoded.split('@')[1]:
                    cred_part, addr_port_part = decoded.split('@', 1)
                    address, port = addr_port_part.rsplit(':', 1)
                    return {"type": "ss", "credential": cred_part, "address": address, "port": port}
                return {"type": "ss", "raw_decoded": decoded, "raw": node_str}
            except Exception:
                address, port = main_part.split(":", 1)
                return {"type": "ss", "address": address, "port": port, "credential": ""}
    except Exception:
        return {"type": "ss", "raw": node_str}

def parse_vmess_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Vmess 节点。"""
    try:
        b64_data = node_str.split("vmess://", 1)[1]
        decoded_data = base64.b64decode(b64_data).decode("utf-8")
        node_json = json.loads(decoded_data)
        return {
            "type": "vmess",
            "address": node_json.get("add"),
            "port": str(node_json.get("port")),
            "id": node_json.get("id"),
            "net": node_json.get("net"), # network type (tcp, ws, http, quic)
            "host": node_json.get("host", ""), # Add host
            "path": node_json.get("path", "") # Add path
        }
    except Exception:
        return {"type": "vmess", "raw": node_str}

def parse_trojan_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Trojan 节点。"""
    try:
        parsed_url = urlparse(node_str)
        password = parsed_url.username
        address, port = parsed_url.hostname, parsed_url.port
        params = parse_qs(parsed_url.query)
        return {
            "type": "trojan",
            "password": password,
            "address": address,
            "port": str(port) if port else None,
            "params": params
        }
    except Exception:
        return {"type": "trojan", "raw": node_str}

def parse_vless_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Vless 节点。"""
    try:
        parsed_url = urlparse(node_str)
        uuid = parsed_url.username
        address, port = parsed_url.hostname, parsed_url.port
        params = parse_qs(parsed_url.query)
        
        # Extract specific parameters for VLESS key
        security = params.get("security", [""])[0]
        vless_type = params.get("type", [""])[0] # e.g., "ws", "grpc", "tcp"
        host = params.get("host", [""])[0]
        path = params.get("path", [""])[0]

        return {
            "type": "vless",
            "id": uuid,
            "address": address, # Keep address for parsing completeness, but might not use in key
            "port": str(port) if port else None, # Keep port for parsing completeness
            "security": security,
            "vless_type": vless_type, # Renamed to avoid conflict with Python's 'type'
            "host": host,
            "path": path,
            "params": params # Keep full params for reference
        }
    except Exception:
        return {"type": "vless", "raw": node_str}

# 协议处理器映射
PROTOCOL_HANDLERS = {
    "ss": parse_ss_node,
    "vmess": parse_vmess_node,
    "trojan": parse_trojan_node,
    "vless": parse_vless_node
}

# ================================================
# 2. 去重键生成 (优化后)
# ================================================

def get_node_dedup_key(node_str: str) -> str:
    """
    根据节点类型和关键特征生成去重键。
    优化目标：对于Vmess和Vless，更侧重于ID和传输协议特性，而不是具体的IP/Port。
    """
    parsed = parse_node(node_str)
    protocol = parsed.get("type", "raw")

    if protocol == "ss" and parsed.get("credential") is not None:
        # SS key: type_credential@address:port (remains specific as per common SS usage)
        if parsed.get("address") and parsed.get("port"):
            return f"ss_{parsed['credential']}@{parsed['address']}:{parsed['port']}"
        return f"raw_{node_str}" # Fallback if address/port missing

    elif protocol == "vmess" and parsed.get("id"):
        # VMess key: type_id_net_host_path_hash
        # Use host and path for stricter uniqueness, as IP/Port can vary for CDN/WS setups.
        # Ensure default empty string for missing host/path to prevent None in f-string
        host = parsed.get("host", "").lower() # Normalize host to lowercase
        path = parsed.get("path", "")
        # Hash path to handle variations like trailing slashes or URL encoding
        path_hash = hashlib.md5(path.encode("utf-8")).hexdigest()
        return f"vmess_{parsed['id']}_{parsed['net']}_{host}_{path_hash}"
    
    elif protocol == "trojan" and parsed.get("password"):
        # Trojan key: type_password@address:port (remains specific)
        if parsed.get("address") and parsed.get("port"):
            return f"trojan_{parsed['password']}@{parsed['address']}:{parsed['port']}"
        return f"raw_{node_str}" # Fallback if address/port missing

    elif protocol == "vless" and parsed.get("id"):
        # VLESS key: type_id_security_type_host_path_hash
        # Focus on core VLESS transport parameters, ignoring specific IP/Port.
        security = parsed.get("security", "").lower()
        vless_type = parsed.get("vless_type", "").lower() # Use 'vless_type'
        host = parsed.get("host", "").lower() # Normalize host to lowercase
        path = parsed.get("path", "")
        path_hash = hashlib.md5(path.encode("utf-8")).hexdigest()
        
        # Sort and hash relevant parameters for consistency in key generation
        # Only include parameters that define the *service* not just a specific endpoint
        key_parts = [
            f"id={parsed['id']}",
            f"security={security}",
            f"type={vless_type}",
            f"host={host}",
            f"path_hash={path_hash}"
        ]
        # Use a consistent order by sorting
        sorted_key_parts = sorted(key_parts)
        final_vless_key_str = "_".join(sorted_key_parts)
        
        return f"vless_{hashlib.md5(final_vless_key_str.encode('utf-8')).hexdigest()}"
        
    # Fallback for unknown/unparsed formats or missing critical info
    return f"raw_{node_str}"

# ================================================
# 3. 去重函数
# ================================================

def deduplicate_nodes(
    input_nodes_content: str,
    output_format: str = "text",
    sort_by: Optional[str] = None,
    report_duplicates: bool = False
) -> Tuple[List[str], List[str]]:
    """
    根据提取的特征对节点进行去重。

    参数:
        input_nodes_content: 包含原始节点列表的字符串。
        output_format: 输出格式 ("text" 或 "json")。
        sort_by: 排序字段 ("protocol" 或 "address").

    返回:
        Tuple[List[str], List[str]]: 去重后的节点列表和重复节点列表。
    """
    unique_keys = set()
    unique_nodes = []
    duplicate_nodes = []

    for line in input_nodes_content.splitlines():
        clean_line = line.strip()
        if not clean_line:
            continue

        dedup_key = get_node_dedup_key(clean_line)
        if dedup_key not in unique_keys:
            unique_keys.add(dedup_key)
            unique_nodes.append(clean_line)
        else:
            duplicate_nodes.append(clean_line)
            if report_duplicates:
                logger.info(f"发现重复节点: {clean_line} (键: {dedup_key})")

    # 排序
    if sort_by:
        if sort_by == "protocol":
            unique_nodes.sort(key=lambda x: parse_node(x).get("type", ""))
        elif sort_by == "address":
            unique_nodes.sort(key=lambda x: parse_node(x).get("address", ""))

    # 格式化输出
    if output_format == "json":
        unique_nodes = [json.dumps(parse_node(node), ensure_ascii=False) for node in unique_nodes]

    return unique_nodes, duplicate_nodes

# ================================================
# 4. 主函数
# ================================================

def main(
    input_path: str = "data/all_unique_nodes.txt",
    output_path: str = "data/deduplicated_output.txt",
    output_format: str = "text",
    sort_by: Optional[str] = None,
    report_duplicates: bool = False
):
    """主函数：读取节点文件，执行去重并保存结果。"""
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"未找到输入文件: {input_path}")
        return
    except PermissionError:
        logger.error(f"无权限读取文件: {input_path}")
        return
    except Exception as e:
        logger.error(f"读取文件失败: {str(e)}")
        return

    unique_nodes, duplicate_nodes = deduplicate_nodes(content, output_format, sort_by, report_duplicates)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if output_format == "json":
                json.dump(unique_nodes, f, ensure_ascii=False, indent=2)
            else:
                f.write("\n".join(unique_nodes) + "\n")
    except PermissionError:
        logger.error(f"无权限写入文件: {output_path}")
        return
    except Exception as e:
        logger.error(f"写入文件失败: {str(e)}")
        return

    logger.info(f"去重完成！唯一节点已保存到: {output_path}")
    logger.info(f"原始节点数量: {len(content.splitlines())}")
    logger.info(f"去重后节点数量: {len(unique_nodes)}")
    if report_duplicates:
        logger.info(f"重复节点数量: {len(duplicate_nodes)}")

if __name__ == "__main__":
    main(
        input_path="data/all_unique_nodes (1).txt", # 确保这里指向你最新上传的文件
        output_path="data/deduplicated_output.txt",
        output_format="text",
        sort_by="protocol",
        report_duplicates=True
    )
