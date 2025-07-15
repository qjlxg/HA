import os
import re
import base64
import json
import hashlib
import logging
from typing import Dict, Optional, List, Tuple
from urllib.parse import parse_qs, urlparse

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 协议处理器
def parse_ss_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Shadowsocks 节点。"""
    try:
        main_part, *_ = node_str.split("://", 1)[1].split("#", 1)
        if "@" in main_part:
            cred_b64, addr_port = main_part.split("@", 1)
            decoded_cred = base64.b64decode(cred_b64 + "==").decode("utf-8", errors="ignore")
            address, port = addr_port.rsplit(":", 1)
            return {"type": "ss", "credential": decoded_cred, "address": address, "port": port}
        decoded = base64.b64decode(main_part + "==").decode("utf-8", errors="ignore")
        address, port = decoded.split(":", 1)
        return {"type": "ss", "address": address, "port": port, "credential": ""}
    except Exception:
        return {"type": "ss", "raw": node_str}

def parse_vmess_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Vmess 节点。"""
    try:
        b64_data = node_str.split("vmess://", 1)[1]
        node_json = json.loads(base64.b64decode(b64_data).decode("utf-8"))
        return {
            "type": "vmess",
            "address": node_json.get("add"),
            "port": str(node_json.get("port")),
            "id": node_json.get("id"),
            "net": node_json.get("net")
        }
    except Exception:
        return {"type": "vmess", "raw": node_str}

def parse_trojan_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Trojan 节点。"""
    try:
        parsed_url = urlparse(node_str)
        return {
            "type": "trojan",
            "password": parsed_url.username,
            "address": parsed_url.hostname,
            "port": str(parsed_url.port) if parsed_url.port else None,
            "params": parse_qs(parsed_url.query)
        }
    except Exception:
        return {"type": "trojan", "raw": node_str}

def parse_vless_node(node_str: str) -> Dict[str, Optional[str]]:
    """解析 Vless 节点。"""
    try:
        parsed_url = urlparse(node_str)
        return {
            "type": "vless",
            "id": parsed_url.username,
            "address": parsed_url.hostname,
            "port": str(parsed_url.port) if parsed_url.port else None,
            "params": parse_qs(parsed_url.query)
        }
    except Exception:
        return {"type": "vless", "raw": node_str}

# 支持 Nekoray 的 JSON 数组格式
def parse_json_subscription(node_str: str) -> List[Dict[str, Optional[str]]]:
    """解析 JSON 格式的节点订阅（如 Nekoray 支持的 JSON 数组）。"""
    try:
        nodes = json.loads(node_str)
        if isinstance(nodes, list):
            parsed_nodes = []
            for node in nodes:
                if isinstance(node, dict):
                    protocol = node.get("protocol", "").lower()
                    if protocol in PROTOCOL_HANDLERS:
                        parsed_nodes.append({
                            "type": protocol,
                            "address": node.get("add") or node.get("server"),
                            "port": str(node.get("port")),
                            "id": node.get("id") or node.get("password"),
                            "net": node.get("net") or node.get("type"),
                            "params": node.get("params", {})
                        })
                    else:
                        parsed_nodes.append({"type": protocol, "raw": json.dumps(node)})
            return parsed_nodes
        return [{"type": "invalid", "raw": node_str}]
    except Exception:
        return [{"type": "invalid", "raw": node_str}]

# 协议处理器映射
PROTOCOL_HANDLERS = {
    "ss": parse_ss_node,
    "vmess": parse_vmess_node,
    "trojan": parse_trojan_node,
    "vless": parse_vless_node,
    "json": parse_json_subscription
}

def parse_node(node_str: str) -> List[Dict[str, Optional[str]]]:
    """通用节点解析函数，支持 Nekoray 的链接和 JSON 订阅格式。"""
    node_str = node_str.strip()
    if not node_str:
        return [{"type": "invalid", "raw": node_str}]

    if node_str.startswith("["):
        return parse_json_subscription(node_str)

    protocol = node_str.split("://", 1)[0].lower()
    handler = PROTOCOL_HANDLERS.get(protocol, lambda x: [{"type": protocol, "raw": x}])
    result = handler(node_str)
    if isinstance(result, list):
        return result
    if not result.get("raw") and not all(result.get(key) for key in ["address", "port"]):
        logger.warning(f"无效节点: {node_str}")
        return [{"type": protocol, "raw": node_str}]
    return [result]

def get_node_dedup_key(node: Dict[str, Optional[str]], raw_str: str) -> str:
    """生成去重键，适配 Nekoray 节点特征。"""
    protocol = node.get("type", "raw")
    if node.get("raw"):
        return f"raw_{hashlib.md5(raw_str.encode('utf-8')).hexdigest()}"

    key_parts = [protocol]
    if protocol == "ss":
        key_parts.extend([node.get("credential", ""), node["address"], node["port"]])
    elif protocol == "vmess":
        key_parts.extend([node.get("id", ""), node["address"], node["port"], node.get("net", "")])
    elif protocol == "trojan":
        key_parts.extend([node.get("password", ""), node["address"], node["port"]])
    elif protocol == "vless":
        params = "&".join(f"{k}={v[0]}" for k, v in sorted(node.get("params", {}).items()))
        params_hash = hashlib.md5(params.encode("utf-8")).hexdigest()
        key_parts.extend([node.get("id", ""), node["address"], node["port"], params_hash])
    else:
        return f"raw_{hashlib.md5(raw_str.encode('utf-8')).hexdigest()}"

    return "_".join(str(part) for part in key_parts if part)

def deduplicate_nodes(
    input_nodes_content: str,
    output_format: str = "text",
    sort_by: Optional[str] = None,
    report_duplicates: bool = False
) -> Tuple[List[str], List[str]]:
    """去重节点，适配 Nekoray 的节点格式。"""
    unique_keys = set()
    unique_nodes = []
    duplicate_nodes = []

    for line in input_nodes_content.splitlines():
        clean_line = line.strip()
        if not clean_line:
            continue

        parsed_nodes = parse_node(clean_line)
        for node in parsed_nodes:
            dedup_key = get_node_dedup_key(node, clean_line)
            if dedup_key not in unique_keys:
                unique_keys.add(dedup_key)
                unique_nodes.append(clean_line)
            else:
                duplicate_nodes.append(clean_line)
                if report_duplicates:
                    logger.info(f"重复节点: {clean_line}")

    if sort_by == "protocol":
        unique_nodes.sort(key=lambda x: parse_node(x)[0].get("type", ""))
    elif sort_by == "address":
        unique_nodes.sort(key=lambda x: parse_node(x)[0].get("address", ""))

    if output_format == "json":
        unique_nodes = [json.dumps(node, ensure_ascii=False) for node in [parse_node(n)[0] for n in unique_nodes]]

    return unique_nodes, duplicate_nodes

def main(
    input_path: str = "data/all_unique_nodes.txt",
    output_path: str = "data/deduplicated_output.txt",
    output_format: str = "text",
    sort_by: Optional[str] = None,
    report_duplicates: bool = False
):
    """主函数：读取节点文件，执行去重并保存结果，适配 Nekoray。"""
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"未找到文件: {input_path}")
        return
    except PermissionError:
        logger.error(f"无权限读取: {input_path}")
        return
    except Exception as e:
        logger.error(f"读取失败: {str(e)}")
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
        logger.error(f"无权限写入: {output_path}")
        return
    except Exception as e:
        logger.error(f"写入失败: {str(e)}")
        return

    logger.info(f"去重完成，保存到: {output_path}")
    logger.info(f"原始节点: {len(content.splitlines())}, 去重后: {len(unique_nodes)}, 重复: {len(duplicate_nodes)}")

if __name__ == "__main__":
    main(
        input_path="data/all_unique_nodes.txt",
        output_path="data/deduplicated_output.txt",
        output_format="text",
        sort_by="protocol",
        report_duplicates=True
    )
