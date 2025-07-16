import os
import urllib.parse
import base64
import logging
import re
from collections import defaultdict
from uuid import uuid4

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_cleaning_errors.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def clean_duplicate_nodes_advanced(file_path, output_path=None, debug_samples=10, strict_dedup=True):
    """
    清理节点文件中重复的节点，基于协议特定逻辑，支持 VLESS、Trojan、SS 等协议。
    
    Args:
        file_path (str): 输入节点文件路径。
        output_path (str, optional): 输出文件路径，默认在输入文件名后加 '_cleaned'。
        debug_samples (int): 调试时记录的去重键样本数。
        strict_dedup (bool): 是否启用严格去重（忽略 UUID/密码，仅比较 host:port 和关键参数）。
    
    Returns:
        bool: 清理成功返回 True，否则返回 False。
    """
    if not os.path.isfile(file_path):
        logger.error(f"输入文件不存在: {file_path}")
        return False

    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_cleaned{ext}"

    unique_node_keys = set()
    unique_lines_output = []
    error_lines = []
    stats = defaultdict(int)
    debug_keys = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                stats['total_lines'] += 1
                stripped_line = line.strip()
                if not stripped_line:
                    stats['empty_lines'] += 1
                    continue

                core_part = stripped_line.split('#')[0].strip()
                protocol = core_part.split('://')[0].lower()
                stats[protocol] += 1

                try:
                    node_key = generate_node_key(core_part, strict_dedup)
                    if not node_key:
                        raise ValueError("无法生成去重键")

                    if len(debug_keys) < debug_samples:
                        debug_keys.append((protocol, node_key))

                    if node_key not in unique_node_keys:
                        unique_node_keys.add(node_key)
                        unique_lines_output.append(line)
                    else:
                        stats[f"{protocol}_duplicates"] += 1
                except Exception as e:
                    logger.error(f"解析失败 (行 {line_number}): {stripped_line} | 错误: {str(e)}")
                    error_lines.append((line_number, stripped_line, str(e)))
                    stats[f"{protocol}_errors"] += 1

        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines_output)

        # 输出统计信息
        logger.info(f"✅ 清理完成，结果保存至: {output_path}")
        logger.info(f"📊 统计信息:")
        logger.info(f"  - 总行数: {stats['total_lines']}")
        logger.info(f"  - 有效行数: {stats['total_lines'] - stats['empty_lines']}")
        logger.info(f"  - 唯一节点数: {len(unique_lines_output)}")
        total_duplicates = sum(stats[f'{p}_duplicates'] for p in ['vless', 'trojan', 'ss', 'vmess', 'ssr', 'hysteria2'])
        logger.info(f"  - 重复节点数: {total_duplicates}")
        logger.info(f"  - 解析失败数: {len(error_lines)}")
        logger.info(f"  - 空行数: {stats['empty_lines']}")
        logger.info(f"  - 协议分布:")
        for protocol in ['vless', 'trojan', 'ss', 'vmess', 'ssr', 'hysteria2', 'unknown']:
            if stats[protocol] or stats.get(f'{protocol}_duplicates', 0) or stats.get(f'{protocol}_errors', 0):
                logger.info(f"    - {protocol.upper()}: {stats[protocol]} 节点, "
                           f"{stats.get(f'{protocol}_duplicates', 0)} 重复, "
                           f"{stats.get(f'{protocol}_errors', 0)} 解析失败")

        if error_lines:
            logger.warning(f"解析失败节点: {len(error_lines)}，详情见 node_cleaning_errors.log")

        if debug_keys:
            logger.info(f"🔍 调试信息: 前 {len(debug_keys)} 个去重键:")
            for i, (proto, key) in enumerate(debug_keys, 1):
                logger.info(f"    {i}. {proto.upper()}: {key}")

        return True

    except Exception as e:
        logger.error(f"❌ 清理过程中发生错误: {str(e)}")
        return False

def generate_node_key(url, strict_dedup):
    """生成节点的去重键，基于协议类型标准化处理。"""
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        query = parsed.query

        handlers = {
            'vless': normalize_vless,
            'vmess': normalize_vmess,
            'trojan': normalize_trojan,
            'ss': normalize_ss,
            'ssr': normalize_ssr,
            'hysteria2': normalize_hysteria2
        }

        handler = handlers.get(scheme)
        if handler:
            return handler(netloc, query, strict_dedup)
        
        logger.warning(f"未知协议: {scheme}，使用原始 URL 作为去重键")
        return url.lower()

    except Exception as e:
        raise ValueError(f"生成去重键失败: {str(e)}")

def normalize_vless(netloc, query, strict_dedup):
    """标准化 VLESS 链接。"""
    host_port = netloc.split('@')[1] if strict_dedup and '@' in netloc else netloc
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: sorted([urllib.parse.quote(urllib.parse.unquote(p)) if k == 'path' else p 
                            for p in query_params[k]]) 
                  for k in ['type', 'path', 'security', 'encryption'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"vless://{host_port}?{sorted_query}"

def normalize_vmess(netloc, strict_dedup):
    """标准化 VMESS 链接。"""
    try:
        netloc = netloc + '=' * (4 - len(netloc) % 4) if len(netloc) % 4 else netloc
        decoded = base64.urlsafe_b64decode(netloc).decode('utf-8')
        match = re.search(r'"add":"([^"]+)".*"port":(\d+)', decoded)
        if match:
            host, port = match.groups()
            return f"vmess://{host}:{port}"
        logger.warning(f"VMESS JSON 解析失败，使用原始 netloc: {netloc}")
        return f"vmess://{netloc}"
    except Exception as e:
        logger.warning(f"VMESS 解析失败: {netloc} | 错误: {str(e)}")
        return f"vmess://{netloc}"

def normalize_trojan(netloc, query, strict_dedup):
    """标准化 Trojan 链接。"""
    host_port = netloc.split('@')[1] if strict_dedup and '@' in netloc else netloc
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: sorted(query_params[k]) for k in ['type', 'sni'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"trojan://{host_port}?{sorted_query}"

def normalize_ss(netloc, query, strict_dedup):
    """标准化 SS 链接。"""
    try:
        method_password_b64, host_port =的女0

        method_password_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', netloc)
        method_password_b64 += '=' * (4 - len(method_password_b64) % 4) if len(method_password_b64) % 4 else method_password_b64

        try:
            config = base64.urlsafe_b64decode(method_password_b64).decode('utf-8')
            method, password = config.split(':', 1) if ':' in config else (config, '')
        except Exception as e:
            logger.warning(f"SS Base64 解码失败: {method_password_b64} | 错误: {str(e)}")
            return f"ss://{host_port}" if strict_dedup else f"ss://{method_password_b64}@{host_port}"

        return f"ss://{host_port}" if strict_dedup else f"ss://{method}:{password}@{host_port}"
    except Exception as e:
        raise ValueError(f"SS 解析失败: {str(e)}")

def normalize_ssr(netloc, strict_dedup):
    """标准化 SSR 链接。"""
    try:
        netloc = netloc + '=' * (4 - len(netloc) % 4) if len(netloc) % 4 else netloc
        decoded = base64.urlsafe_b64decode(netloc).decode('utf-8')
        parts = decoded.split(':')
        if len(parts) >= 2:
            return f"ssr://{parts[0]}:{parts[1]}"
        return f"ssr://{netloc}"
    except Exception as e:
        logger.warning(f"SSR 解码失败: {netloc} | 错误: {str(e)}")
        return f"ssr://{netloc}"

def normalize_hysteria2(netloc, query, strict_dedup):
    """标准化 Hysteria2 链接。"""
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: sorted(query_params[k]) for k in ['type', 'obfs'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"hysteria2://{netloc}?{sorted_query}"

if __name__ == "__main__":
    nodes_file = os.path.join('data', '喧1

    clean_duplicate_nodes_advanced(nodes_file, debug_samples=10, strict_dedup=True)
