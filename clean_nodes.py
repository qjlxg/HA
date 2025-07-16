import os
import urllib.parse
import base64
import logging
from collections import defaultdict

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_cleaning_errors.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def clean_duplicate_nodes_advanced(file_path, output_path=None):
    """
    读取文件，基于协议特定解析逻辑移除重复行，保存到新文件，并提供详细统计数据。
    支持 VLESS、Trojan、SS 协议，忽略非关键字段（如备注、fp），记录解析失败的节点。
    """
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_cleaned{ext}"

    unique_node_keys = set()  # 存储去重键
    unique_lines_output = []  # 存储原始行
    error_lines = []         # 存储解析失败的行
    stats = defaultdict(int)  # 按协议统计节点数
    line_count = 0

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:  # 流式读取
                line_count += 1
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                # 分离核心部分和备注
                hash_index = stripped_line.find('#')
                core_part = stripped_line[:hash_index].strip() if hash_index != -1 else stripped_line
                remark = stripped_line[hash_index:] if hash_index != -1 else ''

                # 提取协议并计数
                protocol = core_part.split('://')[0].lower()
                stats[protocol] += 1

                # 解析并生成去重键
                try:
                    node_key = generate_node_key(core_part)
                    if node_key and node_key not in unique_node_keys:
                        unique_node_keys.add(node_key)
                        unique_lines_output.append(line)
                    else:
                        stats[f"{protocol}_duplicates"] += 1
                except Exception as e:
                    logging.error(f"解析节点失败 (行 {line_count}): {stripped_line} | 错误: {e}")
                    error_lines.append((line_count, stripped_line, str(e)))
                    stats[f"{protocol}_errors"] += 1
                    continue

        # 写入结果
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines_output)

        # 输出统计信息
        logging.info(f"✅ 成功清理重复节点。结果保存到: {output_path}")
        logging.info(f"📊 统计数据:")
        logging.info(f"  - 原始节点数: {line_count}")
        logging.info(f"  - 唯一节点数: {len(unique_lines_output)}")
        logging.info(f"  - 移除的重复节点数: {line_count - len(unique_lines_output)}")
        logging.info(f"  - 按协议分类:")
        for protocol in ['vless', 'trojan', 'ss']:
            logging.info(f"    - {protocol.upper()}: {stats[protocol]} 节点, {stats[f'{protocol}_duplicates']} 重复, {stats[f'{protocol}_errors']} 解析失败")
        if error_lines:
            logging.warning(f"解析失败的节点数: {len(error_lines)}，详情见 node_cleaning_errors.log")

        return True

    except FileNotFoundError:
        logging.error(f"❌ 文件未找到: {file_path}")
        return False
    except Exception as e:
        logging.error(f"❌ 清理节点时发生错误: {e}")
        return False

def generate_node_key(url):
    """根据协议生成去重键，仅包含关键字段"""
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    query = parsed.query

    if scheme == "vless":
        return normalize_vless(url, netloc, query)
    elif scheme == "trojan":
        return normalize_trojan(url, netloc, query)
    elif scheme == "ss":
        return normalize_ss(url, netloc)
    else:
        # 未识别协议，直接返回原始 URL（可扩展为其他协议）
        return url

def normalize_vless(url, netloc, query):
    """标准化 VLESS 链接，忽略非关键字段"""
    # 提取 UUID 和 host:port
    uuid_host_port = netloc
    # 解析查询参数，仅保留关键字段
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: query_params[k] for k in ['type', 'path', 'security', 'encryption'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"vless://{uuid_host_port}?{sorted_query}"

def normalize_trojan(url, netloc, query):
    """标准化 Trojan 链接"""
    # Trojan 的 netloc 是 password@host:port
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: query_params[k] for k in ['type', 'sni'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"trojan://{netloc}?{sorted_query}"

def normalize_ss(url, netloc):
    """标准化 SS 链接"""
    try:
        if '@' in netloc:
            b64_config, host_port = netloc.split('@', 1)
            config = base64.urlsafe_b64decode(b64_config + '===').decode('utf-8')
            return f"ss://{config}@{host_port}"
        else:
            config = base64.urlsafe_b64decode(netloc + '===').decode('utf-8')
            return f"ss://{config}"
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"无法解析 SS 配置: {e}")

if __name__ == "__main__":
    nodes_file = os.path.join('data', 'a.isidomain.web.id.txt')
    clean_duplicate_nodes_advanced(nodes_file)
