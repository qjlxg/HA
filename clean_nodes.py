import os
import urllib.parse
import base64
import logging
import re
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

def clean_duplicate_nodes_advanced(file_path, output_path=None, debug_samples=10, strict_dedup=False):
    """
    读取文件，基于协议特定解析逻辑移除重复行，保存到新文件，并提供详细统计数据。
    支持 VLESS、Trojan、SS 协议，忽略非关键字段（如备注、fp），记录解析失败的节点。
    debug_samples: 记录前 N 个去重键用于调试。
    strict_dedup: 如果为 True，仅比较 host:port 和关键参数，忽略 uuid/password。
    """
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_cleaned{ext}"

    unique_node_keys = set()  # 存储去重键
    unique_lines_output = []  # 存储原始行
    error_lines = []         # 存储解析失败的行
    stats = defaultdict(int)  # 按协议统计节点数
    line_count = 0
    debug_keys = []          # 调试用的去重键样本

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:  # 流式读取
                line_count += 1
                stripped_line = line.strip()
                if not stripped_line:
                    stats['empty_lines'] += 1
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
                    node_key = generate_node_key(core_part, strict_dedup)
                    if node_key:
                        # 记录前 debug_samples 个去重键用于调试
                        if len(debug_keys) < debug_samples:
                            debug_keys.append((protocol, node_key))
                        if node_key not in unique_node_keys:
                            unique_node_keys.add(node_key)
                            unique_lines_output.append(line)
                        else:
                            stats[f"{protocol}_duplicates"] += 1
                    else:
                        raise ValueError("无法生成去重键")
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
        logging.info(f"  - 有效节点数: {line_count - stats['empty_lines']}")
        logging.info(f"  - 唯一节点数: {len(unique_lines_output)}")
        logging.info(f"  - 重复节点数: {sum(stats[f'{p}_duplicates'] for p in ['vless', 'trojan', 'ss'])}")
        logging.info(f"  - 解析失败节点数: {len(error_lines)}")
        logging.info(f"  - 空行数: {stats['empty_lines']}")
        logging.info(f"  - 按协议分类:")
        for protocol in ['vless', 'trojan', 'ss']:
            logging.info(f"    - {protocol.upper()}: {stats[protocol]} 节点, {stats[f'{protocol}_duplicates']} 重复, {stats[f'{protocol}_errors']} 解析失败")
        if error_lines:
            logging.warning(f"解析失败的节点数: {len(error_lines)}，详情见 node_cleaning_errors.log")
        if debug_keys:
            logging.info(f"🔍 调试: 前 {len(debug_keys)} 个去重键样本:")
            for i, (proto, key) in enumerate(debug_keys, 1):
                logging.info(f"    {i}. {proto.upper()}: {key}")

        return True

    except FileNotFoundError:
        logging.error(f"❌ 文件未找到: {file_path}")
        return False
    except Exception as e:
        logging.error(f"❌ 清理节点时发生错误: {e}")
        return False

def generate_node_key(url, strict_dedup=False):
    """根据协议生成去重键，仅包含关键字段"""
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()  # 转换为小写以避免大小写差异
        query = parsed.query

        if scheme == "vless":
            return normalize_vless(netloc, query, strict_dedup)
        elif scheme == "trojan":
            return normalize_trojan(netloc, query, strict_dedup)
        elif scheme == "ss":
            return normalize_ss(netloc, url)
        else:
            # 未识别协议，直接返回原始 URL
            return url.lower()
    except Exception as e:
        raise ValueError(f"解析 URL 失败: {e}")

def normalize_vless(netloc, query, strict_dedup):
    """标准化 VLESS 链接，忽略非关键字段"""
    # 如果 strict_dedup=True，仅使用 host:port 和关键参数，忽略 UUID
    if strict_dedup:
        try:
            _, host_port = netloc.split('@', 1)
        except ValueError:
            host_port = netloc
    else:
        host_port = netloc
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: sorted(query_params[k]) for k in ['type', 'path', 'security', 'encryption'] if k in query_params}
    # 规范化 path 参数
    if 'path' in key_params:
        key_params['path'] = [urllib.parse.quote(urllib.parse.unquote(p)) for p in key_params['path']]
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"vless://{host_port}?{sorted_query}"

def normalize_trojan(netloc, query, strict_dedup):
    """标准化 Trojan 链接"""
    # 如果 strict_dedup=True，仅使用 host:port，忽略 password
    if strict_dedup:
        try:
            _, host_port = netloc.split('@', 1)
        except ValueError:
            host_port = netloc
    else:
        host_port = netloc
    query_params = urllib.parse.parse_qs(query)
    key_params = {k: sorted(query_params[k]) for k in ['type', 'sni'] if k in query_params}
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    return f"trojan://{host_port}?{sorted_query}"

def normalize_ss(netloc, url):
    """标准化 SS 链接，增强容错性"""
    try:
        if '@' in netloc:
            b64_config, host_port = netloc.split('@', 1)
            # 清理 Base64 字符串
            b64_config = re.sub(r'[^A-Za-z0-9+/=]', '', b64_config)
            # 验证 Base64 合法性
            if not re.match(r'^[A-Za-z0-9+/=]+$', b64_config):
                raise ValueError(f"无效的 Base64 字符串: {b64_config}")
            try:
                config = base64.urlsafe_b64decode(b64_config + '===').decode('utf-8')
                # 验证 method:password 格式
                if ':' not in config:
                    raise ValueError(f"无效的 SS 配置格式: {config}")
                return f"ss://{config}@{host_port}"
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                logging.warning(f"SS Base64 解码失败，使用原始 Base64 作为键: {b64_config} | 错误: {e}")
                return f"ss://{b64_config}@{host_port}"
        else:
            # 清理并验证 Base64
            netloc = re.sub(r'[^A-Za-z0-9+/=]', '', netloc)
            config = base64.urlsafe_b64decode(netloc + '===').decode('utf-8', errors='ignore')
            return f"ss://{config}"
    except Exception as e:
        raise ValueError(f"无法解析 SS 配置: {e}")

if __name__ == "__main__":
    nodes_file = os.path.join('data', 'a.isidomain.web.id.txt')
    clean_duplicate_nodes_advanced(nodes_file, debug_samples=10)
