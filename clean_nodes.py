import os
import urllib.parse
import base64
import logging
import re
from collections import defaultdict

# 配置日志
# 日志级别设置为 INFO，格式包含时间、级别和消息
# 日志会输出到文件 'node_cleaning_errors.log' 和控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_cleaning_errors.log', encoding='utf-8'), # 将日志写入文件
        logging.StreamHandler() # 将日志输出到控制台
    ]
)

def clean_duplicate_nodes_advanced(file_path, output_path=None, debug_samples=10, strict_dedup=True):
    """
    读取文件，基于协议特定解析逻辑移除重复行，保存到新文件，并提供详细统计数据。
    支持 VLESS、Trojan、SS 协议，忽略非关键字段（如备注、fp），记录解析失败的节点。

    参数:
    file_path (str): 包含节点链接的输入文件路径。
    output_path (str, optional): 清理后节点输出文件路径。如果为 None，则在原文件名后添加 _cleaned。
    debug_samples (int): 记录前 N 个去重键用于调试。
    strict_dedup (bool): 如果为 True，仅比较 host:port 和关键参数，忽略 uuid/password。
                         如果为 False，则 uuid/password 也将作为去重的一部分。
    """
    # 如果未指定输出路径，则自动生成一个
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_cleaned{ext}"

    unique_node_keys = set()  # 存储去重键，用于判断节点是否唯一
    unique_lines_output = []  # 存储最终要输出的唯一完整行（包含原始备注和换行符）
    error_lines = []          # 存储解析失败的行及其错误信息
    stats = defaultdict(int)  # 存储各种统计数据，如协议类型、重复数、错误数
    line_count = 0            # 原始文件总行数
    debug_keys = []           # 调试用的去重键样本，用于查看生成的键是否符合预期

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:  # 逐行读取文件，适合大文件处理
                line_count += 1
                stripped_line = line.strip() # 移除行首尾空白字符
                if not stripped_line: # 跳过空行
                    stats['empty_lines'] += 1
                    continue

                # 分离核心部分和备注部分
                # 备注通常在 '#' 之后，去重时会忽略它，但原始行会保留备注。
                hash_index = stripped_line.find('#')
                core_part = stripped_line[:hash_index].strip() if hash_index != -1 else stripped_line
                # remark = stripped_line[hash_index:] if hash_index != -1 else '' # 备注在此脚本中未直接使用，但可保留

                # 提取协议类型并进行计数
                protocol = core_part.split('://')[0].lower()
                stats[protocol] += 1 # 统计每种协议的节点数量

                # 解析节点并生成去重键
                try:
                    node_key = generate_node_key(core_part, strict_dedup)
                    if node_key: # 确保成功生成了去重键
                        if len(debug_keys) < debug_samples: # 记录少量去重键用于调试
                            debug_keys.append((protocol, node_key))
                        
                        # 如果生成的去重键是新的，则添加到集合并保留原始行
                        if node_key not in unique_node_keys:
                            unique_node_keys.add(node_key)
                            unique_lines_output.append(line) # 保留原始行，包括换行符和备注
                        else:
                            # 如果去重键已存在，则认为是重复节点
                            stats[f"{protocol}_duplicates"] += 1
                    else:
                        # 如果 generate_node_key 返回 None 或空字符串，则认为无法生成去重键
                        raise ValueError("无法生成去重键")
                except Exception as e:
                    # 捕获解析过程中发生的任何错误
                    logging.error(f"解析节点失败 (行 {line_count}): {stripped_line} | 错误: {e}")
                    error_lines.append((line_count, stripped_line, str(e))) # 记录错误详情
                    stats[f"{protocol}_errors"] += 1 # 统计解析失败的节点数量
                    continue # 继续处理下一行

        # 将唯一的节点写入输出文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines_output)

        # 输出详细的统计信息到控制台和日志文件
        logging.info(f"✅ 成功清理重复节点。结果保存到: {output_path}")
        logging.info(f"📊 统计数据:")
        logging.info(f"  - 原始节点数: {line_count}")
        logging.info(f"  - 有效节点数 (非空行): {line_count - stats['empty_lines']}")
        logging.info(f"  - 唯一节点数: {len(unique_lines_output)}")
        # 计算总重复节点数，只包括我们明确处理的协议
        total_duplicates = sum(stats[f'{p}_duplicates'] for p in ['vless', 'trojan', 'ss'])
        logging.info(f"  - 重复节点数: {total_duplicates}")
        logging.info(f"  - 解析失败节点数: {len(error_lines)}")
        logging.info(f"  - 空行数: {stats['empty_lines']}")
        logging.info(f"  - 按协议分类:")
        # 遍历并打印每种协议的详细统计
        for protocol in ['vless', 'trojan', 'ss', 'vmess', 'ssr', 'hysteria2', 'unknown']: # 包含所有可能协议
            if stats[protocol] > 0 or stats[f'{protocol}_duplicates'] > 0 or stats[f'{protocol}_errors'] > 0:
                logging.info(f"    - {protocol.upper()}: 原始 {stats[protocol]} 节点, {stats[f'{protocol}_duplicates']} 重复, {stats[f'{protocol}_errors']} 解析失败")
        
        if error_lines:
            logging.warning(f"解析失败的节点数: {len(error_lines)}，详情已记录到 node_cleaning_errors.log")
        
        if debug_keys:
            logging.info(f"🔍 调试: 前 {len(debug_keys)} 个去重键样本:")
            for i, (proto, key) in enumerate(debug_keys, 1):
                logging.info(f"    {i}. {proto.upper()}: {key}")

        return True

    except FileNotFoundError:
        logging.error(f"❌ 文件未找到: {file_path}")
        return False
    except Exception as e:
        logging.error(f"❌ 清理节点时发生意外错误: {e}")
        return False

def generate_node_key(url, strict_dedup):
    """
    根据协议类型生成节点的去重键。
    这个键是节点的标准化表示，用于识别重复项。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() # 协议类型，如 'vless', 'trojan', 'ss'
        netloc = parsed.netloc.lower() # 网络位置，通常是 '用户ID@服务器:端口' 或 '服务器:端口'
        query = parsed.query           # 查询字符串，如 'type=ws&security=tls'

        # 根据协议类型调用相应的标准化函数
        if scheme == "vless":
            return normalize_vless(netloc, query, strict_dedup)
        elif scheme == "vmess":
            # VMESS 通常是 Base64 编码的 JSON，这里进行简化处理
            # 完整解析需要 json 和 base64 库，这里仅尝试提取 host:port
            try:
                # 尝试解码 Base64 部分，并解析 JSON（如果存在）
                # 这是一个简化的尝试，可能无法处理所有 VMESS 变体
                decoded_vmess = base64.urlsafe_b64decode(netloc + '===').decode('utf-8')
                # 尝试从 JSON 中提取 host 和 port
                # 实际的 VMESS JSON 结构可能更复杂，这里仅作示意
                match = re.search(r'"add":"([^"]+)".*"port":(\d+)', decoded_vmess)
                if match:
                    host = match.group(1)
                    port = match.group(2)
                    return f"vmess://{host}:{port}"
                else:
                    # 如果无法解析 JSON，退化为使用原始 netloc
                    return f"vmess://{netloc}"
            except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                logging.warning(f"VMESS Base64/JSON 解析失败，使用原始 netloc: {netloc} | 错误: {e}")
                return f"vmess://{netloc}"
        elif scheme == "trojan":
            return normalize_trojan(netloc, query, strict_dedup)
        elif scheme == "ss":
            return normalize_ss(netloc, url, strict_dedup)
        elif scheme == "ssr":
            # SSR 协议通常是 Base64 编码，且结构比 SS 更复杂
            # 这里仅做非常简化的处理，可能无法完全去重
            try:
                # 尝试解码 Base64 部分
                decoded_ssr = base64.urlsafe_b64decode(netloc + '===').decode('utf-8')
                # SSR 链接通常是 host:port:protocol:method:obfs:password_base64/?params
                # 这里只取 host:port 作为去重键
                parts = decoded_ssr.split(':')
                if len(parts) >= 2:
                    host = parts[0]
                    port = parts[1]
                    return f"ssr://{host}:{port}"
                else:
                    return f"ssr://{netloc}" # 退化为使用原始 netloc
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                logging.warning(f"SSR Base64 解码失败，使用原始 netloc: {netloc} | 错误: {e}")
                return f"ssr://{netloc}"
        elif scheme == "hysteria2":
            # Hysteria2 链接通常是 hysteria2://<server>:<port>?<params>
            # 提取 server:port 和关键参数
            host_port = netloc
            query_params = urllib.parse.parse_qs(query)
            # 假设 type 和 obfs 是关键参数
            key_params = {k: sorted(query_params[k]) for k in ['type', 'obfs'] if k in query_params}
            sorted_query = urllib.parse.urlencode(key_params, doseq=True)
            return f"hysteria2://{host_port}?{sorted_query}"
        else:
            # 对于未知或未处理的协议，退化为使用原始 URL 的小写形式作为去重键
            # 这种方式可能无法有效去重，但能避免脚本崩溃
            logging.warning(f"未知或未处理的协议: {scheme}. 使用原始 URL 作为去重键。")
            return url.lower()
    except Exception as e:
        # 捕获 URL 解析或协议处理中的任何错误
        raise ValueError(f"生成节点键失败: {e}")

def normalize_vless(netloc, query, strict_dedup):
    """标准化 VLESS 链接，忽略非关键字段。"""
    # 如果 strict_dedup 为 True，则忽略 UUID 部分，只比较 host:port
    if strict_dedup and '@' in netloc:
        try:
            _, host_port = netloc.split('@', 1)
        except ValueError: # 防止没有 '@' 符号的情况
            host_port = netloc
    else:
        host_port = netloc # 包含 UUID

    query_params = urllib.parse.parse_qs(query) # 解析查询参数
    
    # 定义 VLESS 的关键去重参数
    # 'security' (tls/none), 'type' (ws/grpc/tcp), 'path', 'encryption' (none)
    # 'fp' (fingerprint) 和 'sni' 通常是可选且不影响核心连接的，在此处忽略。
    key_param_names = ['type', 'path', 'security', 'encryption']
    key_params = {}
    for k in key_param_names:
        if k in query_params:
            # 对参数值进行排序，以处理参数值顺序不同的情况 (如 path=/a vs path=/b)
            # 对 path 进行 URL 解码再编码，以标准化其形式
            if k == 'path':
                key_params[k] = [urllib.parse.quote(urllib.parse.unquote(p)) for p in sorted(query_params[k])]
            else:
                key_params[k] = sorted(query_params[k])
    
    # 将关键参数重新编码为查询字符串，并排序确保一致性
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    
    return f"vless://{host_port}?{sorted_query}"

def normalize_trojan(netloc, query, strict_dedup):
    """标准化 Trojan 链接，忽略非关键字段。"""
    # 如果 strict_dedup 为 True，则忽略密码部分，只比较 host:port
    if strict_dedup and '@' in netloc:
        try:
            _, host_port = netloc.split('@', 1)
        except ValueError:
            host_port = netloc
    else:
        host_port = netloc # 包含密码

    query_params = urllib.parse.parse_qs(query) # 解析查询参数
    
    # 定义 Trojan 的关键去重参数
    # 'type' (ws/grpc), 'sni' (服务器名称指示)
    key_param_names = ['type', 'sni']
    key_params = {}
    for k in key_param_names:
        if k in query_params:
            key_params[k] = sorted(query_params[k])
    
    sorted_query = urllib.parse.urlencode(key_params, doseq=True)
    
    return f"trojan://{host_port}?{sorted_query}"

def normalize_ss(netloc, url, strict_dedup):
    """标准化 SS 链接，增强容错性并提取关键信息。"""
    try:
        # SS 链接格式通常为 method:password@server:port 或 base64_encoded_config@server:port
        # 我们需要先处理 Base64 编码的部分
        
        method_password_b64 = ''
        host_port = ''

        if '@' in netloc:
            method_password_b64, host_port = netloc.split('@', 1)
        else:
            # 如果没有 @ 符号，通常是只有 Base64 编码的配置，没有明确的服务器地址在 netloc 中
            # 这种情况下，整个 netloc 可能是 Base64 编码的配置
            method_password_b64 = netloc

        # 清理 Base64 字符串，移除任何非 Base64 字符
        method_password_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', method_password_b64)
        
        # 确保 Base64 字符串长度是 4 的倍数，进行填充
        missing_padding = len(method_password_b64) % 4
        if missing_padding != 0:
            method_password_b64 += '=' * (4 - missing_padding)

        config_decoded = ''
        try:
            # 尝试 Base64 解码
            config_decoded = base64.urlsafe_b64decode(method_password_b64).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logging.warning(f"SS Base64 解码失败，可能 Base64 格式不正确: {method_password_b64} | 错误: {e}")
            # 如果解码失败，退化为使用原始 Base64 字符串作为标识
            if strict_dedup:
                return f"ss://{host_port}" # 严格模式下只用 host:port
            return f"ss://{method_password_b64}@{host_port}" # 非严格模式下保留原始编码

        # 解析解码后的配置 (method:password)
        method = ''
        password = ''
        if ':' in config_decoded:
            method, password = config_decoded.split(':', 1)
        else:
            # 如果解码后没有冒号，可能是只有方法或只有密码，或者格式不正确
            logging.warning(f"SS 解码后配置格式异常: {config_decoded}. 使用原始解码内容作为标识。")
            method = config_decoded # 视为整个是方法或密码

        # 构建去重键
        if strict_dedup:
            # 严格去重模式下，只比较 host:port
            return f"ss://{host_port}"
        else:
            # 非严格模式下，包含 method 和 password
            return f"ss://{method}:{password}@{host_port}"

    except Exception as e:
        # 捕获 SS 链接处理中的任何其他错误
        raise ValueError(f"无法解析 SS 配置: {e}")

if __name__ == "__main__":
    # 定义节点文件路径
    # 确保 'data' 目录存在，并且 'a.isidomain.web.id.txt' 文件在其中
    nodes_file = os.path.join('data', 'a.isidomain.web.id.txt')
    
    # 调用主清理函数
    # debug_samples=10: 打印前10个去重键用于调试
    # strict_dedup=True: 启用严格去重模式（忽略 UUID/密码，只比较 host:port 和关键参数）
    clean_duplicate_nodes_advanced(nodes_file, debug_samples=10, strict_dedup=True)
