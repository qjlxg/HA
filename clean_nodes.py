import os

def clean_duplicate_nodes_advanced(file_path):
    """
    读取文件，根据协议特定（有限的）解析逻辑移除重复行，
    并将唯一的行写回文件。

    尝试对 VLESS/VMESS 链接的查询参数进行简单排序以标准化，并忽略备注。

    !!! 重要局限性警告 !!!
    此脚本受到严格限制，无法使用 Python 标准库中的模块，如 `urllib.parse`, `base64`, 或 `json`。
    因此，它无法正确解析复杂的 URL (例如处理 URL 编码)，解码 Base64 编码的数据，
    或处理某些代理链接中（例如 VMESS/VLESS 的 JSON 配置，SS/SSR 编码）的 JSON 结构。
    它依赖于基本的字符串操作，这在处理复杂情况时极易出错且不健壮。
    为了实现真正健壮的去重，需要使用支持全面协议解析的专业库或客户端。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        unique_node_identifiers = set() # 用于存储节点的标准化标识，用于去重
        unique_lines_output = []        # 用于存储最终要输出的唯一完整行

        for line in lines:
            stripped_line = line.strip()
            if not stripped_line: # 跳过空行
                continue

            # 1. 分离核心部分和备注部分
            # 备注通常在 '#' 之后，我们去重时会忽略它，但原始行会保留备注。
            hash_index = stripped_line.find('#')
            if hash_index != -1:
                # 核心部分：从开始到 '#'
                core_part_with_query = stripped_line[:hash_index].strip()
            else:
                # 如果没有 '#', 则整个去除空白的行就是核心部分
                core_part_with_query = stripped_line

            # 2. 根据协议类型进行有限的初步标准化
            # 这是我们去重比较的“标准化标识符”
            normalized_identifier = core_part_with_query

            # 针对 VLESS/VMESS 链接：尝试对查询参数进行排序
            # 这种方法非常简陋，仅在参数形式为 key=value&key=value 且值中不含特殊字符时有效。
            # 无法处理URL编码、重复键名等复杂情况。
            if normalized_identifier.startswith("vless://") or normalized_identifier.startswith("vmess://"):
                question_mark_index = normalized_identifier.find('?')
                if question_mark_index != -1:
                    base_url = normalized_identifier[:question_mark_index]
                    query_string = normalized_identifier[question_mark_index + 1:]
                    
                    params = query_string.split('&')
                    # 过滤掉空的参数字符串（例如 "&&" 导致的空字符串）
                    params = [p.strip() for p in params if p.strip()]
                    params.sort() # 对参数进行字母排序以标准化，忽略顺序差异
                    
                    normalized_identifier = base_url + '?' + '&'.join(params)
                # 如果没有问号，则保持原样，因为没有查询参数。
            
            # 重要局限性：
            # - SS/SSR 链接 (ss://, ssr://) 包含 Base64 编码的数据，此脚本无法解码和解析。
            # - Trojan/Hysteria2 等协议的特定参数解析也无法实现。
            # - 无法处理 VLESS/VMESS 中可能包含的复杂 JSON 配置。

            # 3. 使用标准化标识符进行去重判断
            if normalized_identifier not in unique_node_identifiers:
                unique_node_identifiers.add(normalized_identifier)
                # 如果是新的唯一节点，则将原始完整行（包括备注和换行符）添加到输出列表
                unique_lines_output.append(line)
            # 否则（发现重复），则跳过此行

        # 写入唯一的节点到文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines_output)
        
        print(f"✅ 成功清理重复节点。唯一节点已保存到: {file_path}")
        print(f"原始节点数: {len(lines)}")
        print(f"清理后唯一节点数: {len(unique_lines_output)}")
        return True
    except FileNotFoundError:
        print(f"❌ 错误：文件未找到在 {file_path}")
        return False
    except Exception as e:
        print(f"❌ 清理节点时发生错误: {e}")
        return False

if __name__ == "__main__":
    nodes_file = os.path.join('data', 'a.isidomain.web.id.txt')
    clean_duplicate_nodes_advanced(nodes_file)
