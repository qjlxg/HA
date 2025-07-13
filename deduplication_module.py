import os
import geoip2.database
import re
import asyncio
import aiofiles
import json
import base64
import collections
import logging
import socket
from urllib.parse import urlparse, parse_qs, urlencode, unquote

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义数据输入和输出目录
INPUT_DATA_DIR = "data" # all.txt 和 GeoLite2-Country.mmdb 所在的目录
OUTPUT_SUB_DIR = "sub"  # deduplicated_nodes.txt 所在的目录

ALL_NODES_FILE = os.path.join(INPUT_DATA_DIR, "all.txt")
GEOLITE_DB_PATH = os.path.join(INPUT_DATA_DIR, "GeoLite2-Country.mmdb") # GeoLite2 数据库现在在 data 目录下
DEDUP_NODES_FILE = os.path.join(OUTPUT_SUB_DIR, "deduplicated_nodes.txt")
DNS_CACHE_FILE = os.path.join(OUTPUT_SUB_DIR, "dns_cache.json") # 新增：DNS 缓存文件路径

# 确保必要的目录都存在
os.makedirs(INPUT_DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_SUB_DIR, exist_ok=True)

# 定义需要解析 IP 的协议
IP_EXTRACT_PATTERNS = { # 注意：这里是正确的变量名
    "vmess": r"(?:\"add\"|\"addr\"|\"host\"|\"sni\")\s*:\s*\"([^\"]+)\"",
    "vless": r"vless:\/\/[a-zA-Z0-9\-]+@([^:]+)",
    "trojan": r"trojan:\/\/.*@([^:]+)",
    "ss": r"ss:\/\/([a-zA-Z0-9+/=_-]+)@([^:]+)",
    "ssr": r"ssr:\/\/([a-zA-Z0-9+/=_-]+)@([^:]+)",
    "hysteria2": r"hysteria2:\/\/.*@([^:]+)",
}

def is_valid_ip(ip_str: str) -> bool:
    """Checks if the string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip_str)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_str)
            return True
        except socket.error:
            return False

def is_valid_domain(domain_str: str) -> bool:
    """Checks if the string is a plausible domain name."""
    # 更严格的域名正则，允许中划线，但不能在开头或结尾
    # 限制总长度，每个标签长度
    if not domain_str or len(domain_str) > 255:
        return False
    if domain_str.endswith('.'): # strip trailing dot
        domain_str = domain_str[:-1]
        
    allowed = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
    return bool(allowed.match(domain_str))

def is_valid_host(host_str: str) -> bool:
    """Checks if the string is a valid IP address or a plausible domain name."""
    return is_valid_ip(host_str) or is_valid_domain(host_str)

def decode_base64_safe(data: str) -> str:
    """尝试进行URL安全和标准base64解码，并处理填充"""
    data = data.strip().replace('<br />', '')
    if not re.fullmatch(r'[A-Za-z0-9+/=_]+', data):
        return ""

    for _ in range(4): # 尝试添加0到3个填充字符
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            data += '='
    return ""

def _clean_json_node(json_data: dict) -> dict:
    """
    内部辅助函数，用于清理 JSON 节点中的不必要字段。
    ⭐ 关键修改：去除了 'ps' (名称/备注) 字段，使其不影响去重判断。
    """
    clean_json = {}
    # 移除 'ps' (名称/备注) 字段，因为它不影响节点的实际配置，但会影响去重
    keys_to_keep = ["v", "add", "port", "id", "net", "type", "tls", "sni", "host", "path"]
    for key in keys_to_keep:
        if key in json_data:
            clean_json[key] = json_data[key]
    return clean_json

def simplify_node(node: str) -> str:
    """
    简化节点字符串，移除不必要的参数，只保留协议和核心信息，并标准化URL参数顺序。
    此函数是去重的核心。
    """
    node_without_name = node.split('#')[0] # 总是移除名称部分
    if not node_without_name:
        return ""

    try:
        if node_without_name.startswith("ss://") or node_without_name.startswith("vmess://"):
            protocol_prefix = "ss://" if node_without_name.startswith("ss://") else "vmess://"
            encoded_part = node_without_name[len(protocol_prefix):]
            decoded_content = decode_base64_safe(encoded_part)

            if not decoded_content:
                logging.debug(f"Base64解码失败，跳过: {node_without_name[:50]}...")
                return ""

            if protocol_prefix == "vmess://":
                try:
                    node_json = json.loads(decoded_content)
                    if isinstance(node_json, dict):
                        clean_json = _clean_json_node(node_json)
                        # ensure_ascii=False 允许中文，separators=(',', ':') 移除空格减少大小
                        return f"{protocol_prefix}{base64.b64encode(json.dumps(clean_json, separators=(',', ':')).encode()).decode().rstrip('=')}"
                except json.JSONDecodeError:
                    logging.debug(f"VMess JSON解码失败，原始内容: {decoded_content[:50]}...")
                    # 如果不是标准JSON，VMess就无法处理，直接返回原始不带名称的部分
                    pass
            elif protocol_prefix == "ss://":
                # Shadowsocks Base64解码后通常是 method:password@server:port 或 password@server:port
                # 尝试标准化为 password@server:port (method有时在SS中是可选的或通过其他方式指定)
                parts = decoded_content.split('@')
                if len(parts) >= 2:
                    # 尝试进一步解析 method:password 部分
                    first_part = parts[0]
                    server_port_part = parts[1]
                    
                    method_password_match = re.match(r"([^:]+):(.+)", first_part)
                    if method_password_match:
                        # 假设是 method:password@server:port
                        method = method_password_match.group(1)
                        password = method_password_match.group(2)
                    else:
                        # 假设是 password@server:port，method可能由外部定义或默认
                        password = first_part
                        method = "" # 留空或默认
                    
                    # 尝试解析 server:port
                    server_match = re.match(r"([^:]+):(\d+)", server_port_part)
                    if server_match:
                        server = server_match.group(1)
                        port = server_match.group(2)

                        # 构建一个标准化字符串，忽略method的缺失或差异
                        # 只用 server, port, password 进行去重，method可以作为额外的参数
                        # 如果需要method参与去重，可以包含 method
                        simplified_ss = f"{password}@{server}:{port}"
                        if method: # 如果有方法，包含进去，但确保顺序
                            simplified_ss = f"{method}:{simplified_ss}"
                        
                        return f"ss://{base64.b64encode(simplified_ss.encode()).decode().rstrip('=')}"
                else:
                    logging.debug(f"SS节点结构不匹配，原始内容: {decoded_content[:50]}...")
                    pass
            
            # 如果以上解析失败，作为回退返回原始不带名称的部分
            return node_without_name

        elif node_without_name.startswith(("vless://", "trojan://", "hysteria2://")):
            parsed_url = urlparse(node_without_name)
            
            # 提取核心部分: 方案, 身份/密码, 服务器, 端口
            protocol = parsed_url.scheme
            userinfo = parsed_url.username # for vless/trojan id/password
            server = parsed_url.hostname
            port = parsed_url.port

            if not (protocol and userinfo and server and port):
                logging.debug(f"URL解析失败，核心信息不完整: {node_without_name[:80]}...")
                return ""

            # 解析并排序查询参数，确保去重时参数顺序不影响
            query_params = parse_qs(parsed_url.query)
            
            # 将多值参数列表转换为单值（如果合适），或者保留为列表并转换为元组以便排序
            # 为了去重，我们将所有参数值转换为字符串，并对键进行排序
            sorted_params = []
            for key in sorted(query_params.keys()):
                values = query_params[key]
                # 对于单个值，直接取第一个；对于多个值，排序并用逗号连接
                normalized_value = ','.join(sorted([unquote(v) for v in values]))
                sorted_params.append(f"{key}={normalized_value}")

            # 重新构建查询字符串
            new_query = "&".join(sorted_params)
            
            # 重新构建一个标准化的URL字符串
            simplified_url = f"{protocol}://{userinfo}@{server}:{port}"
            if new_query:
                simplified_url += f"?{new_query}"
            
            return simplified_url

        elif node_without_name.startswith("ssr://"):
            encoded_part = node_without_name[len("ssr://"):]
            decoded_ssr = decode_base64_safe(encoded_part)

            if not decoded_ssr:
                logging.debug(f"SSR Base64解码失败，跳过: {node_without_name[:50]}...")
                return ""
            
            # SSR 格式通常是 server:port:protocol:method:obfsmode:password_base64/?params_base64
            # 或 server:port:protocol:method:obfsmode:password_base64
            parts = decoded_ssr.split(':')
            if len(parts) < 6: # 最少需要 server:port:protocol:method:obfsmode:password
                logging.debug(f"SSR节点解析失败，部分不足: {decoded_ssr[:50]}...")
                return ""
            
            # 提取核心组件
            server = parts[0]
            port = parts[1]
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            
            # 密码部分可能包含 ?params
            password_and_params = parts[5]
            password_match = re.match(r"([^/?]+)", password_and_params)
            password = password_match.group(1) if password_match else ""

            # 进一步解析并标准化参数 (如果有的话)
            params_part = ""
            if '?' in password_and_params:
                params_part = password_and_params.split('?', 1)[1]
            
            query_params = parse_qs(params_part)
            sorted_params = []
            for key in sorted(query_params.keys()):
                values = query_params[key]
                normalized_value = ','.join(sorted([unquote(v) for v in values]))
                sorted_params.append(f"{key}={normalized_value}")
            
            new_query = "&".join(sorted_params)

            # 重新构建一个标准化形式的SSR字符串
            # 确保顺序一致性
            simplified_ssr = f"{server}:{port}:{protocol}:{method}:{obfs}:{password}"
            if new_query:
                simplified_ssr += f"?{new_query}"
            
            return f"ssr://{base64.urlsafe_b64encode(simplified_ssr.encode()).decode().rstrip('=')}"

    except Exception as e:
        logging.debug(f"简化节点时发生错误 '{e}'，节点: {node_without_name[:80]}...")
        # 发生任何错误时，返回原始不带名称的部分作为回退，避免丢弃
        return node_without_name

    # 如果无法识别协议或处理，返回原始不带名称的部分
    return node_without_name

def get_country_from_ip(ip_address: str, reader) -> str:
    """使用 GeoLite2 数据库获取 IP 对应的国家名称，处理无效 IP"""
    try:
        response = reader.country(ip_address)
        # 尝试获取中文名称
        if 'zh-CN' in response.country.names:
            return response.country.names['zh-CN']
        # 如果没有中文名称，尝试获取英文名称作为备用
        elif 'en' in response.country.names:
            logging.warning(f"IP {ip_address} 无法获取 'zh-CN' 国家名称，使用 'en' 作为备用。")
            return response.country.names['en']
        else:
            logging.warning(f"IP {ip_address} 无法获取 'zh-CN' 或 'en' 国家名称。")
            return "未知地区" # 如果都没有，则返回未知地区
    except geoip2.errors.AddressNotFoundError:
        logging.debug(f"GeoIP 未找到地址: {ip_address}")
        return "未知/私有IP"
    except ValueError as e:
        logging.error(f"解析 IP 地址 {ip_address} 时发生错误: {e}")
        return "无效IP格式"
    except Exception as e:
        # 捕获其他未预期错误
        logging.error(f"GeoIP 查询时发生意外错误，IP: {ip_address}. 错误: {e}", exc_info=True)
        return "未知错误"

async def process_and_deduplicate_nodes():
    """
    读取 all.txt 中的所有节点，去重，进行 GeoIP 查询并重命名，
    最后将处理后的节点写入 deduplicated_nodes.txt。
    """
    if not os.path.exists(ALL_NODES_FILE):
        logging.error(f"错误：输入文件 {ALL_NODES_FILE} 不存在。请确保上游脚本已将其生成。")
        return

    if not os.path.exists(GEOLITE_DB_PATH):
        logging.error(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        logging.info("下载地址：https://dev.maxmind.com/geoip/downloads/geo2/country/?lang=zh-Hans")
        logging.info(f"请下载 GeoLite2-Country.mmdb 并将其放置在 '{INPUT_DATA_DIR}' 文件夹中。")
        return

    all_nodes = set()
    async with aiofiles.open(ALL_NODES_FILE, 'r', encoding='utf-8') as f:
        async for line in f:
            all_nodes.add(line.strip())

    logging.info(f"原始节点数量: {len(all_nodes)}")

    simplified_to_original = {}
    for node in all_nodes:
        simplified_node = simplify_node(node)
        if simplified_node and simplified_node not in simplified_to_original:
            simplified_to_original[simplified_node] = node
            
    logging.info(f"去重后（简化后）节点数量: {len(simplified_to_original)}")

    processed_nodes_with_location = []
    
    # DNS 缓存加载
    dns_cache = {}
    if os.path.exists(DNS_CACHE_FILE):
        try:
            async with aiofiles.open(DNS_CACHE_FILE, 'r', encoding='utf-8') as f:
                content = await f.read()
                if content: # 只有当文件有内容时才尝试加载
                    dns_cache = json.loads(content)
                logging.info(f"成功从 {DNS_CACHE_FILE} 加载 DNS 缓存。")
        except json.JSONDecodeError as e:
            logging.warning(f"DNS 缓存文件 {DNS_CACHE_FILE} 内容损坏，已重置缓存。错误: {e}")
        except Exception as e:
            logging.error(f"加载 DNS 缓存时发生错误: {e}")

    reader = None
    try:
        reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        for original_node in simplified_to_original.values():
            host = extract_host_from_node(original_node)

            if not host:
                logging.warning(f"无法从节点中提取有效主机，已抛弃: {original_node[:80]}...")
                continue

            target_ips = []
            if is_valid_ip(host):
                target_ips = [host]
            elif is_valid_domain(host):
                if host in dns_cache:
                    target_ips = dns_cache[host]
                    logging.debug(f"DNS 缓存命中: {host} -> {target_ips}")
                else:
                    try:
                        # getaddrinfo 返回一个列表的元组，每个元组代表一个 socket 地址信息
                        addrinfo_list = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        
                        # 从 addrinfo_list 中提取唯一的 IP 地址
                        resolved_ips = set()
                        for info in addrinfo_list:
                            if info[0] == socket.AF_INET or info[0] == socket.AF_INET6:
                                resolved_ips.add(info[4][0]) # info[4] 是 sockaddr，info[4][0] 是 IP 地址
                        
                        target_ips = list(resolved_ips)
                        dns_cache[host] = target_ips # 缓存结果
                        logging.info(f"成功解析域名 {host} 为 IP: {target_ips}，已缓存。")

                    except socket.gaierror as e:
                        logging.error(f"无法解析域名 {host} 到 IP 地址，已抛弃节点: '{original_node[:80]}...'. 错误: {e}")
                        continue
                    except Exception as e:
                        logging.error(f"解析域名 {host} 时发生未知错误，已抛弃节点: '{original_node[:80]}...'. 错误: {e}")
                        continue
            else:
                logging.warning(f"提取的主机 '{host}' 既不是有效IP也不是有效域名，已抛弃节点: '{original_node[:80]}...'")
                continue

            if not target_ips:
                logging.warning(f"未找到有效的 IP 地址用于 GeoIP 查询，已抛弃节点: {original_node[:80]}...")
                continue

            protocol_match = re.match(r"^([a-zA-Z0-9]+):\/\/", original_node)
            protocol = protocol_match.group(1) if protocol_match else "未知协议"

            # 优先使用第一个能解析到国家/地区的 IP
            location = "未知地区"
            for ip in target_ips:
                current_location = get_country_from_ip(ip, reader)
                if current_location not in ("未知/私有IP", "无效IP格式", "未知错误"):
                    location = current_location
                    break
            
            processed_nodes_with_location.append((original_node, location, protocol))

        named_nodes = []
        node_groups = collections.defaultdict(list)
        for node, location, protocol in processed_nodes_with_location:
            node_groups[(location, protocol)].append(node)
            
        sorted_keys = sorted(node_groups.keys())
        for location, protocol in sorted_keys:
            nodes_list = node_groups[(location, protocol)]
            nodes_list.sort()  # 确保同一组内的节点顺序一致
            for i, node in enumerate(nodes_list):
                new_name = f"{location}_{protocol}_{i+1}"
                # 检查节点是否已经有 # 标记，如果有，替换名称部分，否则直接添加
                if '#' in node:
                    named_node = re.sub(r'#.*$', f"#{new_name}", node)
                else:
                    named_node = f"{node}#{new_name}"
                named_nodes.append(named_node)

    except FileNotFoundError:
        logging.error(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        return
    except Exception as e:
        logging.error(f"处理节点时发生错误: {e}", exc_info=True) # 打印完整的异常信息
        return
    finally:
        if reader:
            reader.close()
            
        # DNS 缓存保存
        try:
            async with aiofiles.open(DNS_CACHE_FILE, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(dns_cache, ensure_ascii=False, indent=2))
            logging.info(f"DNS 缓存已保存到 {DNS_CACHE_FILE}。")
        except Exception as e:
            logging.error(f"保存 DNS 缓存时发生错误: {e}")

    async with aiofiles.open(DEDUP_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in named_nodes:
            await f.write(f"{node}\n")

    logging.info(f"处理完成，去重并命名后的节点已写入 {DEDUP_NODES_FILE}，共 {len(named_nodes)} 个。")

if __name__ == "__main__":
    asyncio.run(process_and_deduplicate_nodes())
