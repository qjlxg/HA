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

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义数据输入和输出目录
INPUT_DATA_DIR = "data" # all.txt 和 GeoLite2-Country.mmdb 所在的目录
OUTPUT_SUB_DIR = "sub"    # deduplicated_nodes.txt 所在的目录

ALL_NODES_FILE = os.path.join(INPUT_DATA_DIR, "all.txt")
GEOLITE_DB_PATH = os.path.join(INPUT_DATA_DIR, "GeoLite2-Country.mmdb") # GeoLite2 数据库现在在 data 目录下
DEDUP_NODES_FILE = os.path.join(OUTPUT_SUB_DIR, "deduplicated_nodes.txt")
DNS_CACHE_FILE = os.path.join(OUTPUT_SUB_DIR, "dns_cache.json") # 新增：DNS 缓存文件路径

# 确保必要的目录都存在
os.makedirs(INPUT_DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_SUB_DIR, exist_ok=True)

# 定义需要解析 IP 的协议
IP_EXTRACT_PATTERNS = {
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
    """内部辅助函数，用于清理 JSON 节点中的不必要字段"""
    clean_json = {}
    keys_to_keep = ["v", "ps", "add", "port", "id", "net", "type", "tls", "sni", "host", "path"]
    for key in keys_to_keep:
        if key in json_data:
            clean_json[key] = json_data[key]
    return clean_json

def extract_host_from_node(node: str) -> str | None:
    """从节点字符串中提取主机名或IP地址"""
    node = node.strip()

    if not node or node.startswith('#') or len(node) < 10:
        return None

    extracted_host = None

    if node.startswith("ss://") or node.startswith("vmess://"):
        try:
            protocol_prefix = "ss://" if node.startswith("ss://") else "vmess://"
            encoded_part = node[len(protocol_prefix):].split('#')[0]
            decoded_content = decode_base64_safe(encoded_part)

            try:
                node_json = json.loads(decoded_content)
                if isinstance(node_json, dict):
                    extracted_host = node_json.get('add') or node_json.get('addr') or node_json.get('host') or node_json.get('sni')
            except json.JSONDecodeError:
                pass

            if not extracted_host and protocol_prefix == "ss://":
                match = re.search(r"@([^:]+)", decoded_content)
                if match:
                    extracted_host = match.group(1)
        except Exception as e:
            logging.debug(f"{protocol_prefix}节点主机提取失败: {e}, 节点: {node[:50]}...")
            pass

    if not extracted_host:
        for pattern_name, pattern in IP_EXTRACT_PATTERNS.items():
            match = re.search(pattern, node)
            if match:
                for group in match.groups():
                    if group:
                        extracted_host = group.strip()
                        break
            if extracted_host:
                break

    if not extracted_host:
        # 尝试匹配 IP:Port 模式作为最后的尝试
        ip_port_match = re.search(r'\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\]?:\d{1,5}', node)
        if ip_port_match:
            # For IPv6, the host part could be enclosed in brackets
            extracted_host_with_port = ip_port_match.group(1)
            # Remove brackets if it's an IPv6 address with brackets
            if extracted_host_with_port.startswith('[') and extracted_host_with_port.endswith(']'):
                extracted_host = extracted_host_with_port[1:-1]
            else:
                extracted_host = extracted_host_with_port

    if extracted_host and is_valid_host(extracted_host):
        return extracted_host
        
    return None

def simplify_node(node: str) -> str:
    """简化节点字符串，移除不必要的参数，只保留协议和核心信息"""
    node_without_name = node.split('#')[0]

    if not node_without_name:
        return ""

    if node_without_name.startswith("ss://") or node_without_name.startswith("vmess://"):
        try:
            protocol_prefix = "ss://" if node_without_name.startswith("ss://") else "vmess://"
            encoded_part = node_without_name[len(protocol_prefix):]
            decoded_content = decode_base64_safe(encoded_part)
            
            try:
                node_json = json.loads(decoded_content)
                clean_json = _clean_json_node(node_json)
                return f"{protocol_prefix}{base64.b64encode(json.dumps(clean_json, separators=(',', ':')).encode()).decode().rstrip('=')}"
            except json.JSONDecodeError:
                pass

            if protocol_prefix == "ss://":
                match = re.search(r"([^@]+)@([^:]+):(\d+)", decoded_content)
                if match:
                    method_pass = match.group(1)
                    host = match.group(2)
                    port = match.group(3)
                    return f"ss://{base64.b64encode(f'{method_pass}@{host}:{port}'.encode()).decode().rstrip('=')}"
        except Exception:
            pass

    elif node_without_name.startswith("trojan://") or \
          node_without_name.startswith("vless://") or \
          node_without_name.startswith("hysteria2://"):
        match = re.match(r"^(?P<protocol>[a-zA-Z0-9]+):\/\/(?P<id_pass>[^@]+)@(?P<server>[^:]+):(?P<port>\d+)(.*)", node_without_name)
        if match:
            proto = match.group('protocol')
            id_pass = match.group('id_pass')
            server = match.group('server')
            port = match.group('port')
            return f"{proto}://{id_pass}@{server}:{port}"
            
    elif node_without_name.startswith("ssr://"):
        try:
            encoded_part = node_without_name[len("ssr://"):]
            decoded_ssr = decode_base64_safe(encoded_part)
            if decoded_ssr:
                return f"ssr://{base64.urlsafe_b64encode(decoded_ssr.encode()).decode().rstrip('=')}"
        except Exception:
            pass

    return node_without_name

def get_country_from_ip(ip_address: str, reader) -> str:
    """使用 GeoLite2 数据库获取 IP 对应的国家名称，处理无效 IP"""
    try:
        response = reader.country(ip_address)
        return response.country.names['zh-CN']
    except geoip2.errors.AddressNotFoundError:
        logging.debug(f"GeoIP 未找到地址: {ip_address}")
        return "未知/私有IP"
    except ValueError as e:
        logging.error(f"解析 IP 地址 {ip_address} 时发生错误: {e}")
        return "无效IP格式"
    except Exception as e:
        logging.error(f"GeoIP 查询失败 {ip_address}: {e}")
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
                        # (family, type, proto, canonname, sockaddr)
                        # sockaddr 对于 IPv4 是 (address, port)，对于 IPv6 是 (address, port, flowinfo, scopeid)
                        addrinfo_list = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        
                        # 从 addrinfo_list 中提取唯一的 IP 地址
                        # 使用 set 来确保唯一性，并处理 IPv4 和 IPv6 地址
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
