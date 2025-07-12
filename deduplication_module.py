import os
import geoip2.database
import re
import asyncio
import aiofiles
import json
import base64
import collections
import logging
import socket # 新增导入 socket 模块

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
DEDUP_NODES_FILE = os.path.join(DATA_DIR, "deduplicated_nodes.txt")
GEOLITE_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义需要解析 IP 的协议（通常是那些包含 IP/域名 的协议）
IP_EXTRACT_PATTERNS = { # 正确的变量名
    # 捕获 Vmess JSON 中的 "add" 或 "addr" 字段 (或 host, sni)
    "vmess": r"(?:\"add\"|\"addr\"|\"host\"|\"sni\")\s*:\s*\"([^\"]+)\"",
    # 捕获 Vless URL 中的 domain/ip
    "vless": r"vless:\/\/[a-zA-Z0-9\-]+@([^:]+)",
    # 捕获 Trojan URL 中的 domain/ip
    "trojan": r"trojan:\/\/.*@([^:]+)",
    # 捕获 SS URL 中的 domain/ip (假设是 method:password@host:port 格式)
    "ss": r"ss:\/\/([a-zA-Z0-9+/=_-]+)@([^:]+)",
    # 捕获 SSR URL 中的 domain/ip
    "ssr": r"ssr:\/\/([a-zA-Z0-9+/=_-]+)@([^:]+)",
    # 捕获 Hysteria2 URL 中的 domain/ip
    "hysteria2": r"hysteria2:\/\/.*@([^:]+)",
}

def is_valid_ip(ip_str: str) -> bool:
    """Checks if the string is a valid IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    # Simplified IPv6 regex (more robust validation would be complex without ipaddress module)
    # This is a basic check to distinguish from UUIDs and common invalid formats
    ipv6_pattern = re.compile(
        r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:|"
        r"^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}|:)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){2}((:[0-9a-fA-F]{1,4}){1,5}|:)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){3}((:[0-9a-fA-F]{1,4}){1,4}|:)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){4}((:[0-9a-fA-F]{1,4}){1,3}|:)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){5}((:[0-9a-fA-F]{1,4}){1,2}|:)$|"
        r"^(?:[0-9a-fA-F]{1,4}:){6}:[0-9a-fA-F]{1,4}$"
    )

    return bool(ipv4_pattern.match(ip_str) or ipv6_pattern.match(ip_str))

def is_valid_domain(domain_str: str) -> bool:
    """Checks if the string is a plausible domain name."""
    # A simple regex for domain name (not exhaustive, but good enough to filter UUIDs)
    # Allows letters, numbers, hyphens, and dots. Must not start/end with hyphen.
    # Must have at least one dot and a TLD of 2-63 characters.
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )
    return bool(domain_pattern.match(domain_str))

def is_valid_host(host_str: str) -> bool:
    """Checks if the string is a valid IP address or a plausible domain name."""
    return is_valid_ip(host_str) or is_valid_domain(host_str)


def decode_base64_safe(data: str) -> str:
    """尝试进行URL安全和标准base64解码，并处理填充"""
    data = data.strip().replace('<br />', '') # 移除 HTML <br /> 标签
    # 确保是 base64 字符集
    if not re.fullmatch(r'[A-Za-z0-9+/=_]+', data):
        return "" # 包含非base64字符，直接返回空

    for _ in range(4): # 尝试不同填充
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            data += '='
    return ""


def extract_host_from_node(node: str) -> str | None:
    """从节点字符串中提取主机名或IP地址"""
    node = node.strip()

    # 1. 过滤掉明显不是节点的行（如注释、不完整的名称）
    if not node or node.startswith('#') or len(node) < 10: # 简单判断长度，避免处理过短的字符串
        return None

    extracted_host = None

    # 2. 尝试处理 SS 协议 (ss://base64_encoded_info)
    if node.startswith("ss://"):
        try:
            # SS 链接可能是 base64(method:password@host:port)
            # 或者 base64(vmess_json) 用于 Vmess over SS
            encoded_part = node[len("ss://"):].split('#')[0] # 移除 # 后面的名称
            decoded_ss = decode_base64_safe(encoded_part)
            
            # 尝试解析为 JSON (vmess over ss)
            try:
                ss_json = json.loads(decoded_ss)
                if isinstance(ss_json, dict):
                    # 优先 'add', 然后 'addr', 最后 'host'/'sni'
                    extracted_host = ss_json.get('add') or ss_json.get('addr') or ss_json.get('host') or ss_json.get('sni')
            except json.JSONDecodeError:
                pass # 不是 JSON，继续按普通 SS 处理

            if not extracted_host: # 如果不是 JSON 或 JSON中没找到，尝试从 method:password@host:port 格式中提取 host
                match = re.search(r"@([^:]+)", decoded_ss)
                if match:
                    extracted_host = match.group(1)
        except Exception as e:
            logging.debug(f"SS节点主机提取失败: {e}, 节点: {node[:50]}...")
            pass # 继续尝试其他方式或返回 None

    # 3. 尝试处理 Vmess 协议 (vmess://base64_encoded_json)
    elif node.startswith("vmess://"):
        try:
            encoded_part = node[len("vmess://"):].split('#')[0]
            decoded_vmess = decode_base64_safe(encoded_part)
            vmess_json = json.loads(decoded_vmess)
            if isinstance(vmess_json, dict):
                # 优先 'add', 然后 'addr', 最后 'host'/'sni'
                extracted_host = vmess_json.get('add') or vmess_json.get('addr') or vmess_json.get('host') or vmess_json.get('sni')
        except Exception as e:
            logging.debug(f"VMess节点主机提取失败: {e}, 节点: {node[:50]}...")
            pass

    # 4. 遍历通用正则表达式提取主机
    if not extracted_host: # 只有当以上方法未提取到主机时才尝试通用模式
        for protocol, pattern in IP_EXTRACT_PATTERNS.items(): # <--- 修正后的变量名
            match = re.search(pattern, node)
            if match:
                # 对于 Vmess/Vless/Trojan/Hysteria2/SSR，通常第一个非空的捕获组是主机
                for group in match.groups():
                    if group:
                        extracted_host = group.strip()
                        break # 找到第一个就停止
            if extracted_host:
                break # 找到主机就停止遍历

    # 5. 最后尝试直接匹配 IP:Port 格式（作为兜底）
    if not extracted_host:
        ip_port_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b', node)
        if ip_port_match:
            extracted_host = ip_port_match.group(0).split(':')[0] # 只返回IP部分

    # 6. 对提取到的主机进行最终校验
    if extracted_host and is_valid_host(extracted_host):
        return extracted_host
    
    return None # 无法提取有效主机

def get_country_from_ip(ip_address: str, reader) -> str:
    """使用 GeoLite2 数据库获取 IP 对应的国家名称，处理无效 IP"""
    try:
        # geoip2.database.Reader 内部会验证IP地址格式
        response = reader.country(ip_address)
        return response.country.names['zh-CN'] # 返回中文国家名
    except geoip2.errors.AddressNotFoundError:
        # IP 地址未在数据库中找到，可能是私有 IP 或非常用 IP
        logging.debug(f"GeoIP 未找到地址: {ip_address}")
        return "未知/私有IP"
    except ValueError as e:
        # IP 地址格式不正确
        logging.error(f"解析 IP 地址 {ip_address} 时发生错误: {e}")
        raise # 抛出，让上层处理决定是否抛弃节点
    except Exception as e:
        # 其他 GeoIP 错误
        logging.error(f"GeoIP 查询失败 {ip_address}: {e}")
        return "未知错误"

def simplify_node(node: str) -> str:
    """简化节点字符串，移除不必要的参数，只保留协议和核心信息"""
    # 移除 # 后的名称
    node_without_name = node.split('#')[0]

    if node_without_name.startswith("ss://"):
        try:
            # SS 协议：method:password@server:port
            # 或 base64(json)
            encoded_part = node_without_name[len("ss://"):]
            decoded_ss = decode_base64_safe(encoded_part)

            try: # 尝试作为 JSON 处理
                ss_json = json.loads(decoded_ss)
                # 假设我们只想保留 v, ps, add, port, id, net, type, tls, sni, host, path
                # 其他字段如 aid, scy, alpn, fp 等可能需要清理
                clean_json = {}
                for key in ["v", "ps", "add", "port", "id", "net", "type", "tls", "sni", "host", "path"]:
                    if key in ss_json:
                        clean_json[key] = ss_json[key]
                return f"ss://{base64.b64encode(json.dumps(clean_json, separators=(',', ':')).encode()).decode().rstrip('=')}"
            except json.JSONDecodeError:
                pass # 不是 JSON，按普通 SS 处理

            # 尝试从 method:password@host:port 格式中提取
            match = re.search(r"([^@]+)@([^:]+):(\d+)", decoded_ss)
            if match:
                method_pass = match.group(1)
                host = match.group(2)
                port = match.group(3)
                # 重新编码以确保格式一致
                return f"ss://{base64.b64encode(f'{method_pass}@{host}:{port}'.encode()).decode().rstrip('=')}"
            else:
                return node_without_name # 无法解析，保留原样
        except Exception:
            return node_without_name # 解码失败，保留原样

    elif node_without_name.startswith("vmess://"):
        try:
            encoded_part = node_without_name[len("vmess://"):]
            decoded_vmess = decode_base64_safe(encoded_part)
            vmess_json = json.loads(decoded_vmess)
            
            # 假设我们只想保留 v, ps, add, port, id, net, type, tls, sni, host, path
            clean_json = {}
            for key in ["v", "ps", "add", "port", "id", "net", "type", "tls", "sni", "host", "path"]:
                if key in vmess_json:
                    clean_json[key] = vmess_json[key]
            return f"vmess://{base64.b64encode(json.dumps(clean_json, separators=(',', ':')).encode()).decode()}"
        except Exception:
            return node_without_name # 解码或解析失败，保留原样

    elif node_without_name.startswith("trojan://"):
        # 移除 # 后的参数和名称
        # trojan://password@server:port?params#name
        match = re.match(r"trojan:\/\/([^@]+)@([^:]+):(\d+)(.*)", node_without_name)
        if match:
            password = match.group(1)
            server = match.group(2)
            port = match.group(3)
            # 仅保留核心信息
            return f"trojan://{password}@{server}:{port}"
        return node_without_name # 无法解析，保留原样
    
    elif node_without_name.startswith("vless://"):
        # vless://uuid@server:port?params#name
        match = re.match(r"vless:\/\/([a-zA-Z0-9\-]+)@([^:]+):(\d+)(.*)", node_without_name)
        if match:
            uuid = match.group(1)
            server = match.group(2)
            port = match.group(3)
            # 仅保留核心信息
            return f"vless://{uuid}@{server}:{port}"
        return node_without_name # 无法解析，保留原样

    elif node_without_name.startswith("hysteria2://"):
        # hysteria2://password@server:port?params#name
        match = re.match(r"hysteria2:\/\/([^@]+)@([^:]+):(\d+)(.*)", node_without_name)
        if match:
            password = match.group(1)
            server = match.group(2)
            port = match.group(3)
            # 仅保留核心信息
            return f"hysteria2://{password}@{server}:{port}"
        return node_without_name # 无法解析，保留原样
    
    elif node_without_name.startswith("ssr://"):
        try:
            # SSR 协议：base64(server:port:protocol:method:obfs:password_base64/?obfsparam_base64&protoparam_base64#remarks_base64)
            # 我们只简化，不彻底去除所有参数，只确保是标准的 base64 编码
            encoded_part = node_without_name[len("ssr://"):]
            decoded_ssr = decode_base64_safe(encoded_part) # 尝试解码但不进一步解析内部结构
            if decoded_ssr: # 如果成功解码，重新编码回去，确保格式一致
                return f"ssr://{base64.urlsafe_b64encode(decoded_ssr.encode()).decode().rstrip('=')}"
            else:
                return node_without_name
        except Exception:
            return node_without_name

    return node_without_name

async def process_and_deduplicate_nodes():
    """
    读取 all.txt 中的所有节点，去重，进行 GeoIP 查询并重命名，
    最后将处理后的节点写入 deduplicated_nodes.txt。
    """
    if not os.path.exists(ALL_NODES_FILE):
        logging.error(f"错误：{ALL_NODES_FILE} 文件不存在。请先运行 proxy_scraper.py。")
        return

    if not os.path.exists(GEOLITE_DB_PATH):
        logging.error(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        logging.info("下载地址：https://dev.maxmind.com/geoip/downloads/geo2/country/?lang=zh-Hans")
        logging.info("请下载 GeoLite2-Country.mmdb 并将其放置在 'data' 文件夹中。")
        return

    all_nodes = set()
    async with aiofiles.open(ALL_NODES_FILE, 'r', encoding='utf-8') as f:
        async for line in f:
            all_nodes.add(line.strip())

    logging.info(f"原始节点数量: {len(all_nodes)}")

    simplified_to_original = {} # 简化后的节点: 原始节点
    for node in all_nodes:
        simplified_node = simplify_node(node)
        if simplified_node:
            simplified_to_original[simplified_node] = node
    
    logging.info(f"去重后（简化后）节点数量: {len(simplified_to_original)}")

    processed_nodes_with_location = [] # (original_node, location, protocol)

    try:
        reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        for simplified_node, original_node in simplified_to_original.items():
            host = extract_host_from_node(original_node) # 从原始节点提取主机

            if not host:
                logging.warning(f"无法从节点中提取有效主机，已抛弃: {original_node[:80]}...")
                continue # 无法提取有效主机，直接跳过此节点

            target_ip = None
            if is_valid_ip(host):
                target_ip = host
            elif is_valid_domain(host):
                try:
                    # 异步解析域名到 IP
                    # 使用 asyncio.to_thread 包装同步的 DNS 解析，避免阻塞事件循环
                    target_ip = await asyncio.to_thread(socket.gethostbyname, host)
                    logging.info(f"成功解析域名 {host} 为 IP: {target_ip}")
                except socket.gaierror as e:
                    logging.error(f"无法解析域名 {host} 到 IP 地址，已抛弃节点: '{original_node[:80]}...'. 错误: {e}")
                    continue # 无法解析域名，跳过此节点
                except Exception as e:
                    logging.error(f"解析域名 {host} 时发生未知错误，已抛弃节点: '{original_node[:80]}...'. 错误: {e}")
                    continue # 其他解析错误，跳过此节点
            else:
                logging.warning(f"提取的主机 '{host}' 既不是有效IP也不是有效域名，已抛弃节点: '{original_node[:80]}...'")
                continue # 既不是IP也不是域名，跳过

            protocol_match = re.match(r"^([a-zA-Z0-9]+):\/\/", original_node)
            protocol = protocol_match.group(1) if protocol_match else "未知协议"

            location = "未知地区" # 默认值

            if target_ip: # 只有找到 IP 后才进行 GeoIP 查询
                try:
                    # 尝试获取国家信息
                    location = get_country_from_ip(target_ip, reader)
                except ValueError: # 此处捕获 GeoIP 内部的 IP 格式错误 (理论上 is_valid_ip 已过滤)
                    logging.error(f"GeoIP 查询: IP地址格式不正确，已抛弃节点: '{original_node[:80]}...'")
                    continue
                except Exception as e:
                    logging.warning(f"GeoIP 查询失败，标记为未知地区: {e}, 主机: {target_ip}")
                    # 如果是其他 GeoIP 错误，保留为未知地区，但不抛弃
            
            processed_nodes_with_location.append((original_node, location, protocol))

        # 按 location 和 protocol 分组，并按序号命名
        named_nodes = []
        node_groups = collections.defaultdict(list) # {(location, protocol): [node1, node2, ...]}
        for node, location, protocol in processed_nodes_with_location:
            node_groups[(location, protocol)].append(node)
        
        for (location, protocol), nodes_list in node_groups.items():
            for i, node in enumerate(nodes_list):
                new_name = f"{location}_{protocol}_{i+1}"
                # 确保节点链接是原始链接，并添加新名称
                named_node = f"{node}#{new_name}"
                named_nodes.append(named_node)

    except FileNotFoundError:
        logging.error(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        return
    except Exception as e:
        logging.error(f"处理节点时发生错误: {e}")
        return
    finally:
        if 'reader' in locals() and reader:
            reader.close()

    # 将最终的去重并命名后的节点写入文件
    async with aiofiles.open(DEDUP_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in named_nodes:
            await f.write(f"{node}\n")

    logging.info(f"处理完成，去重并命名后的节点已写入 {DEDUP_NODES_FILE}，共 {len(named_nodes)} 个。")

if __name__ == "__main__":
    asyncio.run(process_and_deduplicate_nodes())
