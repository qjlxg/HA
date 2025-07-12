import os
import geoip2.database
import re
import asyncio
import aiofiles
import json
import base64
import collections
import socket # 用于同步 DNS 解析
import logging # 导入 logging 模块

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义数据目录和文件路径
DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
DEDUP_NODES_FILE = os.path.join(DATA_DIR, "deduplicated_nodes.txt")
GEOLITE_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

# 确保数据目录存在，如果不存在则创建
os.makedirs(DATA_DIR, exist_ok=True)

# 定义需要解析 IP 的协议及其正则表达式（通常是那些包含 IP/域名 的协议）
IP_EXTRACT_PATTERNS = {
    "vmess": r"\"add\":\"([^\"]+)\"|\"addr\":\"([^\"]+)\"", # 用于基于 JSON 的 VMess
    "vless": r"vless:\/\/([a-zA-Z0-9\-]+)@([^\:]+)", # 捕获 UUID 和域名/IP
    "trojan": r"trojan:\/\/.*@([^\:]+)",
    "ss": r"ss:\/\/.*@([^\:]+)",
    "ssr": r"ssr:\/\/.*@([^\:]+)",
    "hysteria2": r"hysteria2:\/\/.*@([^\:]+)",
}

def extract_host_from_node(node: str) -> str | None:
    """
    从节点字符串中提取主机名或 IP 地址。
    支持 VMess 的 JSON 解码和各种协议的正则匹配。
    """
    if node.startswith("vmess://"):
        try:
            # VMess 节点需要 base64 解码后解析 JSON
            # 移除 'vmess://' 前缀，并进行 base64 解码
            decoded = base64.b64decode(node[len("vmess://"):].encode()).decode('utf-8')
            data = json.loads(decoded)
            return data.get('add') or data.get('addr') # 优先 'add' 字段，其次 'addr'
        except Exception as e:
            logging.debug(f"VMess 节点解码或解析失败: {node} - {e}")
            return None
    
    # 遍历预定义的协议模式进行匹配
    for protocol, pattern in IP_EXTRACT_PATTERNS.items():
        if node.startswith(f"{protocol}://"):
            match = re.search(pattern, node)
            if match:
                # 对于 vless, vmess, ss, ssr, trojan, hysteria2，捕获组可能不同
                # 简单地取第一个非空的捕获组作为主机
                for group in match.groups():
                    if group:
                        return group
    
    # 尝试匹配简单的 IP:Port 格式
    ip_port_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}\b', node)
    if ip_port_match:
        return ip_port_match.group(1) # 返回匹配到的 IP 地址

    logging.debug(f"未能从节点中提取主机: {node}")
    return None # 如果无法提取主机，则返回 None

def resolve_ip(host: str) -> str:
    """
    尝试将域名解析为 IP 地址，否则返回原主机名。
    注意：此处使用同步的 socket.gethostbyname，在大量解析时可能会阻塞异步事件循环。
    更好的做法是使用异步 DNS 库 (如 aiodns) 或在线程池中执行此操作。
    但考虑到 GeoLite2 是离线的，通常不会成为主要瓶颈。
    """
    try:
        # 使用 socket 库进行同步 DNS 解析
        return socket.gethostbyname(host)
    except socket.gaierror:
        logging.debug(f"DNS 解析失败：{host}，返回原主机名。")
        return host # 解析失败，返回原主机名
    except Exception as e:
        logging.error(f"解析主机名 {host} 时发生未知错误: {e}")
        return host

async def get_location_from_ip(ip_address: str, reader: geoip2.database.Reader) -> str:
    """
    根据 IP 地址获取国家信息。
    GeoLite2-Country.mmdb 必须存在于 data 目录中。
    reader 参数现在由调用方传入，避免重复创建 Reader 实例。
    """
    if not os.path.exists(GEOLITE_DB_PATH):
        logging.error(f"错误：GeoLite2-Country.mmdb 文件不存在于 {GEOLITE_DB_PATH}。请下载并放置。")
        return "未知地区"
    
    try:
        # 使用传入的 reader 实例进行 IP 查询
        response = reader.country(ip_address)
        # 优先使用中文国家名，如果没有则使用英文国家名，再没有则为“未知国家”
        return response.country.names.get('zh-CN', response.country.name or "未知国家")
    except geoip2.errors.AddressNotFoundError:
        logging.debug(f"IP 地址 {ip_address} 未找到地理信息。")
        return "未知地区"
    except Exception as e:
        logging.error(f"解析 IP 地址 {ip_address} 时发生错误: {e}")
        return "未知地区"

async def process_node(node: str, reader: geoip2.database.Reader) -> tuple[str, str]:
    """
    处理单个节点，提取 IP 并获取地理位置。
    这个函数现在接收一个 GeoIP reader 实例。
    """
    host = extract_host_from_node(node)
    if host:
        ip = resolve_ip(host)
        # 对于私有 IP 或无效 IP，直接标记为未知地区
        if ip.startswith(('10.', '172.16.', '192.168.', '127.', '0.', '169.254.')):
            return node, "私有地址"
        location = await get_location_from_ip(ip, reader)
        return node, location
    logging.warning(f"无法从节点中提取主机，标记为未知地区: {node}")
    return node, "未知地区" # 如果无法提取主机，则标记为未知地区

def simplify_node(node: str) -> str:
    """
    简化节点字符串，去除多余信息（如名称），只保留协议和必要内容。
    例如，将 vmess://...#名称 去除 #名称 部分。
    """
    if node.startswith("vmess://"):
        try:
            # VMess 节点可能包含 ps (名称) 字段，这里只保留编码部分
            # 但为了统一，如果带了 # 符号，也直接去除
            parts = node.split('#', 1)
            return parts[0]
        except Exception:
            return node # 无法解析则返回原样
    elif node.startswith("ss://") or node.startswith("ssr://") or \
         node.startswith("trojan://") or node.startswith("vless://") or \
         node.startswith("hysteria2://"):
        # 对于这些协议，通常 # 后面的部分是名称，直接去除
        parts = node.split('#', 1)
        return parts[0]
    return node # 对于不匹配的节点，返回原样

async def main():
    """
    主函数，读取 all.txt 中的节点，进行去重、解析 IP、获取地理位置，
    统一命名，并保存到 deduplicated_nodes.txt。
    """
    if not os.path.exists(ALL_NODES_FILE):
        logging.error(f"错误：{ALL_NODES_FILE} 文件不存在。请先运行 proxy_scraper.py 生成节点列表。")
        return
    
    if not os.path.exists(GEOLITE_DB_PATH):
        logging.error(f"错误：GeoLite2-Country.mmdb 文件不存在于 {GEOLITE_DB_PATH}。请下载并放置。")
        logging.info("下载链接：https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en (需要注册)")
        return

    # 读取所有节点
    logging.info(f"正在从 {ALL_NODES_FILE} 读取所有节点...")
    async with aiofiles.open(ALL_NODES_FILE, 'r', encoding='utf-8') as f:
        # 读取每一行并去除首尾空白，过滤掉空行
        all_nodes = [line.strip() for line in await f.readlines() if line.strip()]

    # 对节点进行初步简化（去除名称等），方便后续去重
    simplified_nodes = [simplify_node(node) for node in all_nodes]
    # 使用 collections.OrderedDict.fromkeys 保持原始顺序并去重
    unique_simplified_nodes = list(collections.OrderedDict.fromkeys(simplified_nodes))

    logging.info(f"原始节点数量: {len(all_nodes)}")
    logging.info(f"去重后（简化后）节点数量: {len(unique_simplified_nodes)}")

    processed_nodes_with_location = []
    reader = None # 初始化 GeoIP reader

    try:
        # 在 try 块中创建 GeoIP Reader 实例，确保在 finally 块中关闭
        reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        
        # 创建异步任务列表，每个任务处理一个独特的简化节点
        tasks = [process_node(node, reader) for node in unique_simplified_nodes]
        # 并行执行所有任务，获取节点及其地理位置
        results = await asyncio.gather(*tasks)

        # 收集处理结果，包含原始节点（去重后）、地理位置和协议
        for node, location in results:
            # 尝试从节点 URL 中提取协议名称
            protocol_match = re.match(r"(vmess|vless|trojan|ss|ssr|hysteria2)://", node)
            protocol = protocol_match.group(1) if protocol_match else "unknown"
            processed_nodes_with_location.append((node, location, protocol))

        # 按 location 和 protocol 分组，并按序号命名
        named_nodes = []
        # 使用 defaultdict 方便按 (location, protocol) 组合分组节点
        node_groups = collections.defaultdict(list) # 格式: {(location, protocol): [node1, node2, ...]}
        for node, location, protocol in processed_nodes_with_location:
            node_groups[(location, protocol)].append(node)
        
        # 遍历每个分组，为其中的节点分配顺序名称
        for (location, protocol), nodes_list in node_groups.items():
            for i, node in enumerate(nodes_list):
                # 构建新的节点名称，格式为：地区_协议_序号
                new_name = f"{location}_{protocol}_{i+1}"
                # 将节点统一改名，并只保留协议的必须内容，然后追加新名称
                # 假设 simplify_node 已经处理了大部分冗余，这里只需追加新名称
                named_node = f"{node}#{new_name}"
                named_nodes.append(named_node)

    except FileNotFoundError:
        logging.error(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        return
    except Exception as e:
        logging.exception(f"处理节点时发生错误: {e}") # 记录详细错误堆栈信息
        return
    finally:
        # 确保在任何情况下 GeoIP reader 都能被关闭，释放资源
        if reader:
            reader.close()
            logging.info("GeoIP 数据库连接已关闭。")

    # 保存去重并命名后的节点到文件
    logging.info(f"正在保存去重并命名后的节点到 {DEDUP_NODES_FILE}...")
    async with aiofiles.open(DEDUP_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in named_nodes:
            await f.write(f"{node}\n")

    logging.info(f"去重并命名后的节点已成功保存到 {DEDUP_NODES_FILE}，总计 {len(named_nodes)} 个。")

if __name__ == '__main__':
    # 运行主异步函数
    asyncio.run(main())
