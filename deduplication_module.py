import os
import geoip2.database
import re
import asyncio
import aiofiles
import json
import base64
import collections

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
DEDUP_NODES_FILE = os.path.join(DATA_DIR, "deduplicated_nodes.txt")
GEOLITE_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 定义需要解析 IP 的协议（通常是那些包含 IP/域名 的协议）
IP_EXTRACT_PATTERNS = {
    "vmess": r"\"add\":\"([^\"]+)\"|\"addr\":\"([^\"]+)\"", # for json based vmess
    "vless": r"vless:\/\/([a-zA-Z0-9\-]+)@([^\:]+)", # captures uuid and domain/ip
    "trojan": r"trojan:\/\/.*@([^\:]+)",
    "ss": r"ss:\/\/.*@([^\:]+)",
    "ssr": r"ssr:\/\/.*@([^\:]+)",
    "hysteria2": r"hysteria2:\/\/.*@([^\:]+)",
}

def extract_host_from_node(node: str) -> str | None:
    """从节点字符串中提取主机名或IP地址"""
    if node.startswith("vmess://"):
        try:
            # VMess 节点需要 base64 解码后解析 JSON
            decoded = base64.b64decode(node[len("vmess://"):].encode()).decode('utf-8')
            data = json.loads(decoded)
            return data.get('add') or data.get('addr')
        except Exception:
            return None
    
    for protocol, pattern in IP_EXTRACT_PATTERNS.items():
        if node.startswith(f"{protocol}://"):
            match = re.search(pattern, node)
            if match:
                # 对于 vless, vmess, ss, ssr, trojan, hysteria2，捕获组可能不同
                # 简单地取第一个非空的捕获组
                for group in match.groups():
                    if group:
                        return group
    
    # 尝试匹配简单的 IP:Port 格式
    ip_port_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}\b', node)
    if ip_port_match:
        return ip_port_match.group(1)

    return None

def resolve_ip(host: str) -> str:
    """尝试将域名解析为 IP 地址，否则返回原主机名"""
    try:
        # 使用 aiodns 进行异步 DNS 解析
        # 这里为了简化，直接用同步的 socket.gethostbyname，在实际生产中，
        # 如果需要大量解析，应该使用异步的 DNS 库 (如 aiodns)
        # 但考虑到 GeoLite2 是离线的，同步解析也问题不大
        import socket
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host # 解析失败，返回原主机名

async def get_location_from_ip(ip_address: str) -> str:
    """
    根据 IP 地址获取国家信息。
    GeoLite2-Country.mmdb 必须存在于 data 目录中。
    """
    if not os.path.exists(GEOLITE_DB_PATH):
        print(f"错误：GeoLite2-Country.mmdb 文件不存在于 {GEOLITE_DB_PATH}。请下载并放置。")
        return "未知地区"
    
    try:
        reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        response = reader.country(ip_address)
        return response.country.names.get('zh-CN', response.country.name or "未知国家")
    except geoip2.errors.AddressNotFoundError:
        return "未知地区"
    except Exception as e:
        print(f"解析 IP 地址 {ip_address} 时发生错误: {e}")
        return "未知地区"

async def process_node(node: str, reader: geoip2.database.Reader) -> tuple[str, str]:
    """处理单个节点，提取 IP 并获取地理位置"""
    host = extract_host_from_node(node)
    if host:
        ip = resolve_ip(host)
        location = await get_location_from_ip(ip)
        return node, location
    return node, "未知地区" # 如果无法提取主机，则标记为未知地区

def simplify_node(node: str) -> str:
    """
    简化节点，只保留协议和必要内容，去除多余信息。
    例如，将 vmess://...#名称 去除 #名称
    """
    if node.startswith("vmess://"):
        try:
            # vmess 节点可能包含 ps (名称) 字段，这里只保留编码部分
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
    return node

async def main():
    """主函数，读取 all.txt，去重，解析 IP，统一命名，并保存。"""
    if not os.path.exists(ALL_NODES_FILE):
        print(f"错误：{ALL_NODES_FILE} 文件不存在。请先运行 proxy_scraper.py。")
        return

    # 读取所有节点
    async with aiofiles.open(ALL_NODES_FILE, 'r', encoding='utf-8') as f:
        all_nodes = [line.strip() for line in await f.readlines() if line.strip()]

    # 对节点进行初步简化，方便去重
    simplified_nodes = [simplify_node(node) for node in all_nodes]
    unique_simplified_nodes = list(collections.OrderedDict.fromkeys(simplified_nodes)) # 保持顺序去重

    print(f"原始节点数量: {len(all_nodes)}")
    print(f"去重后（简化后）节点数量: {len(unique_simplified_nodes)}")

    processed_nodes_with_location = []
    
    # 异步处理节点，获取地理位置
    tasks = []
    for node in unique_simplified_nodes:
        # 这里需要为每个异步任务创建一个 reader 实例，或者将 reader 作为参数传递
        # 为了避免文件句柄过多，这里将 reader 放在循环外，并在 process_node 中使用。
        # 注意：geoip2.database.Reader 是线程安全的，但在 asyncio 任务中直接共享可能会有 IO 阻塞问题
        # 更好的做法是在 ThreadPoolExecutor 中运行 GeoIP 查询，或者使用 aiomultiprocess
        # 鉴于节点数量可能较多，我们假设 GeoIP 查询是相对快的。
        tasks.append(process_node(node, None)) # reader 参数在这里可以先不传，在 process_node 内部每次打开/关闭，或者考虑更高级的池化

    # 为了避免每次都打开 GeoLite2-Country.mmdb，我们在 try-finally 块中统一管理 reader
    reader = None
    try:
        reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        # 重新创建任务，传递 reader 实例
        tasks = [process_node(node, reader) for node in unique_simplified_nodes]
        results = await asyncio.gather(*tasks)

        for node, location in results:
            # 统一命名：Location_协议_序号
            protocol_match = re.match(r"(vmess|vless|trojan|ss|ssr|hysteria2)://", node)
            protocol = protocol_match.group(1) if protocol_match else "unknown"
            
            # 使用一个字典来计数每个 (location, protocol) 组合的节点数量
            # 为了序号升序排列
            # 这里需要一个全局的计数器或者在循环外收集所有相同 (location, protocol) 的节点
            # 然后再分配序号
            processed_nodes_with_location.append((node, location, protocol))

        # 按 location 和 protocol 分组，并按序号命名
        named_nodes = []
        node_groups = collections.defaultdict(list) # {(location, protocol): [node1, node2, ...]}
        for node, location, protocol in processed_nodes_with_location:
            node_groups[(location, protocol)].append(node)
        
        for (location, protocol), nodes_list in node_groups.items():
            for i, node in enumerate(nodes_list):
                new_name = f"{location}_{protocol}_{i+1}"
                # 将节点统一改名，并只保留协议的必须内容
                # 假设 simplify_node 已经处理了大部分冗余，这里只需追加新名称
                named_node = f"{node}#{new_name}"
                named_nodes.append(named_node)

    except FileNotFoundError:
        print(f"错误：无法找到 GeoLite2-Country.mmdb 文件于 {GEOLITE_DB_PATH}。请确保已下载并放置。")
        return
    except Exception as e:
        print(f"处理节点时发生错误: {e}")
        return
    finally:
        if reader:
            reader.close()

    # 保存去重并命名后的节点
    async with aiofiles.open(DEDUP_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in named_nodes:
            await f.write(f"{node}\n")

    print(f"去重并命名后的节点已保存到 {DEDUP_NODES_FILE}")

if __name__ == '__main__':
    asyncio.run(main())
