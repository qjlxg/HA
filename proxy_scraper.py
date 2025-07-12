import httpx
import asyncio
import re
import os
import aiofiles
import json
import yaml
import base64
from collections import defaultdict
import datetime
import hashlib
from bs4 import BeautifulSoup
import logging
import typing
import random # 导入 random 模块

# 配置日志
# 记录级别设置为 INFO，格式包含时间、级别、消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义数据和缓存目录的路径
DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
CACHE_EXPIRATION_HOURS = 48 # 缓存过期时间设置为 48 小时

# 确保数据目录和缓存目录存在，如果不存在则创建
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的节点协议及其对应的正则表达式
NODE_PATTERNS = {
    "hysteria2": r"hysteria2:\/\/.*",
    "vmess": r"vmess:\/\/.*",
    "trojan": r"trojan:\/\/.*",
    "ss": r"ss:\/\/.*",
    "ssr": r"ssr:\/\/.*",
    "vless": r"vless:\/\/.*",
}

# 定义多种 User-Agent 字符串
USER_AGENTS = [
    # 桌面端 (Windows, macOS, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    
    # 手机端 (Android, iPhone)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",

    # iPad
    "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.114 Mobile/15E148 Safari/604.1", # iPad with Chrome user agent

    # 鸿蒙 (HarmonyOS)
    "Mozilla/5.0 (Linux; Android 10; HUAWEIMatePad) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 (HarmonyOS)",
    "Mozilla/5.0 (Linux; HarmonyOS; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.78 Mobile Safari/537.36",
]


async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    支持缓存机制，避免重复下载。
    """
    # 使用 URL 的 MD5 哈希值作为缓存文件的键
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_file_path = os.path.join(CACHE_DIR, cache_key)

    # 检查缓存是否可用且未过期
    if use_cache and os.path.exists(cache_file_path):
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(cache_file_path))
        if datetime.datetime.now() - mtime < datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
            logging.info(f"从缓存读取内容: {url}")
            async with aiofiles.open(cache_file_path, 'r', encoding='utf-8') as f:
                return await f.read()

    # 构建完整的 HTTP 和 HTTPS URL
    full_url_http = f"http://{url}"
    full_url_https = f"https://{url}"

    # 随机选择一个 User-Agent
    random_user_agent = random.choice(USER_AGENTS)

    # 定义请求头，模拟浏览器行为
    headers = {
        "User-Agent": random_user_agent, # 使用随机选择的 User-Agent
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    # 使用 httpx.AsyncClient 进行异步 HTTP 请求
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        for current_url in [full_url_http, full_url_https]: # 尝试 HTTP 和 HTTPS
            try:
                logging.info(f"尝试从 {current_url.split('://')[0].upper()} 获取内容: {current_url} (User-Agent: {random_user_agent[:30]}...)") # 记录 User-Agent 部分信息
                response = await client.get(current_url, headers=headers)
                response.raise_for_status() # 检查 HTTP 状态码，非 2xx 则抛出异常
                content = response.text
                # 将获取到的内容写入缓存文件
                async with aiofiles.open(cache_file_path, 'w', encoding='utf-8') as f:
                    await f.write(content)
                return content
            except httpx.RequestError as exc:
                # 记录请求失败信息
                logging.warning(f"请求失败 {current_url}: {exc}")
            except Exception as e:
                # 记录其他未知错误
                logging.error(f"获取 {current_url} 时发生未知错误: {e}")
        return None # 两次尝试都失败则返回 None

def decode_content(content: str) -> str:
    """尝试解码 base64 编码的内容，并处理 URL 安全编码"""
    content = content.strip()
    try:
        # 尝试标准 base64 解码
        # 填充 '=' 使其成为 4 的倍数
        if len(content) % 4 != 0:
            content += '=' * (4 - len(content) % 4)
        return base64.b64decode(content).decode('utf-8')
    except Exception:
        pass # 如果标准解码失败，尝试 URL 安全解码
    
    try:
        # 尝试 URL 安全 base64 解码
        # 替换 '-' 为 '+'，'_' 为 '/'，并填充 '='
        content = content.replace('-', '+').replace('_', '/')
        if len(content) % 4 != 0:
            content += '=' * (4 - len(content) % 4)
        return base64.urlsafe_b64decode(content).decode('utf-8')
    except Exception:
        return content # 解码失败则返回原始内容

def extract_nodes_from_text(text: str, current_depth: int = 0, max_depth: int = 5) -> list[str]:
    """
    从文本中递归提取各种格式的节点。
    支持明文节点、YAML、JSON、HTML 等多层解析。
    引入递归深度限制以避免 RecursionError。
    """
    if current_depth > max_depth:
        logging.warning(f"达到最大递归深度 ({max_depth})，停止进一步解析。")
        return []

    nodes = []

    # 尝试解析 JSON 格式的节点
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    nodes.append(item)
                elif isinstance(item, dict):
                    # 尝试从字典中提取 URL 或其他节点信息
                    if 'url' in item and isinstance(item['url'], str):
                        nodes.append(item['url'])
                    elif 'add' in item and 'port' in item and 'v' in item: # 可能是 VMess JSON
                        nodes.append(f"vmess://{base64.b64encode(json.dumps(item).encode()).decode()}")
                    else:
                        # 对于无法直接识别的字典，尝试将其转换为字符串后递归解析
                        nodes.extend(extract_nodes_from_text(json.dumps(item), current_depth + 1, max_depth))
        elif isinstance(data, dict):
            # 遍历字典的值，进行递归解析
            for key, value in data.items():
                if isinstance(value, list) or isinstance(value, dict):
                    nodes.extend(extract_nodes_from_text(json.dumps(value), current_depth + 1, max_depth))
                elif isinstance(value, str):
                    nodes.append(value)
    except json.JSONDecodeError:
        pass # 非 JSON 格式，继续尝试其他解析方式

    # 尝试解析 YAML 格式的节点
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            # 处理 Clash 配置文件中的 proxies 字段
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, str):
                        nodes.append(proxy)
                    elif isinstance(proxy, dict):
                        # 根据代理类型构建节点链接
                        if proxy.get('type') == 'vmess' and 'uuid' in proxy:
                            nodes.append(f"vmess://{base64.b64encode(json.dumps(proxy).encode()).decode()}")
                        elif proxy.get('type') == 'trojan' and 'password' in proxy:
                            nodes.append(f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}")
                        elif proxy.get('type') == 'ss' and 'password' in proxy:
                            method_pass = f"{proxy.get('cipher')}:{proxy.get('password')}"
                            nodes.append(f"ss://{base64.urlsafe_b64encode(method_pass.encode()).decode().rstrip('=')}@{proxy.get('server')}:{proxy.get('port')}")
                        elif proxy.get('type') == 'vless' and 'uuid' in proxy:
                            nodes.append(f"vless://{proxy['uuid']}@{proxy['server']}:{proxy['port']}")
                        elif proxy.get('type') == 'hysteria2':
                            nodes.append(f"hysteria2://{proxy['password']}@{proxy['server']}:{proxy['port']}")
                        else:
                            nodes.append(str(proxy)) # 对于未知类型的字典，保留为字符串
            # 处理其他可能的 YAML 结构
            elif 'profiles' in data and isinstance(data['profiles'], dict):
                for profile_name, profile_content in data['profiles'].items():
                    if isinstance(profile_content, str):
                        nodes.append(profile_content)
                    elif isinstance(profile_content, (dict, list)):
                        nodes.extend(extract_nodes_from_text(yaml.dump(profile_content), current_depth + 1, max_depth))
            else:
                # 递归解析 YAML 字典中的所有值
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        nodes.extend(extract_nodes_from_text(yaml.dump(value), current_depth + 1, max_depth))
                    elif isinstance(value, str):
                        nodes.append(value)
    except yaml.YAMLError:
        pass # 非 YAML 格式，继续尝试其他解析方式

    # 尝试从 HTML 文本中提取内容
    try:
        soup = BeautifulSoup(text, 'html.parser')
        # 查找 <pre>, <code>, <textarea> 标签中的文本内容
        for tag_name in ['pre', 'code', 'textarea']:
            for tag in soup.find_all(tag_name):
                # 递归解析这些标签内的文本内容
                nodes.extend(extract_nodes_from_text(tag.get_text(), current_depth + 1, max_depth))
        # 查找包含已知协议的 <a> 标签的 href 属性
        for a_tag in soup.find_all('a', href=True):
            if any(proto in a_tag['href'] for proto in NODE_PATTERNS.keys()):
                nodes.append(a_tag['href'])
    except Exception as e:
        logging.debug(f"HTML 解析失败: {e}") # 记录调试信息，不影响主流程

    # 提取所有已知协议的节点（明文形式）
    for protocol, pattern in NODE_PATTERNS.items():
        nodes.extend(re.findall(pattern, text, re.IGNORECASE))

    # 提取可能的 base64 编码的链接或原始文本
    # 匹配可能的 base64 字符串，要求长度大于10且是4的倍数，以减少误判
    base64_re = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_re, text)
    for match in matches:
        if len(match) > 10 and len(match) % 4 == 0:
            decoded = decode_content(match)
            # 如果解码后发现节点协议，则加入，并递归解析解码内容
            for protocol, pattern in NODE_PATTERns.items():
                if re.search(pattern, decoded, re.IGNORECASE):
                    nodes.append(decoded)
                    nodes.extend(extract_nodes_from_text(decoded, current_depth + 1, max_depth)) # 递归解析
                    break
    
    # 尝试从文本中直接寻找看起来像节点的内容 (例如：IP:Port)
    ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b'
    nodes.extend(re.findall(ip_port_pattern, text))

    # 对提取到的节点进行初步处理，保留原始名称的前5位（如果存在）
    processed_nodes = []
    for node in nodes:
        # 对 vmess, ss, ssr 进行特殊处理，因为其名称通常在 base64 解码后
        if node.startswith("vmess://"):
            try:
                decoded_vmess = base64.b64decode(node[len("vmess://"):].encode()).decode('utf-8')
                vmess_json = json.loads(decoded_vmess)
                name = vmess_json.get('ps', 'vmess_node') # 获取 'ps'字段作为名称
                processed_nodes.append(f"{node}#{name[:5]}") # 将名称附加到节点URL后
            except Exception:
                processed_nodes.append(node) # 无法解码则保留原样
        elif node.startswith("ss://"):
            try:
                # SS 协议通常是 base64(method:password@server:port)#name
                parts = node[len("ss://"):].split('#', 1)
                encoded_part = parts[0]
                # URL 安全解码，并处理可能的填充
                decoded_ss = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                name = parts[1] if len(parts) > 1 else "ss_node"
                processed_nodes.append(f"{node}#{name[:5]}")
            except Exception:
                processed_nodes.append(node)
        elif node.startswith("ssr://"):
            try:
                # SSR 协议也是 base64 编码
                parts = node[len("ssr://"):].split('#', 1)
                encoded_part = parts[0]
                decoded_ssr = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                name = parts[1] if len(parts) > 1 else "ssr_node"
                processed_nodes.append(f"{node}#{name[:5]}")
            except Exception:
                processed_nodes.append(node)
        else:
            # 对于其他协议，简单提取名称前5位（如果节点有名称）
            match = re.search(r'#([^&\s]+)', node) # 查找 # 后面的名称
            if match:
                name = match.group(1)
                # 只保留 # 之前的部分和处理后的名称
                processed_nodes.append(f"{node.split('#')[0]}#{name[:5]}")
            else:
                processed_nodes.append(node)
    return processed_nodes

async def process_url(url: str) -> tuple[str, int, list[str]]: # 返回节点列表
    """
    处理单个 URL，获取内容，提取节点，并将提取到的节点写入单独的 URL 文件。
    返回 URL、提取到的节点数量以及提取到的唯一节点列表。
    """
    logging.info(f"开始处理 URL: {url}")
    content = await get_url_content(url)
    if not content:
        logging.warning(f"无法获取 {url} 的内容，跳过该 URL 的节点提取。")
        return url, 0, [] # 返回空列表

    loop = asyncio.get_running_loop()
    try:
        # 在线程池中执行 CPU 密集型的 extract_nodes_from_text
        logging.info(f"开始解析 {url} 的内容...")
        nodes = await loop.run_in_executor(None, extract_nodes_from_text, content, 0, 5)
        logging.info(f"完成解析 {url} 的内容。")
    except Exception as e:
        logging.error(f"解析 {url} 的内容时发生错误: {e}")
        nodes = [] # 解析失败，节点列表为空

    unique_nodes = list(set(nodes)) # 对提取到的节点进行简单去重

    # 将每个 URL 获取到的内容单独保存到一个文件中
    # 将 URL 中的非字母数字字符替换为 '_'，以创建安全的文件名
    safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
    url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
    async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(f"{node}\n")
    logging.info(f"URL: {url} 的节点已保存到 {url_output_file}")

    logging.info(f"URL: {url} 成功提取到 {len(unique_nodes)} 个节点。")
    return url, len(unique_nodes), unique_nodes # 返回节点列表

async def main():
    """主函数，读取 sources.list 并并行处理 URL。"""
    if not os.path.exists('sources.list'):
        logging.error("sources.list 文件不存在，请创建并添加要抓取的 URL。")
        return

    # 从 sources.list 文件中读取 URL 列表，跳过空行和注释行
    with open('sources.list', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not urls:
        logging.warning("sources.list 中没有找到有效的 URL，程序将退出。")
        return

    node_counts = defaultdict(int) # 用于存储每个 URL 提取到的节点数量
    all_extracted_nodes = [] # 用于收集所有 URL 提取到的节点

    # 为每个 URL 创建一个异步任务
    # process_url 不再接收 all_nodes_writer 参数
    tasks = [process_url(url) for url in urls]
    # 并行执行所有任务
    results = await asyncio.gather(*tasks)

    # 收集每个 URL 的节点数量和所有提取到的节点
    for url, count, nodes_list in results:
        node_counts[url] = count
        all_extracted_nodes.extend(nodes_list) # 将所有节点的列表添加到总列表中

    # 对所有收集到的节点进行全局去重
    global_unique_nodes = list(set(all_extracted_nodes))

    # 将所有全局去重后的节点一次性写入总文件
    logging.info(f"正在将所有 {len(global_unique_nodes)} 个去重后的节点写入 {ALL_NODES_FILE}...")
    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as f:
        for node in global_unique_nodes:
            await f.write(f"{node}\n")
    logging.info(f"所有去重后的节点已合并保存到 {ALL_NODES_FILE}")

    # 将节点数量统计保存为 CSV 文件
    async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8') as f:
        await f.write("URL,NodeCount\n")
        for url, count in node_counts.items():
            await f.write(f"{url},{count}\n")
    
    logging.info(f"所有 URL 处理完成，节点统计已保存到 {NODE_COUNT_CSV}")


if __name__ == '__main__':
    # 运行主异步函数
    asyncio.run(main())
