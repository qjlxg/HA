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
import typing # 导入 typing 模块以正确进行类型提示

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
CACHE_EXPIRATION_HOURS = 48

# 确保数据目录和缓存目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的节点协议正则
NODE_PATTERNS = {
    "hysteria2": r"hysteria2:\/\/.*",
    "vmess": r"vmess:\/\/.*",
    "trojan": r"trojan:\/\/.*",
    "ss": r"ss:\/\/.*",
    "ssr": r"ssr:\/\/.*",
    "vless": r"vless:\/\/.*",
}

async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """
    安全地异步获取 URL 内容，优先尝试 HTTP，失败后尝试 HTTPS。
    支持缓存机制。
    """
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_file_path = os.path.join(CACHE_DIR, cache_key)

    if use_cache and os.path.exists(cache_file_path):
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(cache_file_path))
        if datetime.datetime.now() - mtime < datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
            logging.info(f"从缓存读取: {url}")
            async with aiofiles.open(cache_file_path, 'r', encoding='utf-8') as f:
                return await f.read()

    full_url_http = f"http://{url}"
    full_url_https = f"https://{url}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        try:
            logging.info(f"尝试从 HTTP 获取: {full_url_http}")
            response = await client.get(full_url_http, headers=headers)
            response.raise_for_status()
            content = response.text
            async with aiofiles.open(cache_file_path, 'w', encoding='utf-8') as f:
                await f.write(content)
            return content
        except httpx.RequestError as exc:
            logging.warning(f"HTTP 请求失败 {full_url_http}: {exc}")
            try:
                logging.info(f"尝试从 HTTPS 获取: {full_url_https}")
                response = await client.get(full_url_https, headers=headers)
                response.raise_for_status()
                content = response.text
                async with aiofiles.open(cache_file_path, 'w', encoding='utf-8') as f:
                    await f.write(content)
                return content
            except httpx.RequestError as exc_https:
                logging.error(f"HTTPS 请求也失败 {full_url_https}: {exc_https}")
                return None
        except Exception as e:
            logging.error(f"获取 {url} 时发生未知错误: {e}")
            return None

def decode_content(content: str) -> str:
    """尝试解码 base64 或其他编码内容"""
    try:
        return base64.b64decode(content).decode('utf-8')
    except Exception:
        return content

def extract_nodes_from_text(text: str) -> list[str]:
    """
    从文本中提取各种格式的节点。
    支持明文节点、YAML、JSON 等多层解析。
    """
    nodes = []
    # 尝试解析 JSON
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    nodes.append(item)
                elif isinstance(item, dict):
                    # 简单处理，如果字典中有URL字段，可以尝试提取
                    if 'url' in item and isinstance(item['url'], str):
                        nodes.append(item['url'])
                    elif 'add' in item and 'port' in item: # 可能是VMess等结构
                        nodes.append(json.dumps(item)) # 暂存，后续会再处理
        elif isinstance(data, dict):
            # 尝试从字典中提取节点列表，例如订阅返回的键值
            for key, value in data.items():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            nodes.append(item)
                        elif isinstance(item, dict):
                            if 'url' in item and isinstance(item['url'], str):
                                nodes.append(item['url'])
                            elif 'add' in item and 'port' in item:
                                nodes.append(json.dumps(item))
                elif isinstance(value, str): # 可能是内嵌的base64或直接的URL
                    nodes.append(value)
    except json.JSONDecodeError:
        pass # 不是 JSON，继续

    # 尝试解析 YAML
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, str):
                        nodes.append(proxy)
                    elif isinstance(proxy, dict):
                        # 尝试将 YAML 代理配置转换为可识别的格式
                        if 'type' in proxy:
                            if proxy['type'] == 'vmess' and 'uuid' in proxy:
                                # 简化处理，实际vmess需要更复杂的编码
                                nodes.append(f"vmess://{base64.b64encode(json.dumps(proxy).encode()).decode()}")
                            elif proxy['type'] == 'trojan' and 'password' in proxy:
                                nodes.append(f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'] == 'ss' and 'password' in proxy:
                                # ss://method:password@server:port 格式
                                method_pass = f"{proxy.get('cipher')}:{proxy.get('password')}"
                                nodes.append(f"ss://{base64.urlsafe_b64encode(method_pass.encode()).decode().rstrip('=')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'] == 'vless' and 'uuid' in proxy:
                                nodes.append(f"vless://{proxy['uuid']}@{proxy['server']}:{proxy['port']}")
                            elif proxy['type'] == 'hysteria2':
                                nodes.append(f"hysteria2://{proxy['password']}@{proxy['server']}:{proxy['port']}")
                            else:
                                nodes.append(str(proxy)) # 保留其他类型，后续可以扩展处理
            elif 'profiles' in data and isinstance(data['profiles'], dict): # 某些订阅格式
                for profile_name, profile_content in data['profiles'].items():
                    if isinstance(profile_content, str):
                        nodes.append(profile_content)
    except yaml.YAMLError:
        pass # 不是 YAML，继续

    # 尝试从 HTML 中提取
    try:
        soup = BeautifulSoup(text, 'html.parser')
        # 查找所有 pre, code, textarea 标签内的文本
        for tag_name in ['pre', 'code', 'textarea']:
            for tag in soup.find_all(tag_name):
                nodes.extend(extract_nodes_from_text(tag.get_text())) # 递归解析内嵌内容
        # 查找可能的链接
        for a_tag in soup.find_all('a', href=True):
            if any(proto in a_tag['href'] for proto in NODE_PATTERNS.keys()):
                nodes.append(a_tag['href'])
    except Exception:
        pass # 不是 HTML，或者解析失败

    # 提取所有已知协议的节点
    for protocol, pattern in NODE_PATTERNS.items():
        nodes.extend(re.findall(pattern, text, re.IGNORECASE))

    # 提取可能的 base64 编码的链接或原始文本
    # 尝试识别看起来像 base64 的字符串并解码
    base64_re = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_re, text)
    for match in matches:
        if len(match) > 10: # 避免匹配太短的无关字符串
            decoded = decode_content(match)
            # 如果解码后发现节点协议，则加入
            for protocol, pattern in NODE_PATTERNS.items():
                if re.search(pattern, decoded, re.IGNORECASE):
                    nodes.append(decoded)
                    break
            # 如果解码后是 JSON 或 YAML, 继续解析
            try:
                json.loads(decoded)
                nodes.extend(extract_nodes_from_text(decoded))
            except json.JSONDecodeError:
                pass
            try:
                yaml.safe_load(decoded)
                nodes.extend(extract_nodes_from_text(decoded))
            except yaml.YAMLError:
                pass

    # 尝试从文本中直接寻找看起来像节点的内容 (例如：IP:Port)
    # 简单的IP:Port模式
    ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b'
    nodes.extend(re.findall(ip_port_pattern, text))

    # 对提取到的节点进行初步处理，只保留前5位原始名称
    processed_nodes = []
    for node in nodes:
        # 对 vmess, ss, ssr 进行特殊处理，因为其名称通常在 base64 解码后
        if node.startswith("vmess://"):
            try:
                decoded_vmess = base64.b64decode(node[len("vmess://"):].encode()).decode('utf-8')
                vmess_json = json.loads(decoded_vmess)
                name = vmess_json.get('ps', 'vmess_node')
                processed_nodes.append(f"{node} # {name[:5]}")
            except Exception:
                processed_nodes.append(node) # 无法解码则保留原样
        elif node.startswith("ss://"):
            try:
                # SS 通常是 base64(method:password@server:port)#name
                parts = node[len("ss://"):].split('#', 1)
                encoded_part = parts[0]
                decoded_ss = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8') # 补齐等号
                name = parts[1] if len(parts) > 1 else "ss_node"
                processed_nodes.append(f"{node} # {name[:5]}")
            except Exception:
                processed_nodes.append(node)
        elif node.startswith("ssr://"):
            try:
                # SSR 也是 base64 编码
                parts = node[len("ssr://"):].split('#', 1)
                encoded_part = parts[0]
                decoded_ssr = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                name = parts[1] if len(parts) > 1 else "ssr_node"
                processed_nodes.append(f"{node} # {name[:5]}")
            except Exception:
                processed_nodes.append(node)
        else:
            # 对于其他协议，简单提取名称前5位（如果节点有名称）
            match = re.search(r'#([^&\s]+)', node) # 查找 # 后面的名称
            if match:
                name = match.group(1)
                processed_nodes.append(f"{node.split('#')[0]}#{name[:5]}")
            else:
                processed_nodes.append(node)
    return processed_nodes


async def process_url(url: str, all_nodes_writer: typing.TextIO) -> tuple[str, int]:
    """
    处理单个 URL，获取内容，提取节点，并写入文件。
    返回 URL 和提取到的节点数量。
    """
    logging.info(f"开始处理 URL: {url}")
    content = await get_url_content(url)
    if not content:
        logging.warning(f"无法获取 {url} 的内容，跳过。")
        return url, 0

    nodes = extract_nodes_from_text(content)
    unique_nodes = list(set(nodes)) # 简单去重

    # 将每个 URL 获取到的内容单独保存
    safe_url_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', url)
    url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
    async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(f"{node}\n")

    # 将所有节点写入总文件
    for node in unique_nodes:
        await all_nodes_writer.write(f"{node}\n")

    logging.info(f"URL: {url} 提取到 {len(unique_nodes)} 个节点。")
    return url, len(unique_nodes)

async def main():
    """主函数，读取 sources.list 并并行处理 URL。"""
    if not os.path.exists('sources.list'):
        logging.error("sources.list 文件不存在，请创建并添加 URL。")
        return

    with open('sources.list', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not urls:
        logging.warning("sources.list 中没有找到有效的 URL。")
        return

    node_counts = defaultdict(int)

    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as all_nodes_writer:
        tasks = [process_url(url, all_nodes_writer) for url in urls]
        results = await asyncio.gather(*tasks)

        for url, count in results:
            node_counts[url] = count

    # 将节点数量统计保存为 CSV
    async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8') as f:
        await f.write("URL,NodeCount\n")
        for url, count in node_counts.items():
            await f.write(f"{url},{count}\n")

    logging.info("所有 URL 处理完成。")

if __name__ == '__main__':
    asyncio.run(main())
