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

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
# 继续保留 CACHE_EXPIRATION_HOURS 作为时间兜底机制，防止某些服务器不提供有效的 ETag/Last-Modified
CACHE_EXPIRATION_HOURS = 48

# 确保数据目录和缓存目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的节点协议正则
NODE_PATTERNS = {
    "hysteria2": r"hysteria2:\\/\\/.*",
    "vmess": r"vmess:\\/\\/.*",
    "trojan": r"trojan:\\/\\/.*",
    "ss": r"ss:\\/\\/.*",
    "ssr": r"ssr:\\/\\/.*",
    "vless": r"vless:\\/\\/.*",
}

async def _fetch_url_with_retry(client: httpx.AsyncClient, url: str, headers: dict, original_protocol_url: str) -> httpx.Response | None:
    """
    辅助函数：尝试从 URL 获取内容，并支持 HTTP 到 HTTPS 的回退。
    original_protocol_url 用于判断是否是初始请求，避免 HTTPS 到 HTTPS 的无限回退。
    """
    try:
        logging.info(f"尝试从 {url.split('://')[0].upper()} 获取内容: {url} (User-Agent: {headers.get('User-Agent', 'N/A')})")
        response = await client.get(url, headers=headers)
        response.raise_for_status() # 对 4xx/5xx 响应抛出 HTTPStatusError
        return response
    except httpx.HTTPStatusError as e:
        logging.error(f"获取 {url} 时发生 HTTP 状态错误: {e}")
        # 如果是 HTTP 请求且是初始协议（非重试后的 HTTPS），则尝试 HTTPS 回退
        if url.startswith("http://") and original_protocol_url.startswith("http://"):
            https_url = url.replace("http://", "https://")
            logging.info(f"尝试从 HTTPS 回退获取内容: {https_url}")
            try:
                # 回退时移除条件请求头，因为 ETag/Last-Modified 可能只对原协议有效
                fallback_headers = dict(headers)
                fallback_headers.pop('If-None-Match', None)
                fallback_headers.pop('If-Modified-Since', None)
                response_https = await client.get(https_url, headers=fallback_headers)
                response_https.raise_for_status()
                return response_https
            except httpx.HTTPStatusError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 状态错误: {e_https}")
            except httpx.RequestError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 网络请求错误: {e_https}")
            except Exception as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 未知错误: {e_https}")
        return None
    except httpx.RequestError as e:
        logging.error(f"获取 {url} 时发生网络请求错误: {e}")
        # 如果是 HTTP 请求且是初始协议，则尝试 HTTPS 回退
        if url.startswith("http://") and original_protocol_url.startswith("http://"):
            https_url = url.replace("http://", "https://")
            logging.info(f"尝试从 HTTPS 回退获取内容: {https_url}")
            try:
                fallback_headers = dict(headers)
                fallback_headers.pop('If-None-Match', None)
                fallback_headers.pop('If-Modified-Since', None)
                response_https = await client.get(https_url, headers=fallback_headers)
                response_https.raise_for_status()
                return response_https
            except httpx.HTTPStatusError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 状态错误: {e_https}")
            except httpx.RequestError as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 网络请求错误: {e_https}")
            except Exception as e_https:
                logging.error(f"获取 {https_url} 时发生 HTTPS 未知错误: {e_https}")
        return None
    except Exception as e:
        logging.error(f"获取 {url} 时发生未知错误: {e}")
        return None

async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """从 URL 获取内容，并支持基于 HTTP 头部的缓存验证。"""
    cache_entry_path = os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + ".json")
    
    cached_data = None
    if use_cache and os.path.exists(cache_entry_path):
        try:
            async with aiofiles.open(cache_entry_path, 'r', encoding='utf-8') as f:
                cached_data = json.loads(await f.read())
            
            # 首先检查时间过期（作为兜底，以防服务器不提供或不严格遵循 ETag/Last-Modified）
            cache_timestamp_str = cached_data.get('timestamp', datetime.datetime.min.isoformat())
            cache_timestamp = datetime.datetime.fromisoformat(cache_timestamp_str)
            if (datetime.datetime.now() - cache_timestamp).total_seconds() / 3600 >= CACHE_EXPIRATION_HOURS:
                logging.info(f"缓存 {url} 已过期（超过 {CACHE_EXPIRATION_HOURS} 小时），将重新检查更新。")
                cached_data = None # 标记为过期，强制进行完整请求以获取最新状态

        except Exception as e:
            logging.warning(f"读取或解析缓存文件 {cache_entry_path} 失败: {e}，将重新获取。")
            cached_data = None # 缓存文件损坏，强制重新获取

    client = httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True)
    response = None
    content_to_return = None

    try:
        headers_for_request = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 如果有缓存数据，则添加条件请求头
        if cached_data:
            if cached_data.get('etag'):
                headers_for_request['If-None-Match'] = cached_data['etag']
            if cached_data.get('last-modified'):
                headers_for_request['If-Modified-Since'] = cached_data['last-modified']

        # 调用辅助函数进行 URL 获取和重试
        response = await _fetch_url_with_retry(client, url, headers_for_request, url)

        if response:
            if response.status_code == 304 and cached_data and cached_data.get('content'):
                logging.info(f"URL: {url} 内容未更新 (304 Not Modified)，从缓存读取。")
                content_to_return = base64.b64decode(cached_data['content']).decode('utf-8', errors='ignore')
            else:
                # 内容已更新（200 OK）或首次获取
                content = response.text
                
                # 准备新的缓存数据
                new_cached_data = {
                    "content": base64.b64encode(content.encode('utf-8')).decode('ascii'), # base64编码以避免JSON编码问题
                    "timestamp": datetime.datetime.now().isoformat() # 记录最新缓存时间
                }
                if 'etag' in response.headers:
                    new_cached_data['etag'] = response.headers['etag']
                if 'last-modified' in response.headers:
                    new_cached_data['last-modified'] = response.headers['last-modified']

                async with aiofiles.open(cache_entry_path, 'w', encoding='utf-8') as f:
                    await f.write(json.dumps(new_cached_data))
                logging.info(f"URL: {url} 内容已更新，已写入缓存。")
                content_to_return = content
        else: # response 为 None，表示所有尝试均失败
            logging.error(f"无法获取 URL: {url} 的内容，跳过该 URL 的节点提取。")
            content_to_return = None

    finally:
        await client.aclose() # 确保 httpx 客户端在请求完成后关闭

    return content_to_return

async def extract_nodes_from_content(url: str, content: str) -> list[str]:
    """
    从文本内容中提取符合 Vmess, Trojan, SS, SSR, Vless, Hysteria2 格式的节点。
    """
    unique_nodes = set()
    
    # 尝试解析为 Base64 解码后的 JSON 或 YAML (通常用于Vmess订阅链接)
    try:
        # 尝试 Base64 解码，然后判断是否为 JSON 或 YAML
        decoded_content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
        
        # 尝试作为 JSON 处理 (Vmess订阅)
        try:
            json_data = json.loads(decoded_content)
            if isinstance(json_data, list): # Vmess 订阅通常是节点列表
                for item in json_data:
                    if isinstance(item, dict) and 'ps' in item and 'add' in item: # 简单判断为 Vmess 节点
                        # 重新编码为 Vmess URL
                        unique_nodes.add("vmess://" + base64.b64encode(json.dumps(item, separators=(',', ':')).encode()).decode())
            elif isinstance(json_data, dict) and 'outbounds' in json_data: # Clash 配置的可能
                for outbound in json_data.get('outbounds', []):
                    # 简单判断，并尝试重构为标准链接
                    if outbound.get('type') == 'vmess':
                        # 从 Clash 配置重建 vmess:// 链接
                        vmess_node = {
                            "v": "2", # 假设 Vmess 版本
                            "ps": outbound.get('name', 'node'),
                            "add": outbound.get('server'),
                            "port": outbound.get('port'),
                            "id": outbound.get('uuid'),
                            "aid": outbound.get('alterId', '0'),
                            "net": outbound.get('network', 'tcp'),
                            "type": outbound.get('tls-enable', False), # 这个需要进一步判断
                            "host": outbound.get('servername', ''), # sni
                            "path": outbound.get('ws-path', ''), # ws path
                            "tls": "tls" if outbound.get('tls', False) else "" # tls
                        }
                        # 清理空值
                        vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                        unique_nodes.add("vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode())
                    # 可以添加其他协议的解析，如 trojan, ss 等
            
        except json.JSONDecodeError:
            pass # 不是 JSON，继续

        # 尝试作为 YAML 处理 (Clash/Surge配置)
        try:
            yaml_data = yaml.safe_load(decoded_content)
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data: # Clash 配置
                for proxy in yaml_data.get('proxies', []):
                    # 尝试从 Clash 代理配置中提取节点
                    # 例如，Vmess
                    if proxy.get('type') == 'vmess':
                        vmess_node = {
                            "v": "2",
                            "ps": proxy.get('name', 'node'),
                            "add": proxy.get('server'),
                            "port": proxy.get('port'),
                            "id": proxy.get('uuid'),
                            "aid": proxy.get('alterId', '0'),
                            "net": proxy.get('network', 'tcp'),
                            "type": "", # vmess type
                            "host": proxy.get('ws-headers', {}).get('Host', ''), # ws host
                            "path": proxy.get('ws-path', ''), # ws path
                            "tls": "tls" if proxy.get('tls', False) else "" # tls
                        }
                        vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                        unique_nodes.add("vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode())
                    # 例如，Trojan
                    elif proxy.get('type') == 'trojan':
                        trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}"
                        # 可以在这里添加其他参数，如 sni, allowInsecure, skipCertVerify
                        if proxy.get('sni'):
                             trojan_node += f"?sni={proxy['sni']}"
                        unique_nodes.add(trojan_node)
                    # 可以在这里添加其他协议的解析
        except yaml.YAMLError:
            pass # 不是 YAML，继续
        
    except Exception:
        pass # 不是有效的 Base64 编码，或者解码后不是 JSON/YAML，继续按纯文本处理

    # 尝试从原始内容或 Base64 解码后的内容中匹配各种节点模式
    for protocol, pattern in NODE_PATTERNS.items():
        # 在原始内容中查找
        for match in re.finditer(pattern, content):
            unique_nodes.add(match.group(0))
        # 在解码后的内容中查找 (如果存在且有效)
        if 'decoded_content' in locals() and decoded_content:
            for match in re.finditer(pattern, decoded_content):
                unique_nodes.add(match.group(0))

    # 进一步处理可能嵌入在HTML中的节点链接
    if "<html" in content.lower() or "<!doctype html>" in content.lower():
        soup = BeautifulSoup(content, 'html.parser')
        # 查找所有文本内容
        for text_element in soup.find_all(string=True):
            text = str(text_element)
            for protocol, pattern in NODE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    unique_nodes.add(match.group(0))
            # 尝试解码可能隐藏在文本中的base64
            for word in re.findall(r'\b[A-Za-z0-9+/=_]{20,}\b', text): # 匹配看起来像base64的字符串
                try:
                    decoded_text = base64.b64decode(word + "===").decode('utf-8', errors='ignore') # 尝试填充
                    for protocol, pattern in NODE_PATTERNS.items():
                        for match in re.finditer(pattern, decoded_text):
                            unique_nodes.add(match.group(0))
                except Exception:
                    pass

    return list(unique_nodes)

async def process_url(url: str, all_nodes_writer: aiofiles.threadpool.binary.AsyncTextIOWrapper):
    """处理单个 URL，获取内容，提取节点并写入文件。"""
    logging.info(f"开始处理 URL: {url}")
    content = await get_url_content(url)

    if not content:
        logging.warning(f"无法获取 {url} 的内容，跳过该 URL 的节点提取。")
        return url, 0

    logging.info(f"开始解析 {url} 的内容...")
    unique_nodes = await extract_nodes_from_content(url, content)
    logging.info(f"完成解析 {url} 的内容。")

    # 对节点再次进行一次去重，确保最终写入的节点是唯一的
    unique_nodes = list(set(unique_nodes))

    # 将当前 URL 提取的节点保存到单独的文件
    safe_url_name = re.sub(r'[^a-zA-Z0-9.\-_]', '_', url) # 清理URL用于文件名
    url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
    async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
        for node in unique_nodes:
            await f.write(f"{node}\n")

    # 将所有节点写入总文件
    for node in unique_nodes:
        await all_nodes_writer.write(f"{node}\n")

    logging.info(f"URL: {url} 的节点已保存到 {url_output_file}")
    logging.info(f"URL: {url} 成功提取到 {len(unique_nodes)} 个节点。")
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
    
    # 将每个 URL 的节点数量写入 CSV 文件
    async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8') as f:
        await f.write("URL,NodeCount\n")
        for url, count in node_counts.items():
            await f.write(f"{url},{count}\n")

    logging.info("所有 URL 处理完成。")

if __name__ == "__main__":
    asyncio.run(main())
