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
import csv # 导入 csv 模块用于写入 CSV 文件

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = "data"
ALL_NODES_FILE = os.path.join(DATA_DIR, "all.txt")
NODE_COUNT_CSV = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
CACHE_EXPIRATION_HOURS = 48 # 缓存过期时间（小时）
CLEANUP_THRESHOLD_HOURS = 72 # 缓存清理阈值（小时），比过期时间长，确保过期文件有时间被处理

# 确保数据目录和缓存目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 定义支持的节点协议正则
# 尝试让正则更精确，但同时也要考虑实际链接的复杂性和多样性
NODE_PATTERNS = {
    # 匹配 hysteria2://user:password@host:port/?params#name
    "hysteria2": r"hysteria2:\/\/(?:[^:@\/]+(?::[^@\/]*)?@)?(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
    # 匹配 vmess://base64_encoded_json_string
    "vmess": r"vmess:\/\/[a-zA-Z0-9\-_+=/]+",
    # 匹配 trojan://password@host:port/?params#name
    "trojan": r"trojan:\/\/[^@]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
    # 匹配 ss://method:password@host:port#name 或 ss://base64
    "ss": r"ss:\/\/(?:[a-zA-Z0-9\-_]+:[^@\/]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+|[a-zA-Z0-9\-_+=/]+)(?:#.*)?",
    # 匹配 ssr://base64_encoded_string
    "ssr": r"ssr:\/\/[a-zA-Z0-9\-_+=/]+",
    # 匹配 vless://uuid@host:port/?params#name
    "vless": r"vless:\/\/[0-9a-fA-F\-]+@(?:\[[0-9a-fA-F:\.]+\]|[^:\/?#]+):\d+\/?(?:\?[^#]*)?(?:#.*)?",
}

# Semaphore to limit concurrent requests
# 调整此值以适应您的网络速度和目标服务器的限流策略。
# 过高可能导致限流，过低则会降低抓取效率。
CONCURRENCY_LIMIT = 10 

async def clean_old_cache_files(cleanup_threshold_hours: int):
    """
    清理 data/cache 目录中过期的或不再使用的缓存文件。
    会删除修改时间早于指定阈值（cleanup_threshold_hours）的文件。
    """
    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(hours=cleanup_threshold_hours)
    
    logging.info(f"开始清理缓存目录: {CACHE_DIR}，将删除修改时间早于 {cutoff_time} 的文件。")
    
    deleted_count = 0
    try:
        for filename in os.listdir(CACHE_DIR):
            file_path = os.path.join(CACHE_DIR, filename)
            if os.path.isfile(file_path):
                try:
                    file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                    if file_mtime < cutoff_time:
                        os.remove(file_path)
                        logging.debug(f"已删除过期缓存文件: {filename}")
                        deleted_count += 1
                except OSError as e:
                    logging.warning(f"无法删除文件 {file_path} (可能是权限问题): {e}")
                except Exception as e:
                    logging.warning(f"处理文件 {file_path} 时发生未知错误: {e}")
        logging.info(f"缓存清理完成，共删除 {deleted_count} 个文件。")
    except FileNotFoundError:
        logging.info(f"缓存目录 {CACHE_DIR} 不存在，无需清理。")
    except Exception as e: # 捕获其他任何可能的异常
        logging.error(f"清理缓存时发生意外错误: {e}")

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
            except Exception as e_https: # 捕获其他任何意外异常
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
            except Exception as e_https: # 捕获其他任何意外异常
                logging.error(f"获取 {https_url} 时发生 HTTPS 未知错误: {e_https}")
        return None
    except Exception as e: # 捕获其他任何意外异常
        logging.error(f"获取 {url} 时发生未知错误: {e}")
        return None

async def get_url_content(url: str, use_cache: bool = True) -> str | None:
    """从 URL 获取内容，并支持基于 HTTP 头部的缓存验证和时间兜底。"""
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

        except (json.JSONDecodeError, KeyError) as e:
            logging.warning(f"读取或解析缓存文件 {cache_entry_path} 失败 (JSON 格式错误或键缺失): {e}，将重新获取。")
            cached_data = None # 缓存文件损坏，强制重新获取
        except FileNotFoundError: # 理论上 os.path.exists 会捕获，但作为防御性编程
            logging.debug(f"缓存文件 {cache_entry_path} 不存在。")
            cached_data = None
        except Exception as e: # 捕获读取缓存文件时其他任何意外异常
            logging.warning(f"读取缓存文件 {cache_entry_path} 时发生未知错误: {e}，将重新获取。")
            cached_data = None


    client = httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True)
    response = None
    content_to_return = None

    try:
        headers_for_request = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        if cached_data:
            if cached_data.get('etag'):
                headers_for_request['If-None-Match'] = cached_data['etag']
            if cached_data.get('last-modified'):
                headers_for_request['If-Modified-Since'] = cached_data['last-modified']

        response = await _fetch_url_with_retry(client, url, headers_for_request, url)

        if response:
            if response.status_code == 304 and cached_data and cached_data.get('content'):
                logging.info(f"URL: {url} 内容未更新 (304 Not Modified)，从缓存读取。")
                content_to_return = base64.b64decode(cached_data['content']).decode('utf-8', errors='ignore')
            else:
                content = response.text
                
                new_cached_data = {
                    "content": base64.b64encode(content.encode('utf-8')).decode('ascii'), # base64编码以避免JSON编码问题
                    "timestamp": datetime.datetime.now().isoformat() # 记录最新缓存时间
                }
                if 'etag' in response.headers:
                    new_cached_data['etag'] = response.headers['etag']
                if 'last-modified' in response.headers:
                    new_cached_data['last-modified'] = response.headers['last-modified']

                try:
                    async with aiofiles.open(cache_entry_path, 'w', encoding='utf-8') as f:
                        await f.write(json.dumps(new_cached_data))
                    logging.info(f"URL: {url} 内容已更新，已写入缓存。")
                except IOError as e:
                    logging.error(f"写入缓存文件 {cache_entry_path} 失败 (IO 错误): {e}")
                except Exception as e: # 捕获写入缓存文件时其他任何意外异常
                    logging.error(f"写入缓存文件 {cache_entry_path} 时发生未知错误: {e}")
                
                content_to_return = content
        else: # response 为 None，表示所有尝试均失败
            logging.warning(f"无法从任何协议获取 URL: {url} 的内容，跳过该 URL 的节点提取。")
            content_to_return = None

    finally:
        await client.aclose() # 确保 httpx 客户端在请求完成后关闭

    return content_to_return

async def extract_nodes_from_content(url: str, content: str) -> list[str]:
    """
    从文本内容中提取符合 Vmess, Trojan, SS, SSR, Vless, Hysteria2 格式的节点。
    增加了对多种配置格式（如 Clash/Sing-box）的解析。
    """
    unique_nodes = set()
    
    # 尝试解析为 Base64 解码后的 JSON 或 YAML (通常用于订阅链接或Clash配置)
    decoded_content_attempt = None
    try:
        decoded_content_attempt = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError):
        pass # 不是有效的 Base64 编码，或者解码失败，继续按纯文本处理

    if decoded_content_attempt:
        # 尝试作为 JSON 处理 (Vmess订阅或Clash/Sing-box配置)
        try:
            json_data = json.loads(decoded_content_attempt)
            if isinstance(json_data, list): # Vmess 订阅通常是节点列表
                for item in json_data:
                    # 简单判断为 Vmess 节点，并重新编码为 Vmess URL
                    if isinstance(item, dict) and 'v' in item and 'ps' in item and 'add' in item:
                        unique_nodes.add("vmess://" + base64.b64encode(json.dumps(item, separators=(',', ':')).encode()).decode())
            elif isinstance(json_data, dict): # 可能是Clash/Sing-box等配置
                # Sing-box 风格的配置
                if 'outbounds' in json_data and isinstance(json_data['outbounds'], list):
                     for outbound in json_data['outbounds']:
                         if outbound.get('type') == 'vmess' and outbound.get('server'):
                            # 从 Sing-box 配置重建 vmess:// 链接
                            vmess_node = {
                                "v": "2",
                                "ps": outbound.get('tag', outbound.get('name', 'node')),
                                "add": outbound.get('server'),
                                "port": outbound.get('server_port'),
                                "id": outbound.get('uuid'),
                                "aid": outbound.get('alterId', '0'),
                                "net": outbound.get('network', 'tcp'),
                                "type": outbound.get('tls', {}).get('type', ''), # tls type
                                "host": outbound.get('tls', {}).get('server_name', ''), # sni
                                "path": outbound.get('ws_path', ''), # ws path
                                "tls": "tls" if outbound.get('tls', {}).get('enabled', False) else "" # tls enabled
                            }
                            vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                            unique_nodes.add("vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode())
                         # TODO: 添加其他 Sing-box 协议的解析（如 trojan, vless, hysteria2 等）

                # Clash 风格的配置
                elif 'proxies' in json_data and isinstance(json_data['proxies'], list):
                    for proxy in json_data['proxies']:
                        if proxy.get('type') == 'vmess':
                            vmess_node = {
                                "v": "2",
                                "ps": proxy.get('name', 'node'),
                                "add": proxy.get('server'),
                                "port": proxy.get('port'),
                                "id": proxy.get('uuid'),
                                "aid": proxy.get('alterId', '0'),
                                "net": proxy.get('network', 'tcp'),
                                "type": "",
                                "host": proxy.get('ws-headers', {}).get('Host', ''),
                                "path": proxy.get('ws-path', ''),
                                "tls": "tls" if proxy.get('tls', False) else ""
                            }
                            vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                            unique_nodes.add("vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode())
                        elif proxy.get('type') == 'trojan':
                            trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}"
                            if proxy.get('sni'):
                                trojan_node += f"?sni={proxy['sni']}"
                            if proxy.get('skip-cert-verify', False):
                                trojan_node += "&allowInsecure=1" # Trojan-Go 特有参数
                            unique_nodes.add(trojan_node)
                        # TODO: 添加其他 Clash 协议的解析（如 SS, VLESS, Hysteria2 等）

        except json.JSONDecodeError:
            pass # 不是 JSON 格式，继续尝试 YAML 或正则匹配
        except Exception as e: # 捕获 JSON 解析过程中其他任何意外异常
            logging.debug(f"JSON 解析时发生未知错误: {e}")
        
        # 尝试作为 YAML 处理 (Clash/Surge配置)
        try:
            yaml_data = yaml.safe_load(decoded_content_attempt)
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                for proxy in yaml_data['proxies']:
                    if proxy.get('type') == 'vmess':
                        vmess_node = {
                            "v": "2",
                            "ps": proxy.get('name', 'node'),
                            "add": proxy.get('server'),
                            "port": proxy.get('port'),
                            "id": proxy.get('uuid'),
                            "aid": proxy.get('alterId', '0'),
                            "net": proxy.get('network', 'tcp'),
                            "type": "",
                            "host": proxy.get('ws-headers', {}).get('Host', ''),
                            "path": proxy.get('ws-path', ''),
                            "tls": "tls" if proxy.get('tls', False) else ""
                        }
                        vmess_node = {k: v for k, v in vmess_node.items() if v is not None and v != ''}
                        unique_nodes.add("vmess://" + base64.b64encode(json.dumps(vmess_node, separators=(',', ':')).encode()).decode())
                    elif proxy.get('type') == 'trojan':
                        trojan_node = f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}"
                        if proxy.get('sni'):
                             trojan_node += f"?sni={proxy['sni']}"
                        if proxy.get('skip-cert-verify', False):
                             trojan_node += "&allowInsecure=1"
                        unique_nodes.add(trojan_node)
                    # TODO: 添加其他 YAML Clash 协议的解析（如 SS, VLESS, Hysteria2 等）
        except yaml.YAMLError:
            pass # 不是 YAML 格式，继续尝试正则匹配
        except Exception as e: # 捕获 YAML 解析过程中其他任何意外异常
            logging.debug(f"YAML 解析时发生未知错误: {e}")


    # 尝试从原始内容或 Base64 解码后的内容中匹配各种节点模式
    contents_to_search = [content]
    if decoded_content_attempt:
        contents_to_search.append(decoded_content_attempt)

    for text_content in contents_to_search:
        for protocol, pattern in NODE_PATTERNS.items():
            for match in re.finditer(pattern, text_content):
                node = match.group(0)
                # 针对 Vmess，如果匹配到原始的 base64 字符串，也需要解码验证并重新编码
                if protocol == "vmess" and node.startswith("vmess://"):
                    try:
                        decoded_vmess = base64.b64decode(node[len("vmess://"):].strip('=')).decode('utf-8')
                        json.loads(decoded_vmess) # 尝试解析为JSON，确保是有效的Vmess JSON
                        unique_nodes.add(node)
                    except (base64.binascii.Error, json.JSONDecodeError):
                        logging.debug(f"Vmess 节点 {node} 解码或解析失败，跳过。")
                else:
                    unique_nodes.add(node)

    # 进一步处理可能嵌入在HTML中的节点链接
    if "<html" in content.lower() or "<!doctype html>" in content.lower():
        soup = BeautifulSoup(content, 'html.parser')
        # 查找所有文本内容
        for text_element in soup.find_all(string=True):
            text = str(text_element)
            for protocol, pattern in NODE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    node = match.group(0)
                    if protocol == "vmess" and node.startswith("vmess://"):
                        try:
                            decoded_vmess = base64.b64decode(node[len("vmess://"):].strip('=')).decode('utf-8')
                            json.loads(decoded_vmess)
                            unique_nodes.add(node)
                        except (base64.binascii.Error, json.JSONDecodeError):
                            logging.debug(f"Vmess 节点 {node} 解码或解析失败，跳过。")
                    else:
                        unique_nodes.add(node)
            
            # 尝试解码可能隐藏在文本中的base64（再次，更通用）
            # 匹配可能包含Base64字符的字符串，长度至少20，通常Base64是4的倍数
            for word_match in re.finditer(r'\b[A-Za-z0-9+/=]{20,}\b', text):
                word = word_match.group(0)
                # 尝试填充Base64字符串
                padding_needed = len(word) % 4
                if padding_needed != 0:
                    word += '=' * (4 - padding_needed)
                
                try:
                    decoded_text_from_html_base64 = base64.b64decode(word).decode('utf-8', errors='ignore')
                    # 再次运行节点匹配
                    for protocol, pattern in NODE_PATTERNS.items():
                        for match in re.finditer(pattern, decoded_text_from_html_base64):
                            node = match.group(0)
                            if protocol == "vmess" and node.startswith("vmess://"):
                                try:
                                    decoded_vmess = base64.b64decode(node[len("vmess://"):].strip('=')).decode('utf-8')
                                    json.loads(decoded_vmess)
                                    unique_nodes.add(node)
                                except (base64.binascii.Error, json.JSONDecodeError):
                                    logging.debug(f"Vmess 节点 {node} 解码或解析失败，跳过。")
                            else:
                                unique_nodes.add(node)
                except (base64.binascii.Error, UnicodeDecodeError):
                    pass # 不是有效的 Base64 编码，或者解码失败

    return list(unique_nodes)

async def process_url(url: str, all_nodes_writer: aiofiles.threadpool.binary.AsyncTextIOWrapper, semaphore: asyncio.Semaphore):
    """处理单个 URL，获取内容，提取节点并写入文件，受并发信号量控制。"""
    async with semaphore: # Acquire a semaphore slot
        logging.info(f"开始处理 URL: {url}")
        content = await get_url_content(url)

        if not content:
            logging.warning(f"无法获取 {url} 的内容，跳过该 URL 的节点提取。")
            return url, 0

        logging.info(f"开始解析 {url} 的内容...")
        unique_nodes = await extract_nodes_from_content(url, content)
        logging.info(f"完成解析 {url} 的内容。")

        unique_nodes = list(set(unique_nodes)) # Final deduplication for this URL

        safe_url_name = re.sub(r'[^a-zA-Z0-9.\-_]', '_', url) # 清理URL用于文件名
        url_output_file = os.path.join(DATA_DIR, f"{safe_url_name}.txt")
        try:
            async with aiofiles.open(url_output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes:
                    await f.write(f"{node}\n")
            logging.info(f"URL: {url} 的节点已保存到 {url_output_file}")
        except IOError as e:
            logging.error(f"写入 URL 节点文件 {url_output_file} 失败 (IO 错误): {e}")
        except Exception as e:
            logging.error(f"写入 URL 节点文件 {url_output_file} 时发生未知错误: {e}")
            
        # 将所有节点写入总文件
        try:
            for node in unique_nodes:
                await all_nodes_writer.write(f"{node}\n")
        except IOError as e:
            logging.error(f"写入总节点文件 {ALL_NODES_FILE} 失败 (IO 错误): {e}")
        except Exception as e:
            logging.error(f"写入总节点文件 {ALL_NODES_FILE} 时发生未知错误: {e}")


        logging.info(f"URL: {url} 成功提取到 {len(unique_nodes)} 个节点。")
        return url, len(unique_nodes)

async def main():
    """主函数，读取 sources.list 并并行处理 URL。"""
    # 1. 清理旧缓存文件
    await clean_old_cache_files(CLEANUP_THRESHOLD_HOURS)

    if not os.path.exists('sources.list'):
        logging.error("sources.list 文件不存在，请创建并添加 URL。")
        return

    with open('sources.list', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not urls:
        logging.warning("sources.list 中没有找到有效的 URL。")
        return

    node_counts = defaultdict(int)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) # 创建信号量，限制并发请求数

    async with aiofiles.open(ALL_NODES_FILE, 'w', encoding='utf-8') as all_nodes_writer:
        tasks = [process_url(url, all_nodes_writer, semaphore) for url in urls]
        results = await asyncio.gather(*tasks)

        for url, count in results:
            node_counts[url] = count
    
    # 将每个 URL 的节点数量写入 CSV 文件
    try:
        async with aiofiles.open(NODE_COUNT_CSV, 'w', encoding='utf-8', newline='') as f: # 使用 newline='' 避免空行
            writer = csv.writer(f)
            writer.writerow(["URL", "NodeCount"])
            for url, count in node_counts.items():
                writer.writerow([url, count])
    except IOError as e:
        logging.error(f"写入节点计数 CSV 文件 {NODE_COUNT_CSV} 失败 (IO 错误): {e}")
    except Exception as e:
        logging.error(f"写入节点计数 CSV 文件 {NODE_COUNT_CSV} 时发生未知错误: {e}")


    logging.info("所有 URL 处理完成。")

if __name__ == "__main__":
    asyncio.run(main())
