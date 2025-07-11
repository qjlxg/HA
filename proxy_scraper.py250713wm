#完美
import re
import os
import csv
import base64
import yaml
import json
import hashlib
import random
import warnings
import time
import asyncio
from urllib.parse import unquote, urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup
import logging
import httpx
import urllib3
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
import aiofiles
import geoip2.database # 导入 geoip2 库，用于IP地理位置查询
import socket # 用于DNS解析 (作为备用)
import aiodns # 导入 aiodns 库，用于异步DNS解析

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO, # 设置日志级别为信息
    format='%(asctime)s - %(levelname)s - %(message)s', # 日志格式
    handlers=[
        logging.FileHandler('crawler.log', encoding='utf-8'), # 将日志写入文件
        logging.StreamHandler() # 将日志输出到控制台
    ]
)
logger = logging.getLogger(__name__) # 获取日志记录器实例

# 忽略 InsecureRequestWarning 警告 (当使用 verify=False 时可能出现)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 数据类定义 ---
@dataclass
class CrawlerConfig:
    """爬虫配置类"""
    data_dir: str = "data" # 数据文件存放目录
    sources_file: str = "sources.list" # 包含源URL列表的文件
    # node_counts_file: 节点统计CSV文件路径，使用 field(default_factory=...) 确保在运行时正确初始化
    node_counts_file: str = field(default_factory=lambda: os.path.join("data", "node_counts.csv"))
    # cache_file: URL缓存文件路径
    cache_file: str = field(default_factory=lambda: os.path.join("data", "url_cache.json"))
    # failed_urls_file: 失败URL日志文件路径
    failed_urls_file: str = field(default_factory=lambda: os.path.join("data", "failed_urls.log"))
    concurrent_requests_limit: int = 20 # 并发请求URL的数量限制
    request_timeout: float = 20.0 # HTTP请求超时时间（秒）
    retry_attempts: int = 3 # HTTP请求失败后的重试次数
    cache_save_interval: int = 50 # 每处理多少个URL保存一次缓存
    max_recursion_depth: int = 2 # 最大递归抓取深度（0表示只抓取sources.list中的URL）
    proxies: Optional[Dict] = None # HTTP/HTTPS代理配置字典 (例如: {"http://": "http://user:pass@host:port"})
    # user_agents: 用于HTTP请求的用户代理列表，使用 field(default_factory=list) 确保可变默认值正确初始化
    user_agents: List[str] = field(default_factory=list)

    # 节点测试配置 (示例，实际逻辑需要额外实现)
    node_test: Dict = field(default_factory=dict)
    # GeoIP 和节点命名配置
    geoip: Dict = field(default_factory=dict)

    def __post_init__(self):
        """数据类初始化后处理，确保目录存在和路径正确"""
        # 确保数据目录存在
        os.makedirs(self.data_dir, exist_ok=True)
        
        # 确保路径基于 data_dir，如果它们不是绝对路径或已经正确设置
        if not os.path.isabs(self.node_counts_file) and not self.node_counts_file.startswith(self.data_dir):
            self.node_counts_file = os.path.join(self.data_dir, os.path.basename(self.node_counts_file))
        if not os.path.isabs(self.cache_file) and not self.cache_file.startswith(self.data_dir):
            self.cache_file = os.path.join(self.data_dir, os.path.basename(self.cache_file))
        if not os.path.isabs(self.failed_urls_file) and not self.failed_urls_file.startswith(self.data_dir):
            self.failed_urls_file = os.path.join(self.data_dir, os.path.basename(self.failed_urls_file))

        # 如果 user_agents 列表为空，则使用默认值
        if not self.user_agents:
            self.user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
            ]
        
        # GeoIP 默认值设置
        self.geoip.setdefault('enable_geo_rename', False) # 默认不启用地理位置重命名
        self.geoip.setdefault('database_path', os.path.join(self.data_dir, 'GeoLite2-Country.mmdb')) # 默认数据库路径
        self.geoip.setdefault('default_country', 'UNKNOWN') # 默认国家代码

# --- 节点协议正则表达式 ---
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# 匹配 Base64 字符串的正则表达式 (至少20个字符，减少误判)
BASE64_REGEX = re.compile(r'[A-Za-z0-9+/=]{20,}', re.IGNORECASE)

# --- 辅助函数 ---

async def load_config(config_file: str) -> CrawlerConfig:
    """从 YAML 文件加载配置"""
    try:
        async with aiofiles.open(config_file, mode='r', encoding='utf-8') as f:
            content = await f.read()
            config_data = yaml.safe_load(content)
            # 使用 **config_data 来创建 CrawlerConfig 实例，自动映射配置项
            return CrawlerConfig(**config_data)
    except FileNotFoundError:
        logger.error(f"配置文件 '{config_file}' 未找到，将使用默认配置。")
        return CrawlerConfig()
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}，将使用默认配置。")
        return CrawlerConfig()

async def read_sources(file_path: str) -> List[str]:
    """异步读取 sources.list 文件中的 URL"""
    try:
        async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
            lines = await f.readlines()
        urls = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        logger.info(f"成功读取 {len(urls)} 个源 URL。")
        return urls
    except FileNotFoundError:
        logger.error(f"源文件 '{file_path}' 未找到。")
        return []
    except Exception as e:
        logger.error(f"读取源文件失败: {e}。")
        return []

async def load_cache(cache_file: str) -> Dict:
    """异步加载 URL 缓存"""
    if os.path.exists(cache_file):
        try:
            async with aiofiles.open(cache_file, mode='r', encoding='utf-8') as f:
                content = await f.read()
            return json.loads(content)
        except json.JSONDecodeError:
            logger.warning(f"缓存文件 '{cache_file}' 损坏，将重新生成。")
            return {}
        except Exception as e:
            logger.error(f"加载缓存失败 '{cache_file}': {e}。")
            return {}
    return {}

async def save_cache(cache_file: str, cache_data: Dict) -> None:
    """异步保存 URL 缓存"""
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        async with aiofiles.open(cache_file, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(cache_data, indent=4, ensure_ascii=False))
    except Exception as e:
        logger.error(f"保存缓存失败 '{cache_file}': {e}。")

async def log_failed_url(url: str, reason: str, config: CrawlerConfig) -> None:
    """异步记录失败的 URL 及其原因到文件"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(config.failed_urls_file), exist_ok=True)
        async with aiofiles.open(config.failed_urls_file, mode='a', encoding='utf-8') as f:
            await f.write(f"[{timestamp}] {url}: {reason}\n")
    except Exception as e:
        logger.error(f"记录失败 URL 失败 '{config.failed_urls_file}': {e}。")

def decode_base64_recursive(data: str) -> Optional[str]:
    """尝试递归解码 Base64 字符串，直到无法再解码或内容不再是 Base64。"""
    if not isinstance(data, str) or not data.strip() or len(data) < 20:
        return None

    current_decoded = data
    for _ in range(5):  # 最多递归5层
        try:
            # 尝试 urlsafe 解码
            decoded_bytes = base64.urlsafe_b64decode(current_decoded + '==')
            temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if not temp_decoded or temp_decoded == current_decoded:
                break
            # 检查解码后的字符串是否仍然是 Base64 格式，如果是则继续解码
            # 否则，停止递归，认为已经到达最终内容
            if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                current_decoded = temp_decoded
                break
            current_decoded = temp_decoded
        except (base64.binascii.Error, UnicodeDecodeError):
            try:
                # 尝试标准 Base64 解码
                decoded_bytes = base64.b64decode(current_decoded + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded:
                    break
                if not BASE64_REGEX.fullmatch(temp_decoded.strip()):
                    current_decoded = temp_decoded
                    break
                current_decoded = temp_decoded
            except (base64.binascii.Error, UnicodeDecodeError):
                break
        except Exception as e:
            logger.debug(f"Base64 解码错误: {e}")
            break
    return current_decoded

async def resolve_hostname_async(hostname: str) -> Optional[str]:
    """异步解析域名到 IP 地址"""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname): # 已经是IP地址
        return hostname
    
    try:
        resolver = aiodns.resolver.Resolver()
        # 尝试 A 记录 (IPv4)
        result = await resolver.query(hostname, 'A')
        if result:
            return result[0].host
        # 也可以尝试 AAAA 记录 (IPv6)
        # result_ipv6 = await resolver.query(hostname, 'AAAA')
        # if result_ipv6:
        #     return result_ipv6[0].host
    except aiodns.error.DNSError as e:
        logger.debug(f"DNS 解析失败 {hostname}: {e}")
    except Exception as e:
        logger.debug(f"解析 {hostname} 时发生意外错误: {e}")
    return None

async def fetch_content(url: str, client: httpx.AsyncClient, config: CrawlerConfig, cache_data: Dict = None) -> Tuple[Optional[str], Optional[Dict], str]:
    """
    异步尝试通过 HTTP 或 HTTPS 获取指定 URL 的内容，并包含重试机制。
    """
    headers = {
        'User-Agent': random.choice(config.user_agents), # 随机选择 User-Agent
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'DNT': '1', # Do Not Track 请求头
        'Connection': 'keep-alive'
    }

    if cache_data:
        # 添加缓存相关的HTTP头，实现条件请求
        if 'etag' in cache_data:
            headers['If-None-Match'] = cache_data['etag']
        if 'last_modified' in cache_data:
            headers['If-Modified-Since'] = cache_data['last_modified']

    test_urls = []
    # 确保 URL 总是带上协议头，避免 httpx 内部解析问题
    parsed = urlparse(url)
    if not parsed.scheme:
        # 如果原始URL没有协议头，尝试 HTTPS 和 HTTP
        test_urls.extend([f"https://{url}", f"http://{url}"])
    else:
        # 如果原始URL已有协议头，直接使用
        test_urls.append(url)

    for attempt in range(config.retry_attempts):
        for test_url in test_urls:
            try:
                # 发送 GET 请求，允许重定向
                response = await client.get(test_url, headers=headers, follow_redirects=True)
                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                content_type = response.headers.get('Content-Type', '').lower()
                content_hash = hashlib.sha256(response.content).hexdigest()

                # 如果内容哈希与缓存中的相同，则表示内容未修改
                if cache_data and cache_data.get('content_hash') == content_hash:
                    logger.info(f"{url} 内容未变更，跳过解析。")
                    # 即使内容未变，也更新缓存元数据（如最新的ETag/Last-Modified）
                    return None, {
                        'etag': new_etag,
                        'last_modified': new_last_modified,
                        'content_hash': content_hash,
                        'content_type': content_type,
                        'last_updated_timestamp': cache_data.get('last_updated_timestamp', 'N/A')
                    }, "SKIPPED_UNCHANGED"

                response.raise_for_status() # 检查HTTP状态码，如果不是2xx则抛出异常
                current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                return response.text, {
                    'etag': new_etag,
                    'last_modified': new_last_modified,
                    'content_hash': content_hash,
                    'content_type': content_type,
                    'last_updated_timestamp': current_time
                }, "FETCH_SUCCESS"

            except httpx.TimeoutException:
                logger.warning(f"{url} 请求超时 (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = "FETCH_FAILED_TIMEOUT"
            except httpx.HTTPStatusError as e:
                logger.warning(f"{url} HTTP错误 ({e.response.status_code}) (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = f"FETCH_FAILED_HTTP_{e.response.status_code}"
            except httpx.ConnectError as e:
                logger.warning(f"{url} 连接错误 ({e}) (尝试 {attempt + 1}/{config.retry_attempts})。")
                status = "FETCH_FAILED_CONNECTION_ERROR"
            except Exception as e:
                logger.error(f"{url} 未知错误: {e} (尝试 {attempt + 1}/{config.retry_attempts})。", exc_info=True) # 打印详细栈回溯
                status = "FETCH_FAILED_UNEXPECTED_ERROR"

        if attempt < config.retry_attempts - 1:
            await asyncio.sleep(2 ** attempt + random.uniform(0.5, 1.5)) # 指数退避加随机抖动

    logger.error(f"{url} 所有尝试均失败。")
    await log_failed_url(url, status, config) # 记录失败URL
    return None, None, status

def standardize_node_url(node_url: str) -> str:
    """
    标准化节点链接的查询参数和部分结构，以便更精确地去重。
    并确保返回的 URL 不包含内部换行符。
    """
    if not isinstance(node_url, str):
        return ""

    try:
        parsed = urlparse(node_url)
    except ValueError as e:
        logger.warning(f"标准化节点URL时遇到无效格式错误: {e} - URL: {node_url}")
        # 尝试清理，但返回原始URL，不进行标准化
        return node_url.replace('\n', '').replace('\r', '')

    if parsed.query:
        # 解析查询参数，排序后重新编码，确保参数顺序一致性
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
        encoded_query = urlencode(sorted_params, doseq=True)
        parsed = parsed._replace(query=encoded_query)

    if node_url.lower().startswith("vmess://"):
        try:
            # VMess 链接的 netloc 部分是 Base64 编码的 JSON
            b64_content = parsed.netloc
            decoded = decode_base64_recursive(b64_content)
            if decoded:
                vmess_json = json.loads(decoded)
                # 对 VMess 字段进行排序，保证一致性，同时考虑不同键的类型（字符串化）
                sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                # 确保 base64 内容不包含换行符
                return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}"
        except Exception as e:
            logger.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
            return node_url.replace('\n', '').replace('\r', '') # 失败时也清理

    final_url = parsed.geturl()
    # 显式地从最终的 URL 字符串中移除任何换行符
    return final_url.replace('\n', '').replace('\r', '')

def is_valid_hysteria2_node(node_link: str) -> bool:
    """
    校验 Hysteria2 链接是否有效。
    一个有效的 Hysteria2 链接通常至少包含：
    - 协议头: hysteria2://
    - 用户信息 (UUID 或密码) 和服务器地址:port
    这里我们要求链接中必须有 `@` 符号，且 `@` 之前的部分不为空（代表 UUID/密码），
    并且有有效的服务器地址和端口。
    """
    if not node_link.lower().startswith("hysteria2://"):
        return False

    try:
        parsed = urlparse(node_link)
        netloc = parsed.netloc

        if '@' not in netloc:
            logger.debug(f"Hysteria2 节点缺少认证信息: {node_link}")
            return False # 缺少认证信息

        auth_info, addr_port = netloc.split('@', 1)
        if not auth_info.strip(): # 认证信息为空
            logger.debug(f"Hysteria2 节点认证信息为空: {node_link}")
            return False

        if ':' not in addr_port:
            logger.debug(f"Hysteria2 节点缺少端口: {node_link}")
            return False # 缺少端口

        server, port_str = addr_port.rsplit(':', 1)
        if not server:
            logger.debug(f"Hysteria2 节点服务器地址为空: {node_link}")
            return False
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            logger.debug(f"Hysteria2 节点端口无效: {node_link}")
            return False # 端口不是有效的数字或不在范围内

        return True
    except ValueError:
        logger.debug(f"Hysteria2 链接格式不正确: {node_link}")
        return False # 链接格式不正确

def is_valid_node(node_url: str) -> bool:
    """
    检查节点 URL 的基本有效性并根据协议进行严格校验。
    """
    if not isinstance(node_url, str) or len(node_url) < 10:
        logger.debug(f"节点URL太短或不是字符串: {node_url}")
        return False

    parsed = urlparse(node_url)
    scheme = parsed.scheme.lower()

    if scheme not in NODE_PATTERNS:
        logger.debug(f"不支持的节点协议: {scheme} - {node_url}")
        return False # 不支持的协议

    # 尝试解析节点信息，这将帮助我们进行更细致的校验
    node_info = parse_node_url_to_info(node_url)
    if not node_info:
        logger.debug(f"无法解析节点信息: {node_url}")
        return False # 无法解析基本信息

    server = node_info.get('server')
    port = node_info.get('port')
    name = node_info.get('name')

    # 基本服务器和端口校验（适用于大多数协议）
    if not server:
        logger.debug(f"{scheme} 节点缺少服务器地址: {node_url}")
        return False
    if port is None or not isinstance(port, int) or not (1 <= port <= 65535):
        logger.debug(f"{scheme} 节点端口无效: {port} - {node_url}")
        return False

    if scheme == "hysteria2":
        return is_valid_hysteria2_node(node_url) # 调用专门的Hysteria2校验

    elif scheme == "vmess":
        # VMess 校验：确保有 UUID (id)
        if not node_info.get('id'):
            logger.debug(f"VMess 节点缺少 UUID: {node_url}")
            return False
        # 可以进一步校验UUID格式，但通常不是强制的
        return True

    elif scheme == "trojan":
        # Trojan 校验：确保有密码 (password)
        if not node_info.get('password'):
            logger.debug(f"Trojan 节点缺少密码: {node_url}")
            return False
        return True

    elif scheme == "ss":
        # SS 校验：确保有加密方法 (cipher) 和密码 (password)
        if not (node_info.get('cipher') and node_info.get('password')):
            logger.debug(f"SS 节点缺少加密方法或密码: {node_url}")
            return False
        return True

    elif scheme == "ssr":
        # SSR 校验：SSR 结构复杂，通常需要解析其内部参数
        # 这里进行一个基础校验：确保 Base64 解码后能得到一些关键信息
        # SSR 链接通常是 ssr://<base64_encoded_params>
        # 编码内容通常是 server:port:protocol:method:obfs:base64_password/?params#name
        try:
            decoded_ssr_content = decode_base64_recursive(parsed.netloc)
            if not decoded_ssr_content:
                logger.debug(f"SSR 节点 Base64 解码失败或为空: {node_url}")
                return False
            
            # 尝试解析 SSR 内部结构
            parts = decoded_ssr_content.split(':')
            if len(parts) < 6: # 至少包含 server, port, protocol, method, obfs, password_base64
                logger.debug(f"SSR 节点内部结构不完整: {node_url}")
                return False
            
            # 进一步校验端口
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535):
                logger.debug(f"SSR 节点内部端口无效: {node_url}")
                return False
            
            # 校验密码部分是否可解码 (如果存在)
            # password_base64 = parts[5].split('/?')[0].split('/#')[0]
            # try:
            #     base64.urlsafe_b64decode(password_base64 + '==')
            # except (base64.binascii.Error, UnicodeDecodeError):
            #     logger.debug(f"SSR 节点密码 Base64 解码失败: {node_url}")
            #     return False

            return True
        except Exception as e:
            logger.debug(f"SSR 节点解析异常: {e} - {node_url}")
            return False

    elif scheme == "vless":
        # Vless 校验：确保有 UUID
        if not node_info.get('id'): # Vless 的 UUID 在 parse_node_url_to_info 中被映射到 'id'
            logger.debug(f"Vless 节点缺少 UUID: {node_url}")
            return False
        # 可以进一步校验UUID格式，但通常不是强制的
        return True

    return True # 如果通过了所有检查，则认为是有效节点

def convert_dict_to_node_link(node_dict: Dict) -> Optional[str]:
    """
    将字典形式的节点数据转换为标准节点链接。
    """
    if not isinstance(node_dict, dict):
        return None

    node_type = node_dict.get('type', '').lower()
    server = node_dict.get('server') or node_dict.get('add')
    port = node_dict.get('port')
    password = node_dict.get('password')
    uuid = node_dict.get('uuid') or node_dict.get('id')
    name = node_dict.get('name') or node_dict.get('ps', '') # 备注/名称

    try:
        port = int(port) if port is not None else None
        if port and not (1 <= port <= 65535):
            logger.debug(f"无效端口号: {port} for node {name}")
            return None
    except (ValueError, TypeError):
        logger.debug(f"端口号非整数: {port} for node {name}")
        return None

    if not server: # 服务器地址是必须的
        return None

    if node_type == 'vmess':
        if not (uuid and port): # VMess 必须有 UUID 和端口
            return None
        vmess_obj = {
            "v": node_dict.get('v', '2'),
            "ps": name, # 备注
            "add": server,
            "port": port,
            "id": uuid,
            "aid": int(node_dict.get('alterId', node_dict.get('aid', 0))),
            "net": node_dict.get('network', node_dict.get('net', 'tcp')),
            "type": node_dict.get('type', 'none'),
            "host": node_dict.get('udp', node_dict.get('host', '')),
            "path": node_dict.get('path', ''),
            "tls": "tls" if node_dict.get('tls') else "none",
            "sni": node_dict.get('servername', node_dict.get('sni', '')),
            "scy": node_dict.get('cipher', ''),
            "fp": node_dict.get('fingerprint', '')
        }
        # 移除空值或默认值，使 JSON 更简洁
        vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]}
        try:
            sorted_vmess = dict(sorted(vmess_obj.items())) # 排序确保一致性
            b64_encoded = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}" # 确保不含换行符
        except Exception as e:
            logger.debug(f"转换 VMess 字典失败: {e}, dict: {node_dict}")
            return None

    elif node_type in ['vless', 'trojan']:
        auth = uuid if node_type == 'vless' else password
        if not (auth and port): # Vless 必须有 UUID 和端口；Trojan 必须有密码和端口
            return None
        link = f"{node_type}://{auth}@{server}:{port}"
        params = {}
        if node_dict.get('security') or node_dict.get('tls'):
            params['security'] = node_dict.get('security', 'tls')
        for key in ['flow', 'network', 'path', 'host', 'servername', 'alpn', 'fingerprint']:
            if node_dict.get(key):
                params[key if key != 'servername' else 'sni'] = node_dict[key]
        if name:
            params['remarks'] = name # Vless/Trojan的备注通常是#remarks或query参数
        params = {k: v for k, v in params.items() if v}
        if params:
            # 排序参数，确保一致性
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        return link.replace('\n', '').replace('\r', '')

    elif node_type == 'ss':
        if not (password and node_dict.get('cipher') and port): # SS 必须有密码、加密方法和端口
            return None
        method_pwd = f"{node_dict['cipher']}:{password}"
        encoded = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')
        link = f"ss://{encoded}@{server}:{port}"
        if name:
            link += f"#{name}" # SS的备注通常在#之后
        return link.replace('\n', '').replace('\r', '')

    elif node_type == 'ssr':
        # SSR 转换需要所有关键字段
        if not all(k in node_dict for k in ['server', 'port', 'protocol', 'method', 'obfs', 'password']):
            logger.debug(f"SSR 节点缺少关键字段: {node_dict}")
            return None
        
        # SSR 协议参数编码
        # server:port:protocol:method:obfs:base64_password/?params#name
        # protocol, method, obfs 字段直接使用
        # password 需要 base64 编码
        # params (如 obfsparam, protoparam) 需要在 ? 后面
        
        ssr_password_b64 = base64.urlsafe_b64encode(node_dict['password'].encode()).decode().rstrip('=')
        
        # 构建核心部分
        core_parts = [
            str(server),
            str(port),
            node_dict.get('protocol', 'origin'), # 默认协议
            node_dict.get('method', 'none'), # 默认加密方法
            node_dict.get('obfs', 'plain'), # 默认混淆
            ssr_password_b64
        ]
        
        ssr_link_base = ":".join(core_parts)
        
        params = {}
        if node_dict.get('obfsparam'):
            params['obfsparam'] = base64.urlsafe_b64encode(node_dict['obfsparam'].encode()).decode().rstrip('=')
        if node_dict.get('protoparam'):
            params['protoparam'] = base64.urlsafe_b64encode(node_dict['protoparam'].encode()).decode().rstrip('=')
        
        query_string = urlencode(sorted(params.items()), doseq=True)
        
        if query_string:
            ssr_link_base += f"/?{query_string}"
        
        # 最终 Base64 编码整个 ssr_link_base
        encoded_full_ssr = base64.urlsafe_b64encode(ssr_link_base.encode()).decode().rstrip('=')
        
        final_link = f"ssr://{encoded_full_ssr}"
        if name:
            final_link += f"#{name}"
        
        return final_link.replace('\n', '').replace('\r', '')

    elif node_type == 'hysteria2':
        auth = uuid or password
        if not (auth and port): # Hysteria2 必须有认证信息和端口
            return None
        link = f"hysteria2://{auth}@{server}:{port}"
        params = {}
        if node_dict.get('insecure') is not None:
            params['insecure'] = int(bool(node_dict['insecure'])) # 0 或 1
        for key in ['obfs', 'obfs-password', 'sni', 'up', 'down', 'auth_str', 'alpn', 'peer', 'fast_open']:
            if node_dict.get(key):
                params[key.replace('_', '-')] = node_dict[key] # 转换参数名以匹配URL格式
        params = {k: v for k, v in params.items() if v}
        if params:
            link += "?" + urlencode(sorted(params.items()), doseq=True)
        if name:
            link += f"#{urlparse(name).path.replace(' ', '%20')}" # Hysteria2的名称在#之后
        return link.replace('\n', '').replace('\r', '')

    return None

def parse_node_url_to_info(node_url: str) -> Optional[Dict]:
    """
    解析节点 URL，提取其协议、服务器地址、端口、名称等关键信息。
    返回一个字典，便于后续操作。
    """
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        node_info = {"protocol": scheme, "original_url": node_url}
        
        if scheme == "vmess":
            decoded = decode_base64_recursive(parsed.netloc)
            if decoded:
                vmess_obj = json.loads(decoded)
                node_info.update(vmess_obj)
                node_info["server"] = vmess_obj.get("add")
                node_info["port"] = vmess_obj.get("port")
                node_info["name"] = vmess_obj.get("ps", "")
        elif scheme in ["vless", "trojan", "ss", "ssr", "hysteria2"]:
            netloc_parts = parsed.netloc.split('@', 1)
            if len(netloc_parts) == 2:
                auth_info, addr_port_str = netloc_parts
            else: # SS, SSR可能没有@，只有地址:端口
                auth_info = ""
                addr_port_str = netloc_parts[0] if netloc_parts else ""
            
            if ':' in addr_port_str:
                server, port_str = addr_port_str.rsplit(':', 1)
                node_info["server"] = server
                node_info["port"] = int(port_str) if port_str.isdigit() else None
            else:
                node_info["server"] = addr_port_str
                node_info["port"] = None # netloc中没有端口
            
            # 从 URL fragment (即 # 后面的部分) 提取名称
            if parsed.fragment:
                node_info["name"] = unquote(parsed.fragment)
            else:
                node_info["name"] = node_info.get("server", "") # 如果没有 fragment，使用服务器地址作为默认名称

            # 对于 SS 协议，解码认证信息以获取加密方法和密码
            if scheme == "ss":
                try:
                    decoded_auth = base64.b64decode(auth_info).decode('utf-8', errors='ignore')
                    if ':' in decoded_auth:
                        cipher, password = decoded_auth.split(':', 1)
                        node_info["cipher"] = cipher
                        node_info["password"] = password
                except Exception as e:
                    logger.debug(f"解码 SS 认证信息失败: {e}")
            elif scheme == "hysteria2": # 提取 Hysteria2 的认证字符串
                node_info["auth_str"] = auth_info
            elif scheme == "ssr":
                # SSR 内部结构解析 (简化版，实际可能更复杂)
                try:
                    decoded_ssr_content = decode_base64_recursive(parsed.netloc)
                    if decoded_ssr_content:
                        parts = decoded_ssr_content.split(':')
                        if len(parts) >= 6: # server:port:protocol:method:obfs:base64_password
                            node_info["server"] = parts[0]
                            node_info["port"] = int(parts[1]) if parts[1].isdigit() else None
                            node_info["protocol"] = parts[2]
                            node_info["method"] = parts[3]
                            node_info["obfs"] = parts[4]
                            # password is base64 encoded in parts[5]
                            try:
                                password_b64 = parts[5].split('/?')[0].split('/#')[0]
                                node_info["password"] = base64.urlsafe_b64decode(password_b64 + '==').decode('utf-8', errors='ignore')
                            except Exception as e:
                                logger.debug(f"SSR 密码解码失败: {e}")
                        # 处理 obfsparam 和 protoparam
                        if '/?' in decoded_ssr_content:
                            query_str = decoded_ssr_content.split('/?', 1)[1].split('/#')[0]
                            query_params = parse_qs(query_str)
                            if 'obfsparam' in query_params and query_params['obfsparam']:
                                node_info['obfsparam'] = base64.urlsafe_b64decode(query_params['obfsparam'][0] + '==').decode('utf-8', errors='ignore')
                            if 'protoparam' in query_params and query_params['protoparam']:
                                node_info['protoparam'] = base64.urlsafe_b64decode(query_params['protoparam'][0] + '==').decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug(f"SSR 内部解析失败: {e}")
            elif scheme == "vless":
                # Vless 的 UUID 就是 netloc 的用户部分
                node_info["id"] = auth_info # 映射到 'id' 字段以便统一处理
        
        # 解析查询参数以获取更多信息
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for k, v in query_params.items():
                if v: node_info[k] = v[0] # 取第一个值

        return node_info
    except Exception as e:
        logger.debug(f"解析节点URL失败: {node_url}, 错误: {e}")
        return None

def update_node_remark(node_url: str, new_remark: str) -> str:
    """
    更新节点 URL 中的 remark/ps (名称) 字段。
    """
    parsed = urlparse(node_url)
    scheme = parsed.scheme.lower()

    if scheme == "vmess":
        try:
            b64_content = parsed.netloc
            decoded = decode_base64_recursive(b64_content)
            if decoded:
                vmess_json = json.loads(decoded)
                vmess_json['ps'] = new_remark # 更新备注字段
                
                # 重新编码并重构 URL
                sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                return f"vmess://{normalized_b64.replace('\n', '').replace('\r', '')}"
        except Exception as e:
            logger.debug(f"更新 VMess 备注失败: {e}")
            return node_url
    elif scheme in ["vless", "trojan", "ss", "ssr", "hysteria2"]:
        # 对于这些协议，备注通常在 URL 的 fragment 部分 (# 之后)
        new_parsed = parsed._replace(fragment=new_remark)
        return new_parsed.geturl().replace('\n', '').replace('\r', '')
    
    return node_url # 如果协议未处理，则返回原始URL

_geoip_reader = None # 全局变量，用于存储 GeoIP Reader 实例

def get_country_code_from_ip(ip: str, geoip_db_path: str) -> str:
    """从 IP 地址获取国家代码"""
    global _geoip_reader
    if not _geoip_reader:
        try:
            _geoip_reader = geoip2.database.Reader(geoip_db_path)
        except geoip2.errors.AddressNotFoundError:
            logger.error(f"GeoIP 数据库文件未找到或无效: {geoip_db_path}")
            return "ERR"
        except Exception as e:
            logger.error(f"加载 GeoIP 数据库失败: {e}")
            return "ERR"

    try:
        response = _geoip_reader.country(ip)
        return response.country.iso_code or "UNKNOWN" # 返回 ISO 国家代码，如果无法识别则为 UNKNOWN
    except geoip2.errors.AddressNotFoundError:
        return "UNKNOWN" # IP 地址未在数据库中找到
    except Exception as e:
        logger.debug(f"查询 GeoIP 失败 {ip}: {e}")
        return "ERR"

async def rename_and_deduplicate_by_geo(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """
    根据地理位置重命名和去重节点。
    返回一个更新了名称的节点集合。
    """
    if not config.geoip.get('enable_geo_rename', False):
        logger.info("GeoIP 命名和去重功能未启用。")
        return nodes

    geoip_db_path = config.geoip.get('database_path')
    if not os.path.exists(geoip_db_path):
        logger.error(f"GeoIP 数据库文件 '{geoip_db_path}' 不存在，无法进行地理位置命名。请下载并放置。")
        return nodes
    
    logger.info(f"开始 GeoIP 命名和去重，使用数据库: {geoip_db_path}")

    node_details = [] # 存储解析后的节点详细信息
    ip_lookup_tasks = [] # 存储DNS解析任务
    
    # 第一步：解析节点信息并收集IP/域名
    for node_url in nodes:
        info = parse_node_url_to_info(node_url)
        if info and info.get('server'):
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country']})
            ip_lookup_tasks.append(resolve_hostname_async(info['server']))
        else:
            logger.debug(f"无法解析节点服务器信息: {node_url}")
            # 对于无法解析的节点，仍然保留，但国家设为默认
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country']})

    # 第二步：并发执行DNS解析
    logger.info(f"开始并发解析 {len(ip_lookup_tasks)} 个域名/IP。")
    # 使用 return_exceptions=True 确保即使部分任务失败，其他任务也能完成
    resolved_ips = await asyncio.gather(*ip_lookup_tasks, return_exceptions=True)
    
    for i, ip_result in enumerate(resolved_ips):
        if not isinstance(ip_result, Exception) and ip_result:
            node_details[i]['ip'] = ip_result
        else:
            logger.debug(f"解析 {node_details[i]['info'].get('server', 'N/A')} 失败: {ip_result}")

    # 第三步：GeoIP查询
    loop = asyncio.get_running_loop()
    geoip_tasks = []
    for detail in node_details:
        if detail['ip']:
            # 使用 loop.run_in_executor 将同步的 geoip2 查询放入线程池执行，避免阻塞事件循环
            geoip_tasks.append(loop.run_in_executor(None, get_country_code_from_ip, detail['ip'], geoip_db_path))
        else:
            # 对于没有 IP 的节点，直接返回默认国家
            geoip_tasks.append(asyncio.sleep(0, result=config.geoip['default_country']))

    logger.info(f"开始并发查询 {len(geoip_tasks)} 个IP的地理位置。")
    country_codes = await asyncio.gather(*geoip_tasks)

    for i, country_code in enumerate(country_codes):
        node_details[i]['country'] = country_code
        logger.debug(f"节点 {node_details[i]['original_url'][:50]}... IP: {node_details[i]['ip']} -> 国家: {country_code}")

    # 第四步：分组、重命名和重新去重
    # grouped_nodes: 按国家代码分组节点
    grouped_nodes: Dict[str, List[Dict]] = defaultdict(list)
    
    for detail in node_details:
        # 创建一个更精细的唯一标识符用于去重，基于 IP、端口、协议和认证信息哈希
        unique_key_parts = []
        if detail['ip']:
            unique_key_parts.append(detail['ip'])
        if detail['info'].get('port'):
            unique_key_parts.append(str(detail['info']['port']))
        unique_key_parts.append(detail['info']['protocol'])
        
        # 对于认证信息（UUID, Password等），只取哈希或关键部分以确保隐私和简洁
        auth_id = ""
        if detail['info']['protocol'] == 'vmess':
            auth_id = detail['info'].get('id', '')
        elif detail['info']['protocol'] in ['vless', 'hysteria2']:
            auth_id = detail['info'].get('uuid', detail['info'].get('auth_str', ''))
        elif detail['info']['protocol'] == 'trojan':
            auth_id = detail['info'].get('password', '')
        elif detail['info']['protocol'] == 'ss':
            auth_id = detail['info'].get('password', '') + detail['info'].get('cipher', '')
        elif detail['info']['protocol'] == 'ssr': # SSR 认证信息可能在内部
            auth_id = detail['info'].get('password', '') + detail['info'].get('method', '') + detail['info'].get('obfs', '')

        if auth_id:
            unique_key_parts.append(hashlib.sha256(auth_id.encode()).hexdigest()[:8]) # 用哈希的短前缀

        unique_node_identifier = "_".join(unique_key_parts)
        
        detail['unique_identifier'] = unique_node_identifier
        grouped_nodes[detail['country']].append(detail)
    
    final_renamed_nodes = set()
    seen_unique_identifiers = set() # 用于确保最终列表中的节点是基于功能性去重的

    for country_code, details_list in sorted(grouped_nodes.items()):
        # 对同一国家的节点进行排序，以便获得稳定的序号
        # 可以按原始URL哈希或者解析出的server+port排序
        details_list.sort(key=lambda x: hashlib.sha256(x['original_url'].encode()).hexdigest())

        counter = 0
        for detail in details_list:
            if detail['unique_identifier'] not in seen_unique_identifiers:
                counter += 1
                new_remark = f"{country_code}_{counter:02d}" # 例如 SG_01
                updated_node_url = update_node_remark(detail['original_url'], new_remark)
                final_renamed_nodes.add(updated_node_url)
                seen_unique_identifiers.add(detail['unique_identifier'])
            else:
                logger.debug(f"发现功能性重复节点，跳过重命名: {detail['original_url']}")

    logger.info(f"GeoIP 命名和去重完成，得到 {len(final_renamed_nodes)} 个唯一节点。")
    return final_renamed_nodes


def extract_nodes_from_json(parsed_json: Dict | List) -> List[str]:
    """从解析后的JSON数据中提取节点链接。"""
    nodes = set()
    if isinstance(parsed_json, dict):
        if 'proxies' in parsed_json and isinstance(parsed_json['proxies'], list):
            for proxy in parsed_json['proxies']:
                if isinstance(proxy, dict):
                    node = convert_dict_to_node_link(proxy)
                    if node and is_valid_node(node):
                        nodes.add(node)
        # 兼容其他可能包含节点列表的 JSON 结构
        for value in parsed_json.values():
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value))
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_json(value)) # 递归查找
    elif isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item))
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_json(item)) # 递归查找
    return list(nodes)

def extract_nodes_from_yaml(parsed_yaml: Dict | List) -> List[str]:
    """从解析后的YAML数据中提取节点链接。"""
    nodes = set()
    if isinstance(parsed_yaml, dict):
        if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
            for proxy in parsed_yaml['proxies']:
                if isinstance(proxy, dict):
                    node = convert_dict_to_node_link(proxy)
                    if node and is_valid_node(node):
                        nodes.add(node)
        # 兼容其他可能包含节点列表的 YAML 结构
        for value in parsed_yaml.values():
            if isinstance(value, str):
                nodes.update(extract_and_validate_nodes(value))
            elif isinstance(value, (dict, list)):
                nodes.update(extract_nodes_from_yaml(value)) # 递归查找
    elif isinstance(parsed_yaml, list):
        for item in parsed_yaml:
            if isinstance(item, str):
                nodes.update(extract_and_validate_nodes(item))
            elif isinstance(item, (dict, list)):
                nodes.update(extract_nodes_from_yaml(item)) # 递归查找
    return list(nodes)

def extract_nodes_from_html(html_content: str, base_url: str) -> Tuple[List[str], List[str]]:
    """
    从HTML内容中提取节点链接，并识别可能指向其他订阅源的URL。
    返回 (extracted_node_links, potential_subscription_urls)
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    nodes = set()
    new_urls = set()

    # 1. 查找所有链接
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        
        # 将相对路径转换为绝对路径
        absolute_href = urljoin(base_url, href)
        
        # 尝试将href作为节点链接处理
        standardized = standardize_node_url(unquote(absolute_href))
        if is_valid_node(standardized):
            nodes.add(standardized)
        else:
            # 如果不是直接节点，检查是否为订阅链接
            # 过滤掉常见的图片、JS、CSS、邮件等链接，只关注可能的订阅链接
            if (absolute_href.startswith(('http://', 'https://')) and
                not absolute_href.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico')) and
                not absolute_href.startswith('mailto:') and
                (absolute_href.endswith(('.txt', '.yaml', '.yml', '.json')) or
                 'sub' in absolute_href.lower() or 'subscribe' in absolute_href.lower() or
                 'clash' in absolute_href.lower() or 'singbox' in absolute_href.lower() or
                 'v2ray' in absolute_href.lower() or 'trojan' in absolute_href.lower() or
                 'ss' in absolute_href.lower() or 'ssr' in absolute_href.lower() or
                 'hysteria' in absolute_href.lower())):
                new_urls.add(absolute_href)

    # 2. 查找 <pre>, <code>, <textarea> 中的文本内容，这些可能包含原始节点列表或Base64编码
    for tag in soup.find_all(['pre', 'code', 'textarea']):
        text = tag.get_text().strip()
        if text:
            # 尝试直接解析其中的节点
            nodes.update(extract_and_validate_nodes(text))
            # 尝试 Base64 解码并提取节点
            decoded = decode_base64_recursive(text)
            if decoded and decoded != text:
                nodes.update(extract_and_validate_nodes(decoded))

    # 3. 查找 <script> 标签中的内容，可能包含 JSON 或 Base64 编码的节点
    for script in soup.find_all('script'):
        script_content = script.string
        if script_content:
            # 尝试解析 JSON
            if script_content.strip().startswith(('{', '[')):
                try:
                    js_data = json.loads(script_content)
                    # 递归从JS数据中提取节点
                    nodes.update(extract_nodes_from_json(js_data))
                except json.JSONDecodeError:
                    pass
            
            # 提取脚本内容中的所有类似 Base64 的字符串并尝试解码
            for b64 in BASE64_REGEX.findall(script_content):
                if len(b64) > 30 and '=' in b64: # 简单过滤短的或非Base64的匹配
                    decoded = decode_base64_recursive(b64)
                    if decoded and decoded != b64:
                        # 从解码后的内容中提取节点
                        nodes.update(extract_and_validate_nodes(decoded))

    return list(nodes), list(new_urls)

def parse_content(content: str, base_url: str, content_type: str) -> Tuple[List[str], List[str]]:
    """
    智能解析内容，尝试通过 Content-Type 提示，然后回退到内容嗅探。
    返回 (extracted_node_links, new_urls_to_follow)
    """
    nodes = set()
    new_urls = set()

    # 1. 尝试 JSON 解析 (基于 Content-Type 或内容前缀)
    if "json" in content_type or content.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(content)
            logger.info("内容被识别为 JSON 格式。")
            nodes.update(extract_nodes_from_json(parsed))
            # JSON 内容中可能也直接包含 Base64 编码的节点列表
            nodes.update(extract_and_validate_nodes(content))
            return list(nodes), list(new_urls)
        except json.JSONDecodeError:
            logger.debug("内容尝试 JSON 解析失败。")
            pass

    # 2. 尝试 YAML 解析 (基于 Content-Type 或内容前缀)
    if "yaml" in content_type or content.strip().startswith(("---", "- ", "proxies:", "outbounds:")):
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']):
                logger.info("内容被识别为 YAML 格式。")
                nodes.update(extract_nodes_from_yaml(parsed))
                # YAML 内容中可能也直接包含 Base64 编码的节点列表
                nodes.update(extract_and_validate_nodes(content))
                return list(nodes), list(new_urls)
        except yaml.YAMLError:
            logger.debug("内容尝试 YAML 解析失败。")
            pass

    # 3. 尝试 HTML 解析 (基于 Content-Type 或内容前缀)
    if "html" in content_type or any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html>']):
        logger.info("内容被识别为 HTML 格式。")
        html_nodes, html_urls = extract_nodes_from_html(content, base_url)
        nodes.update(html_nodes)
        new_urls.update(html_urls)
        # HTML 页面中的文本部分也可能直接包含 Base64 编码的节点列表
        nodes.update(extract_and_validate_nodes(content))
        return list(nodes), list(new_urls)

    # 4. 尝试纯文本/Base64 嗅探 (作为最后的回退)
    logger.info("内容尝试纯文本/Base64 嗅探。")
    decoded = decode_base64_recursive(content)
    content_to_scan = decoded if decoded and decoded != content else content # 如果成功解码，则扫描解码后的内容
    if decoded and decoded != content:
        logger.info("内容被识别为 Base64 编码，已递归解码。")

    # 解码后尝试再次进行 JSON/YAML 解析
    try:
        parsed = json.loads(content_to_scan)
        nodes.update(extract_nodes_from_json(parsed))
    except json.JSONDecodeError:
        pass
    try:
        parsed = yaml.safe_load(content_to_scan)
        if isinstance(parsed, dict) and any(key in parsed for key in ['proxies', 'proxy-groups', 'outbounds']):
            nodes.update(extract_nodes_from_yaml(parsed))
    except yaml.YAMLError:
        pass
    nodes.update(extract_and_validate_nodes(content_to_scan))
    return list(nodes), list(new_urls)

def extract_and_validate_nodes(content: str) -> List[str]:
    """ 从解析后的内容中提取并验证所有支持格式的节点 URL。 """
    if not content:
        return []
    nodes = set()
    for name, pattern in NODE_PATTERNS.items():
        for match in pattern.findall(content):
            normalized = standardize_node_url(unquote(match).strip())
            if is_valid_node(normalized): # 使用增强后的 is_valid_node
                nodes.add(normalized)
    return list(nodes)

async def save_node_counts_to_csv(file_path: str, counts_data: Dict) -> None:
    """将每个 URL 的节点数量统计保存到 CSV 文件。"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
            fieldnames = ['URL', 'Status', 'Extracted Nodes Count', 'New URLs Found Count', 'Last Updated']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            await f.write(','.join(writer.fieldnames) + '\n') # 手动写入CSV头，因为aiofiles没有writer.writeheader()
            for url, data in counts_data.items():
                # 确保写入的行与 fieldnames 匹配
                await f.write(f"{url},{data.get('status', 'N/A')},{data.get('extracted_nodes_count', 0)},{data.get('new_urls_found_count', 0)},{data.get('last_updated_timestamp', 'N/A')}\n")
        logger.info(f"节点统计信息已保存到 {file_path}。")
    except Exception as e:
        logger.error(f"保存节点统计信息失败 '{file_path}': {e}。", exc_info=True)

def sanitize_filename(url: str) -> str:
    """
    从 URL 创建一个文件系统安全的文件名。
    使用 SHA256 哈希确保长/复杂 URL 的唯一性和有效性，
    并预置 URL 的一个短的、可识别的部分。
    """
    parsed = urlparse(url)
    # 使用 hostname 和 path 作为可识别的前缀
    prefix = parsed.hostname or "link"
    if parsed.path:
        path = parsed.path.strip('/').replace('/', '_')
        if path:
            prefix += f"_{path}"
    
    # 对完整 URL 进行哈希，确保唯一性并处理无效字符
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    
    # 结合截断的前缀和哈希
    # 限制前缀长度，避免文件名过长
    max_prefix_len = 50
    if len(prefix) > max_prefix_len:
        prefix = prefix[:max_prefix_len] + "_"

    # 替换无效的文件名字符 (例如: :, ?, *, <, >, |, ", /)
    safe_prefix = "".join(c for c in prefix if c.isalnum() or c in ('_', '-')).strip()
    if not safe_prefix: # 如果前缀在净化后变为空，则使用默认值
        safe_prefix = "url"

    return f"{safe_prefix}_{url_hash[:10]}.txt" # 使用哈希的短前缀作为文件名

async def process_url(url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, 
                     url_cache: Dict, config: CrawlerConfig, depth: int) -> Tuple[str, List[str], List[str]]:
    """
    处理单个 URL，包括内容抓取、缓存管理和节点/新 URL 提取。
    返回 (处理状态, 提取到的节点列表, 发现的新 URL 列表)。
    """
    async with semaphore: # 使用信号量控制并发
        logger.info(f"正在处理 URL: {url} (深度: {depth})。")
        cache_data = url_cache.get(url, {}) # 获取缓存数据
        
        content, cache_meta, status = await fetch_content(url, client, config, cache_data)
        
        # 更新缓存 for this URL
        if cache_meta:
            url_cache[url] = {**cache_data, **cache_meta}

        if status == "SKIPPED_UNCHANGED":
            # 如果内容未修改，使用之前缓存的提取节点和URL
            nodes = cache_data.get('extracted_nodes', [])
            new_urls = cache_data.get('new_urls_found', [])
            logger.info(f"{url} 内容未变更，使用缓存数据。提取节点数: {len(nodes)}, 发现新URL数: {len(new_urls)}。")
            return status, nodes, new_urls
        elif status.startswith("FETCH_FAILED"):
            return status, [], []
        elif content is None: # 理论上不应该发生，除非 fetch_content 成功但返回 None
            logger.error(f"{url} 内容抓取成功但返回内容为 None。")
            return "FETCH_SUCCESS_NO_CONTENT", [], []

        # 解析内容并提取节点/新 URL
        content_type = cache_meta.get('content_type', 'unknown') if cache_meta else 'unknown'
        nodes, new_urls = parse_content(content, url, content_type)
        
        # 更新缓存，包含提取的节点和新 URL
        url_cache[url].update({
            'extracted_nodes': nodes,
            'new_urls_found': new_urls,
            'parse_status': "PARSE_SUCCESS",
            'last_updated_timestamp': cache_meta.get('last_updated_timestamp', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")) # 确保时间戳存在
        })

        logger.info(f"{url} 解析完成。提取节点数: {len(nodes)}, 发现新URL数: {len(new_urls)}。")
        
        # 将提取到的节点保存到以 URL 命名的文件中
        if nodes:
            filename = os.path.join(config.data_dir, sanitize_filename(url))
            try:
                os.makedirs(os.path.dirname(filename), exist_ok=True) # 确保输出目录存在
                async with aiofiles.open(filename, mode='w', encoding='utf-8') as f:
                    for node in nodes:
                        await f.write(f"{node}\n") # 直接写入节点，每个节点一行
                logger.info(f"已将 {len(nodes)} 个节点保存到文件: {filename}。")
            except Exception as e:
                logger.error(f"保存节点到文件失败 ({filename}): {e}。", exc_info=True)

        return "PROCESSED_SUCCESS", nodes, new_urls

# 增强：节点活跃度测试函数 (仅框架，实际测试逻辑复杂)
async def test_and_filter_nodes(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """
    异步测试节点活跃度并进行筛选。
    这是一个框架函数，实际的测试逻辑需要根据不同的协议和测试方式进行实现。
    例如：对 HTTP/SOCKS 代理进行 CONNECT 请求，对 Vmess/Trojan 等使用特定库进行握手。
    """
    if not config.node_test.get('enable', False):
        logger.info("节点活跃度测试未启用，跳过。")
        return nodes

    logger.info(f"开始测试 {len(nodes)} 个节点，并发数: {config.node_test.get('concurrency', 10)}。")
    tested_good_nodes = set()
    semaphore = asyncio.Semaphore(config.node_test.get('concurrency', 10))

    async def _test_single_node(node: str) -> Optional[str]:
        async with semaphore:
            # 这是一个示例测试逻辑，您需要根据实际协议进行替换
            # 例如：使用 httpx 尝试通过代理访问一个测试网站
            try:
                # 假设有一个函数 parse_node_info 可以从 node_url 提取代理信息
                # proxy_info = parse_node_url_to_info(node)
                # if proxy_info and proxy_info.get('protocol') == 'http':
                #     async with httpx.AsyncClient(proxies={"http://": f"http://{proxy_info['server']}:{proxy_info['port']}"}, timeout=config.node_test.get('timeout', 5)) as client:
                #         resp = await client.get("http://www.google.com/generate_204")
                #         resp.raise_for_status()
                #     logger.debug(f"节点 {node[:30]}... 测试成功。")
                #     return node
                
                # 暂时直接返回，表示框架，模拟测试时间
                await asyncio.sleep(0.1) # 模拟测试时间
                if random.random() > 0.1: # 模拟90%成功率
                    return node
                else:
                    logger.debug(f"节点 {node[:30]}... 测试失败。")
                    return None
            except Exception as e:
                logger.debug(f"节点 {node[:30]}... 测试过程中出现错误: {e}")
                return None

    tasks = [_test_single_node(node) for node in nodes]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            tested_good_nodes.add(result)
    
    logger.info(f"节点活跃度测试完成，发现 {len(tested_good_nodes)} 个可用节点。")
    return tested_good_nodes

# 增强：保存节点为 Clash 配置 (示例框架)
async def save_nodes_as_clash_config(file_path: str, nodes: Set[str]) -> None:
    """异步将节点保存为 Clash YAML 配置格式 (仅框架，需完善)"""
    clash_proxies = []
    for node_url in nodes:
        node_info = parse_node_url_to_info(node_url)
        if not node_info:
            continue
        
        # 尝试使用 GeoIP 命名后的名称，否则使用协议和服务器
        proxy_name = node_info.get("name", f"{node_info['protocol']}-{node_info.get('server', 'unknown')}")
        proxy_type = node_info["protocol"] # 转换为 Clash 兼容的类型
        
        # 这是一个简化示例，实际需要更详细的映射，将各种协议的参数转换为 Clash 兼容的字段
        clash_proxy_entry = {
            "name": proxy_name,
            "type": proxy_type,
            "server": node_info.get("server"),
            "port": node_info.get("port")
            # ... 更多特定协议的参数映射，例如：
            # "uuid": node_info.get("id"), # VMess
            # "alterId": node_info.get("aid", 0), # VMess
            # "cipher": node_info.get("cipher"), # SS
            # "password": node_info.get("password"), # SS, Trojan
            # "tls": node_info.get("tls", False), # Vless, Trojan, VMess
            # "network": node_info.get("net", "tcp"), # VMess
            # "ws-path": node_info.get("path", "/"), # VMess (websocket)
            # "ws-headers": {"Host": node_info.get("host")}, # VMess (websocket)
            # "sni": node_info.get("sni"), # Vless, Trojan, Hysteria2
            # "obfs": node_info.get("obfs"), # Hysteria2
            # "obfs-password": node_info.get("obfs-password"), # Hysteria2
        }
        # 移除 None 值，使 Clash 配置更简洁
        clash_proxy_entry = {k: v for k, v in clash_proxy_entry.items() if v is not None}
        clash_proxies.append(clash_proxy_entry)
        
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": clash_proxies,
        "proxy-groups": [
            # 这是一个简单的代理组，实际可以根据需求创建更多分组
            {"name": "Proxy", "type": "select", "proxies": [p["name"] for p in clash_proxies if "name" in p]},
            {"name": "DIRECT", "type": "direct"}
        ],
        "rules": [
            # 这是一个简单的规则，所有流量都走 Proxy 组
            "MATCH,Proxy"
        ]
    }

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True) # 确保输出目录存在
        async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
            await f.write(yaml.dump(clash_config, indent=2, allow_unicode=True, sort_keys=False)) # sort_keys=False 保持字典插入顺序
        logger.info(f"已将 Clash 配置保存到 {file_path}。")
    except Exception as e:
        logger.error(f"保存 Clash 配置失败: {e}。", exc_info=True)


async def main():
    """主函数"""
    start_time = time.time()
    
    # 从 config.yaml 文件加载配置
    config = await load_config("config.yaml")
    
    sources_urls = await read_sources(config.sources_file)
    if not sources_urls:
        logger.error("无有效源 URL，退出程序。")
        return

    url_cache = await load_cache(config.cache_file)
    url_summary = defaultdict(int) # 统计各种状态的URL数量
    url_details = {} # 存储每个URL的详细处理信息
    processed_count = 0 # 已处理的URL计数
    unique_nodes = set() # 存储所有唯一且有效的节点

    # 初始化 httpx.AsyncClient，不再直接传递 proxies 参数
    # 如果需要使用代理，应通过 httpx.ProxyTransport 或环境变量配置
    async with httpx.AsyncClient(timeout=config.request_timeout, verify=False) as client:
        semaphore = asyncio.Semaphore(config.concurrent_requests_limit) # 控制并发请求数量的信号量
        queue = deque([(url, 0) for url in sources_urls]) # 双端队列，用于广度优先遍历
        urls_in_queue = set(sources_urls) # 跟踪已加入队列的URL，避免重复

        while queue:
            url, depth = queue.popleft() # 从队列左侧取出URL和当前深度

            # 避免重复处理已在url_details中记录的URL，除非是之前处理失败的URL
            if url in url_details and url_details[url].get('status') not in ["FETCH_FAILED_UNEXPECTED_ERROR", "UNEXPECTED_MAIN_ERROR"]:
                logger.debug(f"URL {url} 已处理或在处理中，跳过。")
                continue

            processed_count += 1
            logger.info(f"正在处理第 {processed_count} 个URL (总队列中): {url} (深度: {depth})。")

            try:
                # 处理当前 URL，获取状态、提取到的节点和新发现的URL
                status, nodes, new_urls = await process_url(url, client, semaphore, url_cache, config, depth)
                unique_nodes.update(nodes) # 将提取到的节点添加到总的唯一节点集合中
                
                # 更新当前URL的详细处理信息
                url_details[url] = {
                    'status': status,
                    'extracted_nodes_count': len(nodes),
                    'new_urls_found_count': len(new_urls),
                    'last_updated_timestamp': url_cache.get(url, {}).get('last_updated_timestamp', 'N/A')
                }
                url_summary[status] += 1 # 更新状态统计

                # 如果当前深度允许进一步递归，则将新发现的URL添加到队列
                if depth < config.max_recursion_depth:
                    for new_url in new_urls:
                        # 确保新URL未被处理过且未在队列中，避免无限循环和重复抓取
                        if new_url not in urls_in_queue and new_url not in url_details:
                            queue.append((new_url, depth + 1))
                            urls_in_queue.add(new_url)

                # 定期保存缓存，防止程序意外中断导致数据丢失
                if processed_count % config.cache_save_interval == 0:
                    await save_cache(config.cache_file, url_cache)

            except Exception as e:
                logger.error(f"处理URL {url} 时发生意外主循环异常: {e}", exc_info=True)
                url_details[url] = {
                    'status': "UNEXPECTED_MAIN_ERROR",
                    'extracted_nodes_count': 0, # 如果发生意外错误，节点计数清零
                    'new_urls_found_count': 0,
                    'last_updated_timestamp': url_cache.get(url, {}).get('last_updated_timestamp', 'N/A')
                }
                url_summary["UNEXPECTED_MAIN_ERROR"] += 1
                await log_failed_url(url, f"主循环错误: {e}", config) # 记录失败URL
                await save_cache(config.cache_file, url_cache) # 立即保存缓存，即使出错

    # ----------------------------------------------------
    # 新增 GeoIP 命名和去重步骤：在所有节点收集完毕后进行
    # ----------------------------------------------------
    if config.geoip.get('enable_geo_rename', False):
        unique_nodes = await rename_and_deduplicate_by_geo(unique_nodes, config)

    # 增强：在所有节点收集完毕后进行活跃度测试 (GeoIP处理之后，这样测试的是已命名和去重过的节点)
    if config.node_test.get('enable', False):
        unique_nodes = await test_and_filter_nodes(unique_nodes, config)

    # 保存所有唯一节点到一个总文件
    total_nodes_file = os.path.join(config.data_dir, "all_nodes.txt")
    try:
        os.makedirs(os.path.dirname(total_nodes_file), exist_ok=True) # 确保输出目录存在
        async with aiofiles.open(total_nodes_file, mode='w', encoding='utf-8') as f:
            for node in sorted(unique_nodes):
                await f.write(f"{node}\n")
        logger.info(f"已将 {len(unique_nodes)} 个唯一节点保存到 {total_nodes_file}。")
    except Exception as e:
        logger.error(f"保存总节点文件失败: {e}。", exc_info=True)

    # 增强：保存 Clash 配置
    clash_config_file = os.path.join(config.data_dir, "clash_config.yaml")
    await save_nodes_as_clash_config(clash_config_file, unique_nodes)


    await save_cache(config.cache_file, url_cache) # 脚本结束时，保存最终缓存
    await save_node_counts_to_csv(config.node_counts_file, url_details) # 保存最终统计信息

    end_time = time.time()
    logger.info("\n--- 处理完成报告 ---")
    logger.info(f"总计处理 {processed_count} 个 URL。")
    logger.info(f"总计提取唯一节点: {len(unique_nodes)}。")
    logger.info("状态统计:")
    for status, count in sorted(url_summary.items()):
        logger.info(f"  {status}: {count} 个。")
    logger.info(f"总耗时: {end_time - start_time:.2f} 秒。")

if __name__ == "__main__":
    # 运行主异步函数
    asyncio.run(main())
