import re
import os
import csv
import json
import base64
import yaml
import hashlib
import random
import logging
import asyncio
import aiohttp
import socket
import time
import warnings
from urllib.parse import unquote, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup, SoupStrainer
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime
import urllib3

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
    handlers=[
        logging.FileHandler("node_extractor.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 忽略 InsecureRequestWarning
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# --- 配置模块 ---
class Config:
    DATA_DIR = "data"
    SOURCES_FILE = os.path.join(DATA_DIR, "sources.list")
    NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, "proxy_nodes_")
    MAX_NODES_PER_SLICE = 2000
    NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
    CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")
    FAILED_URLS_FILE = os.path.join(DATA_DIR, "failed_urls.log")
    MAX_CONCURRENT_REQUESTS = min(os.cpu_count() * 2 or 4, 20)
    REQUEST_TIMEOUT = 15
    RETRY_ATTEMPTS = 3
    MINIMUM_BACKOFF = 1
    MAXIMUM_BACKOFF = 10
    VALIDATE_HOSTNAME = True
    OUTPUT_BY_PROTOCOL = True
    OUTPUT_BY_REGION = True
    TEST_NODE_LATENCY = True
    LATENCY_TEST_TIMEOUT = 3
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    ]

# --- 协议解析模块 ---
class ProtocolHandler:
    NODE_PATTERNS = {
        "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "tuic": re.compile(r"tuic://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
        "wireguard": re.compile(r"wireguard://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    }
    BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', re.IGNORECASE)

    @staticmethod
    def decode_base64_recursive(data: str) -> Optional[str]:
        if not isinstance(data, str) or not data.strip() or len(data) < 20:
            return None
        current_decoded = data
        for _ in range(5):
            try:
                decoded_bytes = base64.urlsafe_b64decode(current_decoded + '==')
                temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if not temp_decoded or temp_decoded == current_decoded:
                    break
                current_decoded = temp_decoded
                if not ProtocolHandler.BASE64_REGEX.fullmatch(current_decoded):
                    break
            except (base64.binascii.Error, UnicodeDecodeError):
                try:
                    decoded_bytes = base64.b64decode(current_decoded + '==')
                    temp_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    if not temp_decoded or temp_decoded == current_decoded:
                        break
                    current_decoded = temp_decoded
                    if not ProtocolHandler.BASE64_REGEX.fullmatch(current_decoded):
                        break
                except (base64.binascii.Error, UnicodeDecodeError):
                    break
            except Exception as e:
                logger.debug(f"Base64 解码失败: {e}")
                break
        return current_decoded

    @staticmethod
    def standardize_node_url(node_url: str) -> str:
        if not isinstance(node_url, str):
            return ""
        parsed = urlparse(node_url)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
            encoded_query = urlencode(sorted_params, doseq=True)
            parsed = parsed._replace(query=encoded_query)
        if node_url.lower().startswith("vmess://"):
            try:
                b64_content = parsed.netloc
                decoded_b64 = ProtocolHandler.decode_base64_recursive(b64_content)
                if decoded_b64:
                    vmess_json = json.loads(decoded_b64)
                    sorted_vmess_json = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                    normalized_b64 = base64.b64encode(json.dumps(sorted_vmess_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                    return f"vmess://{normalized_b64}"
            except Exception as e:
                logger.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
                return node_url
        return parsed.geturl()

    @staticmethod
    async def is_valid_node(node_url: str) -> bool:
        if not isinstance(node_url, str) or len(node_url) < 10:
            return False
        found_protocol = any(node_url.lower().startswith(f"{proto}://") for proto in ProtocolHandler.NODE_PATTERNS)
        if not found_protocol:
            return False
        parsed_url = urlparse(node_url)
        if parsed_url.scheme not in ["ss", "ssr", "vmess"]:
            if not parsed_url.hostname:
                return False
            if parsed_url.port and not (1 <= parsed_url.port <= 65535):
                return False
            if Config.VALIDATE_HOSTNAME:
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, lambda: socket.getaddrinfo(parsed_url.hostname, parsed_url.port or 443))
                except (socket.gaierror, socket.timeout):
                    logger.debug(f"主机验证失败: {parsed_url.hostname}:{parsed_url.port or 443}")
                    return False
        elif parsed_url.scheme == "vmess":
            try:
                b64_content = parsed_url.netloc
                decoded = ProtocolHandler.decode_base64_recursive(b64_content)
                if not decoded:
                    return False
                vmess_obj = json.loads(decoded)
                if not all(key in vmess_obj for key in ['add', 'port', 'id']):
                    return False
                port = int(vmess_obj['port'])
                if not (1 <= port <= 65535):
                    return False
                if Config.VALIDATE_HOSTNAME:
                    try:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, lambda: socket.getaddrinfo(vmess_obj['add'], port))
                    except (socket.gaierror, socket.timeout):
                        logger.debug(f"VMess 主机验证失败: {vmess_obj['add']}:{port}")
                        return False
            except Exception:
                return False
        return True

    @staticmethod
    def convert_dict_to_node_link(node_dict: Dict) -> Optional[str]:
        if not isinstance(node_dict, dict):
            return None
        node_type = node_dict.get('type', '').lower()
        server = node_dict.get('server') or node_dict.get('add')
        port = node_dict.get('port')
        password = node_dict.get('password')
        uuid = node_dict.get('uuid') or node_dict.get('id')
        name = node_dict.get('name') or node_dict.get('ps', '')
        try:
            port = int(port) if port is not None else None
            if port and not (1 <= port <= 65535):
                logger.debug(f"无效端口: {port} for node {name}")
                return None
        except (ValueError, TypeError):
            logger.debug(f"端口非整数: {port} for node {name}")
            return None
        if not (server and port):
            return None
        if node_type == 'vmess':
            vmess_obj = {
                "v": node_dict.get('v', '2'),
                "ps": name,
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
            vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ['', 0, 'none', None]}
            try:
                sorted_vmess_obj = dict(sorted(vmess_obj.items()))
                return f"vmess://{base64.b64encode(json.dumps(sorted_vmess_obj, separators=(',', ':')).encode('utf-8')).decode('utf-8')}"
            except Exception as e:
                logger.debug(f"转换 VMess 失败: {e}")
                return None
        elif node_type == 'vless':
            if not uuid:
                return None
            vless_link = f"vless://{uuid}@{server}:{port}"
            params = {}
            if node_dict.get('security'):
                params['security'] = node_dict['security']
            elif node_dict.get('tls'):
                params['security'] = 'tls'
            for key in ['flow', 'type', 'path', 'host', 'sni', 'alpn', 'fp']:
                if node_dict.get(key):
                    params[key] = node_dict[key]
            if name:
                params['remarks'] = name
            if params:
                sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
                vless_link += "?" + urlencode(sorted_params, doseq=True)
            if name and not params:
                vless_link += f"#{name}"
            return vless_link
        elif node_type == 'trojan':
            if not password:
                return None
            trojan_link = f"trojan://{password}@{server}:{port}"
            params = {}
            if node_dict.get('security'):
                params['security'] = node_dict['security']
            elif node_dict.get('tls'):
                params['security'] = 'tls'
            for key in ['type', 'path', 'host', 'sni', 'alpn', 'fp']:
                if node_dict.get(key):
                    params[key] = node_dict[key]
            if name:
                params['remarks'] = name
            if params:
                sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
                trojan_link += "?" + urlencode(sorted_params, doseq=True)
            if name and not params:
                trojan_link += f"#{name}"
            return trojan_link
        elif node_type == 'ss':
            if not password or not node_dict.get('cipher'):
                return None
            method_pwd = f"{node_dict['cipher']}:{password}"
            encoded_method_pwd = base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8').rstrip('=')
            ss_link = f"ss://{encoded_method_pwd}@{server}:{port}"
            if name:
                ss_link += f"#{name}"
            return ss_link
        elif node_type == 'ssr':
            if not password or not node_dict.get('cipher') or not node_dict.get('obfs') or not node_dict.get('protocol'):
                return None
            ssr_data = f"{server}:{port}:{node_dict['protocol']}:{node_dict['cipher']}:{node_dict['obfs']}:{base64.b64encode(password.encode('utf-8')).decode('utf-8').rstrip('=')}"
            encoded = base64.b64encode(ssr_data.encode('utf-8')).decode('utf-8').rstrip('=')
            ssr_link = f"ssr://{encoded}"
            params = {}
            for key in ['obfs-param', 'protoparam', 'remarks', 'group']:
                if node_dict.get(key):
                    params[key] = base64.b64encode(str(node_dict[key]).encode('utf-8')).decode('utf-8').rstrip('=')
            if params:
                sorted_params = sorted([(k.replace('obfs-param', 'obfsparam').replace('protoparam', 'protoparam'), v) for k, v in params.items()])
                ssr_link += "?" + urlencode(sorted_params, doseq=True)
            return ssr_link
        elif node_type == 'hysteria2':
            if not password:
                return None
            params = {'password': password}
            for key in ['obfs', 'obfs-password', 'up', 'down', 'alpn', 'sni']:
                if node_dict.get(key):
                    params[key.replace('_', '-')] = node_dict[key]
            if name:
                params['remarks'] = name
            query_string = urlencode(sorted(params.items()), doseq=True)
            return f"hysteria2://{server}:{port}?{query_string}"
        elif node_type == 'tuic':
            if not uuid or not password:
                return None
            tuic_link = f"tuic://{uuid}:{password}@{server}:{port}"
            params = {}
            for key in ['congestion_control', 'alpn', 'sni']:
                if node_dict.get(key):
                    params[key] = node_dict[key]
            if node_dict.get('skip_cert_verify'):
                params['skip-cert-verify'] = str(node_dict['skip_cert_verify']).lower()
            if name:
                params['remarks'] = name
            if params:
                sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
                tuic_link += "?" + urlencode(sorted_params, doseq=True)
            if name and not params:
                tuic_link += f"#{name}"
            return tuic_link
        elif node_type == 'wireguard':
            if not node_dict.get('private_key') or not node_dict.get('public_key'):
                return None
            wireguard_link = f"wireguard://{server}:{port}"
            params = {
                'private_key': node_dict.get('private_key'),
                'public_key': node_dict.get('public_key'),
                'allowed_ips': node_dict.get('allowed_ips', '0.0.0.0/0,::/0'),
                'endpoint': f"{server}:{port}",
            }
            if node_dict.get('preshared_key'):
                params['preshared_key'] = node_dict['preshared_key']
            if node_dict.get('dns'):
                params['dns'] = node_dict['dns']
            if name:
                params['remarks'] = name
            sorted_params = sorted([(k, v) for k, values in params.items() for v in (values if isinstance(values, list) else [values])])
            wireguard_link += "?" + urlencode(sorted_params, doseq=True)
            return wireguard_link
        return None

    @staticmethod
    def extract_region(node_url: str) -> Optional[str]:
        parsed = urlparse(node_url)
        hostname = parsed.hostname or ''
        remarks = parsed.fragment or (parsed.path.split('/')[-1] if '/' in parsed.path else '')
        region_keywords = {
            'us': ['us', 'usa', 'united states', 'america'],
            'jp': ['jp', 'japan', 'tokyo'],
            'sg': ['sg', 'singapore'],
            'hk': ['hk', 'hongkong', 'hong kong'],
            'eu': ['eu', 'europe', 'germany', 'france', 'uk'],
        }
        for region, keywords in region_keywords.items():
            if any(keyword in hostname.lower() or keyword in remarks.lower() for keyword in keywords):
                return region
        return None

# --- 网络请求模块 ---
class NetworkClient:
    def __init__(self):
        self.session = None

    async def start_session(self):
        if not self.session:
            connector = aiohttp.TCPConnector(limit=Config.MAX_CONCURRENT_REQUESTS, ssl=False)
            self.session = aiohttp.ClientSession(connector=connector, trust_env=True)

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def fetch_content(self, url: str, cache_data: Dict = None) -> Tuple[Optional[str], Optional[Dict], str]:
        await self.start_session()
        headers = {
            'User-Agent': random.choice(Config.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Cache-Control': 'no-cache',
        }
        if cache_data:
            if cache_data.get('etag'):
                headers['If-None-Match'] = cache_data['etag']
            if cache_data.get('last_modified'):
                headers['If-Modified-Since'] = cache_data['last_modified']
        test_urls = []
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            test_urls.extend([f"http://{url}", f"https://{url}"])
        else:
            test_urls.append(url)
        for attempt in range(Config.RETRY_ATTEMPTS):
            for test_url in test_urls:
                try:
                    async with self.session.get(test_url, headers=headers, timeout=Config.REQUEST_TIMEOUT) as response:
                        if response.status == 304:
                            logger.info(f"{url} 未修改 (304)")
                            return None, cache_data, "SKIPPED_UNCHANGED"
                        response.raise_for_status()
                        content = await response.text()
                        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                        new_cache_meta = {
                            'etag': response.headers.get('ETag'),
                            'last_modified': response.headers.get('Last-Modified'),
                            'content_hash': content_hash,
                            'content_type': response.headers.get('Content-Type', '').lower()
                        }
                        if cache_data and cache_data.get('content_hash') == content_hash:
                            logger.info(f"{url} 内容未变化")
                            return None, new_cache_meta, "SKIPPED_UNCHANGED"
                        return content, new_cache_meta, "FETCH_SUCCESS"
                except aiohttp.ClientResponseError as e:
                    logger.warning(f"{url} HTTP错误 ({e.status} {e.message}) (尝试 {attempt + 1}/{Config.RETRY_ATTEMPTS})")
                    status_reason = f"FETCH_FAILED_HTTP_{e.status}"
                except aiohttp.ClientConnectionError as e:
                    logger.warning(f"{url} 连接错误 ({e}) (尝试 {attempt + 1}/{Config.RETRY_ATTEMPTS})")
                    status_reason = "FETCH_FAILED_CONNECTION_ERROR"
                except aiohttp.ClientError as e:
                    logger.warning(f"{url} 请求失败 ({e}) (尝试 {attempt + 1}/{Config.RETRY_ATTEMPTS})")
                    status_reason = "FETCH_FAILED_REQUEST_ERROR"
                except Exception as e:
                    logger.error(f"{url} 意外错误: {e} (尝试 {attempt + 1}/{Config.RETRY_ATTEMPTS})")
                    status_reason = "FETCH_FAILED_UNEXPECTED_ERROR"
                if attempt < Config.RETRY_ATTEMPTS - 1:
                    backoff = min(Config.MINIMUM_BACKOFF * (2 ** attempt) + random.uniform(0, 0.1), Config.MAXIMUM_BACKOFF)
                    await asyncio.sleep(backoff)
        logger.error(f"{url} 所有尝试失败")
        with open(Config.FAILED_URLS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {url}: {status_reason}\n")
        return None, None, status_reason

# --- 内容解析模块 ---
class ContentParser:
    @staticmethod
    def parse_content(content: str, content_type_hint: str = "unknown") -> str:
        if not content:
            return ""
        combined_text = []
        if "json" in content_type_hint or content.strip().startswith(("{", "[")):
            try:
                parsed_json = json.loads(content)
                logger.info("识别为 JSON 格式")
                nodes = ContentParser.extract_nodes_from_json(parsed_json)
                combined_text.extend(nodes)
                combined_text.append(content)
                return "\n".join(set(combined_text))
            except json.JSONDecodeError:
                logger.debug("JSON 解析失败")
        if "yaml" in content_type_hint or content.strip().startswith(("---", "- ", "proxies:")):
            try:
                parsed_yaml = yaml.safe_load(content)
                if isinstance(parsed_yaml, dict) and any(key in parsed_yaml for key in ['proxies', 'outbounds']):
                    logger.info("识别为 YAML 格式")
                    nodes = ContentParser.extract_nodes_from_yaml(parsed_yaml)
                    combined_text.extend(nodes)
                    combined_text.append(content)
                    return "\n".join(set(combined_text))
            except yaml.YAMLError:
                logger.debug("YAML 解析失败")
        if "html" in content_type_hint or any(tag in content.lower() for tag in ['<html', '<body', '<!doctype html>']):
            logger.info("识别为 HTML 格式")
            nodes = ContentParser.extract_nodes_from_html(content)
            combined_text.extend(nodes)
            return "\n".join(set(combined_text))
        logger.info("尝试文本/Base64 解析")
        decoded = ProtocolHandler.decode_base64_recursive(content)
        if decoded and decoded != content:
            combined_text.append(decoded)
            try:
                temp_json = json.loads(decoded)
                combined_text.extend(ContentParser.extract_nodes_from_json(temp_json))
            except json.JSONDecodeError:
                pass
            try:
                temp_yaml = yaml.safe_load(decoded)
                if isinstance(temp_yaml, dict) and any(key in temp_yaml for key in ['proxies', 'outbounds']):
                    combined_text.extend(ContentParser.extract_nodes_from_yaml(temp_yaml))
            except yaml.YAMLError:
                pass
        combined_text.append(content)
        all_text = "\n".join(set(combined_text))
        for b64_match in ProtocolHandler.BASE64_REGEX.findall(all_text):
            if len(b64_match) > 30 and '=' in b64_match:
                decoded_b64 = ProtocolHandler.decode_base64_recursive(b64_match)
                if decoded_b64 and decoded_b64 != b64_match:
                    combined_text.append(decoded_b64)
        return "\n".join(set(combined_text))

    @staticmethod
    def extract_nodes_from_json(parsed_json: Dict | List) -> List[str]:
        nodes = []
        if isinstance(parsed_json, list):
            for item in parsed_json:
                if isinstance(item, str):
                    nodes.append(item)
                elif isinstance(item, dict):
                    node_link = ProtocolHandler.convert_dict_to_node_link(item)
                    if node_link:
                        nodes.append(node_link)
        elif isinstance(parsed_json, dict):
            if 'proxies' in parsed_json:
                for proxy in parsed_json['proxies']:
                    if isinstance(proxy, dict):
                        node_link = ProtocolHandler.convert_dict_to_node_link(proxy)
                        if node_link:
                            nodes.append(node_link)
            for value in parsed_json.values():
                if isinstance(value, str):
                    nodes.append(value)
                    decoded = ProtocolHandler.decode_base64_recursive(value)
                    if decoded and decoded != value:
                        nodes.append(decoded)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            nodes.append(item)
                            decoded = ProtocolHandler.decode_base64_recursive(item)
                            if decoded and decoded != item:
                                nodes.append(decoded)
                        elif isinstance(item, dict):
                            node_link = ProtocolHandler.convert_dict_to_node_link(item)
                            if node_link:
                                nodes.append(node_link)
        return nodes

    @staticmethod
    def extract_nodes_from_yaml(parsed_yaml: Dict) -> List[str]:
        nodes = []
        if 'proxies' in parsed_yaml:
            for proxy in parsed_yaml['proxies']:
                if isinstance(proxy, dict) and 'type' in proxy:
                    node_link = ProtocolHandler.convert_dict_to_node_link(proxy)
                    if node_link:
                        nodes.append(node_link)
        def search_b64(obj):
            if isinstance(obj, dict):
                for v in obj.values():
                    search_b64(v)
            elif isinstance(obj, list):
                for item in obj:
                    search_b64(item)
            elif isinstance(obj, str):
                decoded = ProtocolHandler.decode_base64_recursive(obj)
                if decoded and decoded != obj:
                    nodes.append(decoded)
        search_b64(parsed_yaml)
        return nodes

    @staticmethod
    def extract_nodes_from_html(html_content: str) -> List[str]:
        nodes = []
        soup = BeautifulSoup(html_content, 'html.parser', parse_only=SoupStrainer(['pre', 'code', 'textarea']))
        for tag in soup:
            text = tag.get_text(separator="\n", strip=True)
            if text:
                nodes.append(text)
        return nodes

# --- 节点管理模块 ---
class NodeManager:
    @staticmethod
    async def extract_and_validate_nodes(content: str) -> List[Tuple[str, Optional[str], Optional[float]]]:
        nodes = []
        for pattern_name, pattern in ProtocolHandler.NODE_PATTERNS.items():
            for match in pattern.findall(content):
                decoded = unquote(match).strip()
                normalized = ProtocolHandler.standardize_node_url(decoded)
                if await ProtocolHandler.is_valid_node(normalized):
                    region = ProtocolHandler.extract_region(normalized)
                    latency = await NodeManager.test_node_latency(normalized) if Config.TEST_NODE_LATENCY else None
                    nodes.append((normalized, region, latency))
        return nodes

    @staticmethod
    async def test_node_latency(node_url: str) -> Optional[float]:
        parsed = urlparse(node_url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return None
        try:
            start_time = time.time()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=Config.LATENCY_TEST_TIMEOUT))
            return (time.time() - start_time) * 1000
        except (socket.timeout, socket.gaierror, ConnectionRefusedError):
            return None

    @staticmethod
    def save_nodes(nodes: List[Tuple[str, Optional[str], Optional[float]]], output_prefix: str):
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        for filename in os.listdir(Config.DATA_DIR):
            if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'):
                try:
                    os.remove(os.path.join(Config.DATA_DIR, filename))
                    logger.info(f"删除旧文件: {filename}")
                except OSError as e:
                    logger.warning(f"删除旧文件失败: {filename}, {e}")
        nodes_by_protocol = defaultdict(list)
        nodes_by_region = defaultdict(list)
        for node, region, latency in nodes:
            protocol = node.split('://')[0].lower()
            nodes_by_protocol[protocol].append((node, region, latency))
            if region:
                nodes_by_region[region].append((node, latency))
        saved_files = 0
        if Config.OUTPUT_BY_PROTOCOL:
            for protocol, proto_nodes in nodes_by_protocol.items():
                proto_nodes.sort(key=lambda x: (x[2] or float('inf'), x[0]))
                num_slices = (len(proto_nodes) + Config.MAX_NODES_PER_SLICE - 1) // Config.MAX_NODES_PER_SLICE
                for i in range(num_slices):
                    start = i * Config.MAX_NODES_PER_SLICE
                    end = min((i + 1) * Config.MAX_NODES_PER_SLICE, len(proto_nodes))
                    slice_nodes = proto_nodes[start:end]
                    file_name = f"{output_prefix}{protocol}_{i+1:03d}.txt"
                    try:
                        with open(file_name, 'w', encoding='utf-8') as f:
                            for j, (node, _, latency) in enumerate(slice_nodes):
                                latency_str = f" [Latency: {latency:.2f}ms]" if latency is not None else ""
                                f.write(f"Proxy-{start + j + 1:05d} = {node}{latency_str}\n")
                        logger.info(f"保存文件: {file_name} ({len(slice_nodes)} 个 {protocol} 节点)")
                        saved_files += 1
                    except IOError as e:
                        logger.error(f"保存文件失败: {file_name}, {e}")
        if Config.OUTPUT_BY_REGION:
            for region, region_nodes in nodes_by_region.items():
                region_nodes.sort(key=lambda x: (x[1] or float('inf'), x[0]))
                file_name = f"{output_prefix}region_{region}.txt"
                try:
                    with open(file_name, 'w', encoding='utf-8') as f:
                        for j, (node, latency) in enumerate(region_nodes):
                            latency_str = f" [Latency: {latency:.2f}ms]" if latency is not None else ""
                            f.write(f"Proxy-{j + 1:05d} = {node}{latency_str}\n")
                    logger.info(f"保存文件: {file_name} ({len(region_nodes)} 个 {region} 节点)")
                    saved_files += 1
                except IOError as e:
                    logger.error(f"保存文件失败: {file_name}, {e}")
        if not (Config.OUTPUT_BY_PROTOCOL or Config.OUTPUT_BY_REGION):
            nodes.sort(key=lambda x: (x[2] or float('inf'), x[0]))
            num_slices = (len(nodes) + Config.MAX_NODES_PER_SLICE - 1) // Config.MAX_NODES_PER_SLICE
            for i in range(num_slices):
                start = i * Config.MAX_NODES_PER_SLICE
                end = min((i + 1) * Config.MAX_NODES_PER_SLICE, len(nodes))
                slice_nodes = nodes[start:end]
                file_name = f"{output_prefix}{i+1:03d}.txt"
                try:
                    with open(file_name, 'w', encoding='utf-8') as f:
                        for j, (node, _, latency) in enumerate(slice_nodes):
                            latency_str = f" [Latency: {latency:.2f}ms]" if latency is not None else ""
                            f.write(f"Proxy-{start + j + 1:05d} = {node}{latency_str}\n")
                    logger.info(f"保存文件: {file_name} ({len(slice_nodes)} 个节点)")
                    saved_files += 1
                except IOError as e:
                    logger.error(f"保存文件失败: {file_name}, {e}")
        logger.info(f"共保存 {saved_files} 个文件")

# --- 主逻辑 ---
async def process_single_url(url: str, client: NetworkClient, cache_data: Dict) -> Tuple[str, int, Dict, List[Tuple[str, Optional[str], Optional[float]]], str, Set[str]]:
    logger.info(f"处理 URL: {url}")
    content, new_cache_meta, fetch_status = await client.fetch_content(url, cache_data.get(url, {}))
    if fetch_status == "SKIPPED_UNCHANGED":
        cached_info = cache_data.get(url, {'node_count': 0, 'status': 'UNKNOWN', 'protocols': []})
        return url, cached_info['node_count'], new_cache_meta, [], fetch_status, set(cached_info['protocols'])
    if fetch_status != "FETCH_SUCCESS":
        return url, 0, None, [], fetch_status, set()
    parsed_content = ContentParser.parse_content(content, new_cache_meta.get('content_type', 'unknown') if new_cache_meta else 'unknown')
    nodes = await NodeManager.extract_and_validate_nodes(parsed_content)
    protocols = {node[0].split('://')[0].lower() for node in nodes}
    logger.info(f"从 {url} 提取 {len(nodes)} 个节点，协议: {', '.join(protocols) or '无'}")
    if new_cache_meta:
        new_cache_meta['node_count'] = len(nodes)
        new_cache_meta['status'] = "PARSE_NO_NODES" if not nodes else "PARSE_SUCCESS"
        new_cache_meta['protocols'] = list(protocols)
    else:
        new_cache_meta = {'node_count': len(nodes), 'status': "PARSE_NO_NODES" if not nodes else "PARSE_SUCCESS", 'protocols': list(protocols)}
    return url, len(nodes), new_cache_meta, nodes, new_cache_meta['status'], protocols

async def main():
    start_time = time.time()
    logger.info("脚本启动")
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    source_urls = []
    try:
        with open(Config.SOURCES_FILE, 'r', encoding='utf-8') as f:
            source_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"未找到 {Config.SOURCES_FILE}")
        return
    if not source_urls:
        logger.error("无有效 URL，终止")
        return
    url_cache = {}
    try:
        if os.path.exists(Config.CACHE_FILE):
            with open(Config.CACHE_FILE, 'r', encoding='utf-8') as f:
                url_cache = json.load(f)
    except json.JSONDecodeError:
        logger.warning("缓存文件损坏，重置")
    if os.path.exists(Config.FAILED_URLS_FILE):
        try:
            os.remove(Config.FAILED_URLS_FILE)
            logger.info(f"清空 {Config.FAILED_URLS_FILE}")
        except OSError as e:
            logger.warning(f"清空失败日志失败: {e}")
    existing_nodes = set()
    for filename in os.listdir(Config.DATA_DIR):
        if filename.startswith(os.path.basename(Config.NODE_OUTPUT_PREFIX)) and filename.endswith('.txt'):
            try:
                with open(os.path.join(Config.DATA_DIR, filename), 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(' = ', 1)
                        if len(parts) == 2:
                            node_url = parts[1].split(' [')[0].strip()
                            existing_nodes.add(ProtocolHandler.standardize_node_url(node_url))
            except Exception as e:
                logger.warning(f"加载节点文件失败: {filename}, {e}")
    all_nodes = set(existing_nodes)
    url_info = {}
    url_summary = defaultdict(int)
    client = NetworkClient()
    try:
        tasks = [process_single_url(url, client, url_cache) for url in source_urls]
        for i, future in enumerate(asyncio.as_completed(tasks)):
            try:
                url, node_count, cache_meta, nodes, status, protocols = await future
                url_info[url] = {'count': node_count, 'status': status, 'protocols': protocols}
                url_summary[status] += 1
                for node, region, latency in nodes:
                    all_nodes.add(node)
                if cache_meta:
                    url_cache[url] = cache_meta
                else:
                    url_cache[url] = {'node_count': node_count, 'status': status, 'protocols': list(protocols)}
                if (i + 1) % 20 == 0:
                    try:
                        with open(Config.CACHE_FILE, 'w', encoding='utf-8') as f:
                            json.dump(url_cache, f, indent=4)
                        logger.info(f"处理 {i + 1} 个 URL，保存缓存")
                    except IOError as e:
                        logger.error(f"保存缓存失败: {e}")
            except Exception as e:
                logger.error(f"URL 处理失败: {e}", exc_info=True)
                url_summary["UNEXPECTED_MAIN_ERROR"] += 1
    finally:
        await client.close_session()
    logger.info("\n--- 处理报告 ---")
    logger.info(f"处理 {len(source_urls)} 个 URL")
    for status, count in sorted(url_summary.items()):
        logger.info(f"  {status}: {count}")
    logger.info(f"共收集 {len(all_nodes)} 个去重节点")
    NodeManager.save_nodes([(node, ProtocolHandler.extract_region(node), await NodeManager.test_node_latency(node) if Config.TEST_NODE_LATENCY else None) for node in all_nodes], Config.NODE_OUTPUT_PREFIX)
    try:
        with open(Config.NODE_COUNTS_FILE, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source URL", "Node Count", "Status", "Protocols"])
            for url in sorted(url_info.keys()):
                item = url_info[url]
                writer.writerow([url, item['count'], item['status'], ','.join(item['protocols'])])
    except IOError as e:
        logger.error(f"保存统计失败: {e}")
    try:
        with open(Config.CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(url_cache, f, indent=4)
    except IOError as e:
        logger.error(f"保存缓存失败: {e}")
    logger.info(f"耗时: {time.time() - start_time:.2f} 秒")
    if any(status.startswith("FETCH_FAILED") or status == "UNEXPECTED_MAIN_ERROR" or status == "PARSE_NO_NODES" for status in url_summary):
        logger.info(f"失败详情见: {Config.FAILED_URLS_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
