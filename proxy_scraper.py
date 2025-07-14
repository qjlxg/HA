import asyncio
import httpx
import re
import yaml
import json
import base64
from bs4 import BeautifulSoup
import aiofiles
import os
import csv
import hashlib
import time
from datetime import datetime, timedelta
import random
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

# 定义支持的节点协议前缀
SUPPORTED_PROTOCOLS = [
    "hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"
]

# 用户代理列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36"
]

# 缓存目录和过期时间（24小时）
CACHE_DIR = "cache"
CACHE_EXPIRATION_TIME = timedelta(hours=24)

# 确保data和cache目录存在
os.makedirs("data", exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

async def read_urls_from_file(file_path="sources.list"):
    """
    从指定文件中读取URL列表。
    """
    urls = []
    try:
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 忽略空行和注释行
                    urls.append(line)
        logging.info(f"成功从 {file_path} 读取 {len(urls)} 个URL。")
    except FileNotFoundError:
        logging.error(f"错误：文件 {file_path} 未找到。")
    return urls

def get_full_url(url):
    """
    补全URL，如果缺少http或https前缀。
    """
    if not (url.startswith("http://") or url.startswith("https://")):
        return f"http://{url}"  # 优先尝试HTTP
    return url

def validate_node(node_string):
    """
    验证节点字符串是否符合已知协议格式且信息完整。
    """
    for protocol in SUPPORTED_PROTOCOLS:
        if node_string.startswith(protocol):
            try:
                if protocol == "vmess://":
                    # VMess 节点是 Base64 编码的 JSON
                    # 注意：如果解码后的JSON内容包含非UTF-8字符，这里也可能报错
                    decoded = base64.b64decode(node_string[len("vmess://"):].encode('utf-8')).decode('utf-8')
                    node_info = json.loads(decoded)
                    return all(k in node_info for k in ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type'])
                elif protocol == "vless://":
                    # VLESS 节点通常是 URL 格式，包含 UUID 和地址
                    parts = re.match(r"vless:\/\/([a-f0-9-]+)@([\d\w\.-]+):(\d+)", node_string)
                    return bool(parts)
                elif protocol == "trojan://":
                    # Trojan 节点通常是 password@address:port
                    parts = re.match(r"trojan:\/\/([^@]+)@([\d\w\.-]+):(\d+)", node_string)
                    return bool(parts)
                elif protocol == "ss://":
                    # SS 节点是 Base64 编码的 method:password@server:port
                    # Base64 部分可能包含非 UTF-8 编码的密码
                    encoded_part = node_string[len("ss://"):].split('#')[0]
                    if '@' in encoded_part:
                        base66_segment = encoded_part.split('@')[0]
                        try:
                            # 尝试对 Base64 部分解码，但不强制进行 UTF-8 解码，只判断 Base64 格式是否有效
                            base64.b64decode(base66_segment.encode('utf-8'))
                            return '@' in node_string and ':' in node_string # 确保有 @ 和 : 分隔符
                        except (base64.binascii.Error):
                            # Base64 解码失败，说明 Base64 字符串本身无效
                            return False
                    return False # 没有 @ 分隔符也不是有效的 SS 链接
                elif protocol == "ssr://":
                    # SSR 节点是 Base64 编码的 URL
                    # 对解码后的内容忽略 UTF-8 错误
                    decoded = base64.b64decode(node_string[len("ssr://"):].encode('utf-8')).decode('utf-8', errors='ignore')
                    return 'obfsparam=' in decoded and 'protoparam=' in decoded
                elif protocol == "hysteria2://":
                    # Hysteria2 节点格式
                    return re.match(r"hysteria2:\/\/([^@]+)@([\d\w\.-]+):(\d+)\?.*", node_string) is not None
            except Exception as e:
                # 捕获所有其他解析/验证错误
                logging.warning(f"节点 {node_string[:50]}... 验证失败: {e}")
                return False
    return False

def parse_and_extract_nodes(content):
    """
    解析网页内容，提取各种格式的节点，并进行初步过滤。
    优先处理 <pre>, <code>, <textarea> 等可能包含节点内容的标签。
    """
    nodes = set()
    soup = BeautifulSoup(content, 'html.parser')

    # 优先从 pre, code, textarea 标签中提取
    for tag_name in ['pre', 'code', 'textarea']:
        for tag in soup.find_all(tag_name):
            text_content = tag.get_text()
            # 查找所有支持的协议前缀
            for protocol in SUPPORTED_PROTOCOLS:
                # 改进的正则表达式，匹配协议开头，直到遇到空格或换行符
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s]+', text_content)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)

    # 查找 Base64 编码的字符串 (更谨慎地处理解码)
    base64_patterns = [
        r'[A-Za-z0-9+/]{20,}=+', # 常见的 Base64 模式，可能包含非节点内容
        r'vmess:\/\/([A-Za-z0-9+/]+={0,2})', # 捕获 VMess Base64 部分
        r'ss:\/\/([A-Za-z0-9+/]+={0,2})' # 捕获 SS Base64 部分
    ]
    for pattern in base64_patterns:
        for match in re.findall(pattern, content):
            try:
                # 在这里，我们假设解码后的内容是 UTF-8，但如果不是，我们忽略错误
                decoded_content = base64.b64decode(match).decode('utf-8', errors='ignore')
                for protocol in SUPPORTED_PROTOCOLS:
                    # 再次在解码内容中查找节点
                    found_nodes = re.findall(rf'{re.escape(protocol)}[^\s]+', decoded_content)
                    for node in found_nodes:
                        if validate_node(node): # 这里的 validate_node 已经改进了对 ss:// 的处理
                            nodes.add(node)
            except (base64.binascii.Error, UnicodeDecodeError):
                # 忽略 Base64 解码失败的情况，或 Base64 解码成功但不是有效 UTF-8 的情况
                pass

    # 查找 YAML 和 JSON 中的节点（假设节点是字符串值）
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) or isinstance(data, list):
            yaml_str = json.dumps(data) # 转换为字符串以便正则匹配
            for protocol in SUPPORTED_PROTOCOLS:
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s"\']+', yaml_str)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)
    except yaml.YAMLError:
        pass # 不是 YAML 格式

    try:
        data = json.loads(content)
        if isinstance(data, dict) or isinstance(data, list):
            json_str = json.dumps(data) # 转换为字符串以便正则匹配
            for protocol in SUPPORTED_PROTOCOLS:
                found_nodes = re.findall(rf'{re.escape(protocol)}[^\s"\']+', json_str)
                for node in found_nodes:
                    if validate_node(node):
                        nodes.add(node)
    except json.JSONDecodeError:
        pass # 不是 JSON 格式

    # 查找明文节点
    for protocol in SUPPORTED_PROTOCOLS:
        # 在整个内容中查找，但避免匹配HTML标签属性等
        found_nodes = re.findall(rf'{re.escape(protocol)}[^\s<>"\'
