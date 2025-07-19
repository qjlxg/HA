# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import base64
import subprocess
import threading
import time
import urllib.parse
import json
import glob
import re
import yaml
import random
import string
import httpx
import asyncio
from itertools import chain
from typing import Dict, List, Optional
import sys
import requests
import zipfile
import gzip
import shutil
import platform
import os
from datetime import datetime
from asyncio import Semaphore
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import warnings
warnings.filterwarnings('ignore')
from requests_html import HTMLSession
import psutil


# TEST_URL = "http://www.gstatic.com/generate_204"
TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
# 存储所有节点的速度测试结果
SPEED_TEST = False
SPEED_TEST_LIMIT = 5 # 只测试前30个节点的下行速度，每个节点测试5秒
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 100 # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input" # 从文件中加载订阅链接或者yaml文件
# OUTPUT = "output" # 保存clash配置的文件夹
SUB_FILE = "sub_links.txt"
LAST_CHECK_FILE = 'last_check.txt'
LAST_SUC_FILE = 'last_successful_proxies.txt'
EXCLUDE_FILE = 'exclude_proxies.txt'

CLASH_DOWNLOAD_URL = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" # Updated URL

# core 名称
CLASH_CORE_NAME = "mihomo" # Updated core name

async def fetch_url(session, url, proxy=None, headers=None, allow_redirects=True):
    try:
        async with session.get(url, proxy=proxy, timeout=TIMEOUT, headers=headers, allow_redirects=allow_redirects) as response:
            response.raise_for_status()
            return await response.text()
    except httpx.RequestError as e:
        # print(f"请求失败: {e}")
        return None

def check_valid_url(url):
    # 检查URL是否符合要求
    if not (url.startswith("http://") or url.startswith("https://")):
        # print("URL不符合HTTP或HTTPS协议，已跳过:", url)
        return False
    return True

async def check_proxy_speed(session, proxy_name: str, proxy_type: str, test_url: str, timeout: int = 5):
    start_time = time.time()
    clash_api_url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}"
    try:
        # 切换节点
        await switch_proxy_async(proxy_name, api_url=clash_api_url)

        # 尝试通过代理访问目标 URL
        async with session.get(test_url, timeout=timeout) as response:
            response.raise_for_status()
            end_time = time.time()
            speed = end_time - start_time
            # print(f"节点 {proxy_name} - 类型 {proxy_type} - 速度: {speed:.2f} 秒")
            return proxy_name, proxy_type, speed
    except httpx.RequestError as e:
        # print(f"节点 {proxy_name} - 类型 {proxy_type} - 请求失败: {e}")
        return proxy_name, proxy_type, float('inf')  # 返回无穷大表示失败
    except Exception as e:
        # print(f"节点 {proxy_name} - 类型 {proxy_type} - 发生错误: {e}")
        return proxy_name, proxy_type, float('inf')

async def check_proxy_validity(session, proxy_name: str, api_url: str):
    # 切换节点
    await switch_proxy_async(proxy_name, api_url=api_url)
    try:
        # 尝试通过代理访问测试 URL
        async with session.get(TEST_URL, timeout=TIMEOUT) as response:
            response.raise_for_status()
            # print(f"节点 {proxy_name} 有效")
            return True
    except httpx.RequestError as e:
        # print(f"节点 {proxy_name} 无效: {e}")
        return False
    except Exception as e:
        # print(f"节点 {proxy_name} 发生错误: {e}")
        return False

async def get_clash_proxies(api_url: str) -> Optional[Dict]:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{api_url}/proxies", timeout=TIMEOUT)
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as e:
        print(f"获取 Clash 代理列表失败: {e}")
        return None

async def switch_proxy_async(proxy_name: str, api_url: str):
    try:
        async with httpx.AsyncClient() as client:
            # print(f"尝试切换到节点: {proxy_name}")
            response = await client.put(f"{api_url}/proxies/GLOBAL", json={"name": proxy_name}, timeout=TIMEOUT)
            response.raise_for_status()
            # print(f"成功切换到节点: {proxy_name}")
    except httpx.RequestError as e:
        print(f"切换 Clash 代理失败: {e}")

def switch_proxy(proxy_name: str):
    try:
        api_url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}"
        # print(f"尝试切换到节点: {proxy_name}")
        response = requests.put(f"{api_url}/proxies/GLOBAL", json={"name": proxy_name}, timeout=TIMEOUT)
        response.raise_for_status()
        # print(f"成功切换到节点: {proxy_name}")
    except requests.exceptions.RequestException as e:
        print(f"切换 Clash 代理失败: {e}")

async def proxy_clean():
    clash_api_url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}"
    proxies_data = await get_clash_proxies(clash_api_url)
    if not proxies_data:
        print("无法获取代理信息，跳过清理。")
        return

    all_proxies = []
    # 提取所有代理，包括常规代理和URLTest、Fallback中的代理
    for proxy_name, proxy_info in proxies_data.get('proxies', {}).items():
        if proxy_name in ['GLOBAL', 'DIRECT', 'REJECT']:
            continue
        all_proxies.append({'name': proxy_name, 'type': proxy_info.get('type', 'unknown')})
        if 'all' in proxy_info: # For 'URLTest' and 'Fallback' groups
            for p in proxy_info['all']:
                all_proxies.append({'name': p, 'type': 'group_member'}) # Mark as group member

    # 过滤掉重复的代理名称，确保每个代理只检测一次
    unique_proxies = {p['name']: p for p in all_proxies}.values()
    # print(f"共找到 {len(unique_proxies)} 个代理节点进行检测。")
    print(f"===================开始批量检测节点可用性======================")

    valid_proxies_info = []
    sem = asyncio.Semaphore(MAX_CONCURRENT_TESTS)

    async def check_and_collect(session, proxy_data, api_url):
        async with sem:
            is_valid = await check_proxy_validity(session, proxy_data['name'], api_url)
            if is_valid:
                valid_proxies_info.append(proxy_data)
            return is_valid

    async with httpx.AsyncClient() as session:
        tasks = [check_and_collect(session, p, clash_api_url) for p in unique_proxies]
        await asyncio.gather(*tasks)

    print(f"===================节点可用性检测完毕，共 {len(valid_proxies_info)} 个可用节点======================")

    # 过滤掉已排除的代理
    exclude_proxies = read_exclude_proxies()
    final_valid_proxies = [p for p in valid_proxies_info if p['name'] not in exclude_proxies]

    # 保存可用节点
    save_successful_proxies(final_valid_proxies)

    # 速度测试
    if SPEED_TEST and final_valid_proxies:
        print(f"===================开始批量检测节点速度 (限制前 {SPEED_TEST_LIMIT} 个节点)======================")
        speed_test_results = []
        speed_test_tasks = []

        # 只对最终可用的节点进行速度测试，并限制数量
        proxies_to_speed_test = final_valid_proxies[:SPEED_TEST_LIMIT]

        sem_speed = asyncio.Semaphore(SPEED_TEST_LIMIT) # 速度测试也限制并发

        async def check_speed_and_collect(session, proxy_data, test_url, timeout):
            async with sem_speed:
                name, p_type, speed = await check_proxy_speed(session, proxy_data['name'], proxy_data['type'], test_url, timeout)
                if speed != float('inf'):
                    speed_test_results.append({'name': name, 'type': p_type, 'speed': speed})

        async with httpx.AsyncClient() as session:
            for p in proxies_to_speed_test:
                speed_test_tasks.append(check_speed_and_collect(session, p, TEST_URL, SPEED_TEST_LIMIT))
            await asyncio.gather(*speed_test_tasks)

        # 按速度排序
        sorted_speed_results = sorted(speed_test_results, key=lambda x: x['speed'])
        # print("\n速度测试结果 (从快到慢):")
        # for res in sorted_speed_results:
        #     print(f"  节点: {res['name']}, 类型: {res['type']}, 速度: {res['speed']:.2f} 秒")
        global results_speed
        results_speed = sorted_speed_results
        print(f"===================节点速度检测完毕======================")
    else:
        print("跳过速度测试。")

def start_clash():
    # 检测系统类型
    system = platform.system()
    clash_executable = f"./{CLASH_CORE_NAME}"
    if system == "Windows":
        clash_executable = f"{CLASH_CORE_NAME}.exe"
    elif system == "Darwin": # macOS
        clash_executable = f"./{CLASH_CORE_NAME}-darwin"
        # 检查是否是 ARM 架构
        if platform.machine() == "arm64":
            clash_executable = f"./{CLASH_CORE_NAME}-darwin-arm64"
    # elif system == "Linux":
    #     # 检查是否是 ARM 架构
    #     if platform.machine() == "aarch64":
    #         clash_executable = f"./clash-linux-arm64"


    # 检查 Clash 核心是否存在
    if not os.path.exists(clash_executable):
        print(f"未找到 Clash 核心 '{clash_executable}'，正在尝试下载...")
        download_clash_core()
        if not os.path.exists(clash_executable):
            print(f"下载失败，请手动将 Clash 核心放入脚本所在目录并命名为 '{clash_executable}'。")
            sys.exit(1)
    
    # 赋予执行权限 (Linux/macOS)
    if system != "Windows":
        os.chmod(clash_executable, 0o755)

    # 启动 Clash 进程
    # 启动命令需要根据实际的 Clash 核心和配置路径调整
    # 默认使用当前目录的 config.yaml
    cmd = [clash_executable, "-f", CONFIG_FILE]
    if CLASH_API_SECRET:
        cmd.extend(["-secret", CLASH_API_SECRET])
    
    # print(f"执行命令: {' '.join(cmd)}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 等待 Clash 启动并监听端口
    # 这是一个简单的等待机制，可能需要根据实际情况调整
    start_time = time.time()
    while time.time() - start_time < 10: # 等待最多10秒
        try:
            # 尝试连接 Clash API
            requests.get(f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/version", timeout=1)
            print("Clash 核心启动成功。")
            return process
        except requests.exceptions.RequestException:
            time.sleep(0.5)
    
    print("Clash 核心启动失败或API端口未响应。")
    # 如果启动失败，打印错误信息
    stdout, stderr = process.communicate(timeout=1)
    if stdout:
        print("Clash stdout:", stdout)
    if stderr:
        print("Clash stderr:", stderr)
    sys.exit(1)

def download_clash_core():
    system = platform.system()
    machine = platform.machine()
    download_url = None
    asset_name = None

    if system == "Windows":
        if machine == "AMD64":
            asset_name = f"{CLASH_CORE_NAME}-windows-amd64"
        elif machine == "i386":
            asset_name = f"{CLASH_CORE_NAME}-windows-386"
    elif system == "Darwin": # macOS
        if machine == "arm64":
            asset_name = f"{CLASH_CORE_NAME}-darwin-arm64"
        elif machine == "x86_64":
            asset_name = f"{CLASH_CORE_NAME}-darwin-amd64"
    elif system == "Linux":
        if machine == "x86_64":
            asset_name = f"{CLASH_CORE_NAME}-linux-amd64"
        elif machine == "aarch64":
            asset_name = f"{CLASH_CORE_NAME}-linux-arm64"
        elif machine == "armv7l":
            asset_name = f"{CLASH_CORE_NAME}-linux-arm32v7"
        elif machine == "i386":
            asset_name = f"{CLASH_CORE_NAME}-linux-386"

    if not asset_name:
        print(f"不支持的操作系统或架构: {system}/{machine}")
        return

    try:
        response = requests.get(CLASH_DOWNLOAD_URL, timeout=10)
        response.raise_for_status()
        release_info = response.json()
        
        # 寻找对应的下载资产
        for asset in release_info['assets']:
            # Updated asset matching pattern
            if asset['name'].startswith(asset_name) and asset['name'].endswith(".gz"):
                download_url = asset['browser_download_url']
                break

        if not download_url:
            print(f"未找到适合您系统 ({system}-{machine}) 的 Clash 核心下载链接。")
            print("可用资产:")
            for asset in release_info['assets']:
                print(f"- {asset['name']}")
            return

        print(f"正在下载 Clash 核心: {download_url}")
        core_response = requests.get(download_url, stream=True, timeout=30)
        core_response.raise_for_status()

        # 保存为压缩文件
        compressed_file_path = f"{CLASH_CORE_NAME}.gz"
        with open(compressed_file_path, 'wb') as f:
            for chunk in core_response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"下载完成: {compressed_file_path}")

        # 解压文件
        output_filename = CLASH_CORE_NAME
        if system == "Windows":
            output_filename += ".exe"
        
        with gzip.open(compressed_file_path, 'rb') as f_in:
            with open(output_filename, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"解压完成: {output_filename}")
        
        os.remove(compressed_file_path)
        print(f"已删除压缩包: {compressed_file_path}")

    except requests.exceptions.RequestException as e:
        print(f"下载 Clash 核心失败: {e}")
    except Exception as e:
        print(f"处理下载文件时发生错误: {e}")

def parse_vmess_link(link):
    try:
        if not link.startswith("vmess://"):
            return None
        
        encoded_json = link[len("vmess://"):]
        decoded_json = base64.b64decode(encoded_json).decode('utf-8')
        node_data = json.loads(decoded_json)

        name = node_data.get('ps', f"vmess-{random_string(6)}")
        server = node_data.get('add')
        port = node_data.get('port')
        uuid = node_data.get('id')
        alterId = node_data.get('aid', 0)
        cipher = node_data.get('scy', 'auto') # New field 'scy' for security, default to 'auto'
        network = node_data.get('net', 'tcp')
        tls = node_data.get('tls', '')
        sni = node_data.get('sni', node_data.get('host', ''))
        path = node_data.get('path', '/')
        host = node_data.get('host', '')
        # Vmess reality
        # fingerprint = node_data.get('fp', '')
        # pbk = node_data.get('pbk', '')
        # sid = node_data.get('sid', '')
        # spiderx = node_data.get('spx', '/')


        # VLESS XTLS support
        flow = node_data.get('flow', '') # For VLESS XTLS

        # transport specific settings
        ws_opts = {}
        http_opts = {}
        grpc_opts = {}

        if network == 'ws':
            ws_opts = {
                'path': path,
                'headers': {'Host': host}
            }
        elif network == 'http':
            http_opts = {
                'method': 'GET',
                'path': [path],
                'headers': {'Host': [host]}
            }
        elif network == 'grpc':
            grpc_opts = {
                'serviceName': node_data.get('path', ''),
                'authority': host if host else server # grpc authority can be host or server
            }


        proxy_node = {
            'name': name,
            'type': 'vmess',
            'server': server,
            'port': port,
            'uuid': uuid,
            'alterId': alterId,
            'cipher': cipher, # Add cipher field
            'network': network,
        }
        
        if tls == 'tls':
            proxy_node['tls'] = True
            if sni:
                proxy_node['servername'] = sni
            # if fingerprint: # Vmess reality
            #     proxy_node['reality-fingerprint'] = fingerprint
            # if pbk:
            #     proxy_node['reality-public-key'] = pbk
            # if sid:
            #     proxy_node['reality-short-id'] = sid
            # if spiderx and spiderx != '/':
            #     proxy_node['reality-spiderX'] = spiderx

        if network == 'ws':
            proxy_node['ws-opts'] = ws_opts
        elif network == 'http':
            proxy_node['http-opts'] = http_opts
        elif network == 'grpc':
            proxy_node['grpc-opts'] = grpc_opts
        
        if flow: # For VLESS XTLS
            proxy_node['flow'] = flow

        return proxy_node
    except Exception as e:
        # print(f"解析 VMESS 链接失败: {link} - {e}")
        return None

def parse_ss_link(link):
    try:
        if not link.startswith("ss://"):
            return None

        # 分离加密方式、密码和服务器信息
        # ss://method:password@server:port#tag
        
        # 提取 #tag 之前的部分
        parts = link[len("ss://"):].split('#', 1)
        core_part = parts[0]
        tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else f"shadowsocks-{random_string(6)}"

        # 检查是否有 @ 符号
        if '@' not in core_part: # Base64 encoded ss link
            decoded_core_part = base64.b64decode(core_part).decode('utf-8')
            method_password, server_port = decoded_core_part.rsplit('@', 1)
        else:
            method_password, server_port = core_part.rsplit('@', 1)

        method, password = method_password.split(':', 1)
        server, port = server_port.split(':', 1)

        proxy_node = {
            'name': tag,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
        return proxy_node
    except Exception as e:
        # print(f"解析 Shadowsocks 链接失败: {link} - {e}")
        return None

def parse_trojan_link(link):
    try:
        if not link.startswith("trojan://"):
            return None
        
        # trojan://password@server:port?params#tag
        parts = link[len("trojan://"):].split('#', 1)
        core_part = parts[0]
        tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else f"trojan-{random_string(6)}"

        password_server_port, params_str = (core_part.split('?', 1) + [''])[:2]
        password, server_port = password_server_port.split('@', 1)
        server, port = server_port.split(':', 1)

        proxy_node = {
            'name': tag,
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'tls': True # Trojan 强制开启 TLS
        }

        params = urllib.parse.parse_qs(params_str)
        
        # SNI
        if 'sni' in params and params['sni'][0]:
            proxy_node['servername'] = params['sni'][0]
        elif 'peername' in params and params['peername'][0]: #兼容旧版参数
            proxy_node['servername'] = params['peername'][0]
        
        # AllowInsecure
        if 'allowInsecure' in params and params['allowInsecure'][0].lower() == '1':
            proxy_node['skip-cert-verify'] = True
        
        # alpn
        if 'alpn' in params and params['alpn'][0]:
            proxy_node['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]

        # MUX
        if 'mux' in params and params['mux'][0].lower() == '1':
            proxy_node['network'] = 'tcp'
            proxy_node['tcp-opts'] = {'dscp': 0, 'fast-open': False, 'no-delay': False} # 默认值

        # WebSocket
        if 'type' in params and params['type'][0] == 'ws':
            proxy_node['network'] = 'ws'
            ws_opts = {}
            if 'path' in params and params['path'][0]:
                ws_opts['path'] = params['path'][0]
            if 'host' in params and params['host'][0]:
                ws_opts['headers'] = {'Host': params['host'][0]}
            proxy_node['ws-opts'] = ws_opts
        
        # gRPC
        if 'type' in params and params['type'][0] == 'grpc':
            proxy_node['network'] = 'grpc'
            grpc_opts = {}
            if 'serviceName' in params and params['serviceName'][0]:
                grpc_opts['serviceName'] = params['serviceName'][0]
            if 'host' in params and params['host'][0]: # grpc authority
                grpc_opts['authority'] = params['host'][0]
            proxy_node['grpc-opts'] = grpc_opts


        return proxy_node
    except Exception as e:
        # print(f"解析 Trojan 链接失败: {link} - {e}")
        return None

def parse_vless_link(link):
    try:
        if not link.startswith("vless://"):
            return None

        # vless://uuid@server:port?params#tag
        parts = link[len("vless://"):].split('#', 1)
        core_part = parts[0]
        tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else f"vless-{random_string(6)}"

        uuid_server_port, params_str = (core_part.split('?', 1) + [''])[:2]
        uuid, server_port = uuid_server_port.split('@', 1)
        server, port = server_port.split(':', 1)

        proxy_node = {
            'name': tag,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'tls': False # 默认为 False，根据参数判断
        }

        params = urllib.parse.parse_qs(params_str)

        # TLS settings
        if 'security' in params and params['security'][0] == 'tls':
            proxy_node['tls'] = True
            if 'sni' in params and params['sni'][0]:
                proxy_node['servername'] = params['sni'][0]
            elif 'host' in params and params['host'][0]: # 兼容 host 参数作为 sni
                proxy_node['servername'] = params['host'][0]
            if 'flow' in params and params['flow'][0]:
                proxy_node['flow'] = params['flow'][0]
            if 'fp' in params and params['fp'][0]: # reality fingerprint
                proxy_node['client-fingerprint'] = params['fp'][0]
            if 'pbk' in params and params['pbk'][0]: # reality public key
                proxy_node['reality-public-key'] = params['pbk'][0]
            if 'sid' in params and params['sid'][0]: # reality short ID
                proxy_node['reality-short-id'] = params['sid'][0]
            if 'spx' in params and params['spx'][0]: # reality spiderX
                proxy_node['reality-spiderX'] = params['spx'][0]
            
            if 'alpn' in params and params['alpn'][0]:
                proxy_node['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]
        
        # 如果 security 是 none 但有 flow，也添加 flow
        if 'security' in params and params['security'][0] == 'none' and 'flow' in params and params['flow'][0]:
            proxy_node['flow'] = params['flow'][0]

        # Network and transport settings
        network = params.get('type', ['tcp'])[0]
        proxy_node['network'] = network

        if network == 'ws':
            ws_opts = {}
            if 'path' in params and params['path'][0]:
                ws_opts['path'] = params['path'][0]
            if 'host' in params and params['host'][0]:
                ws_opts['headers'] = {'Host': params['host'][0]}
            proxy_node['ws-opts'] = ws_opts
        elif network == 'grpc':
            grpc_opts = {}
            if 'serviceName' in params and params['serviceName'][0]:
                grpc_opts['serviceName'] = params['serviceName'][0]
            if 'authority' in params and params['authority'][0]:
                grpc_opts['authority'] = params['authority'][0]
            elif 'host' in params and params['host'][0]: #兼容 host 作为 authority
                grpc_opts['authority'] = params['host'][0]
            proxy_node['grpc-opts'] = grpc_opts
        
        return proxy_node
    except Exception as e:
        # print(f"解析 VLESS 链接失败: {link} - {e}")
        return None

def parse_url(url):
    if url.startswith("ss://"):
        return parse_ss_link(url)
    elif url.startswith("vmess://"):
        return parse_vmess_link(url)
    elif url.startswith("trojan://"):
        return parse_trojan_link(url)
    elif url.startswith("vless://"):
        return parse_vless_link(url)
    # 添加其他协议的解析函数
    return None

def merge_lists(list1, list2):
    """
    合并两个列表，去除重复项，并随机打乱顺序。
    """
    combined = list1 + list2
    unique = list(set(combined)) # 使用 set 去除重复项
    random.shuffle(unique) # 随机打乱顺序
    return unique

def random_string(length=8):
    """生成指定长度的随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_clash_config(subscribe_links: List[str], load_nodes: List[Dict]):
    proxies = []
    # 从订阅链接生成代理节点
    for link in subscribe_links:
        if not check_valid_url(link):
            continue
        try:
            # 尝试作为 Clash 订阅链接处理
            headers = {'User-Agent': 'ClashforWindows/0.19.8'}
            # print(f"尝试下载订阅: {link}")
            with requests.get(link, headers=headers, timeout=10, stream=True) as response:
                response.raise_for_status()
                # 检查是否是 gzip 压缩
                if 'content-encoding' in response.headers and response.headers['content-encoding'] == 'gzip':
                    decoded_content = gzip.decompress(response.content).decode('utf-8')
                else:
                    decoded_content = response.text
                
                # 尝试解析为 YAML (Clash 配置)
                try:
                    config = yaml.safe_load(decoded_content)
                    if isinstance(config, dict) and 'proxies' in config:
                        # print(f"从 Clash 订阅链接加载到 {len(config['proxies'])} 个节点。")
                        for proxy in config['proxies']:
                            if 'name' in proxy and 'type' in proxy:
                                proxies.append(proxy)
                        continue # 已经处理，跳过后续的 base64 和单链接解析
                except yaml.YAMLError:
                    pass # 不是 YAML，继续尝试其他解析方式

                # 尝试 Base64 解码
                try:
                    decoded_content = base64.b64decode(decoded_content).decode('utf-8')
                    # Base64 解码后内容可能是多行 URL
                    urls = decoded_content.splitlines()
                    for url in urls:
                        node = parse_url(url.strip())
                        if node:
                            proxies.append(node)
                    if urls: # 如果成功解析出链接，说明是 Base64 订阅，跳过单链接解析
                        # print(f"从 Base64 订阅链接加载到 {len(urls)} 个节点。")
                        continue
                except (base64.binascii.Error, UnicodeDecodeError):
                    pass # 不是 Base64，继续尝试单链接解析
                
                # 最后尝试作为单链接解析
                node = parse_url(link)
                if node:
                    proxies.append(node)
                    # print(f"从单链接加载到 1 个节点。")

        except requests.exceptions.RequestException as e:
            print(f"处理订阅链接 {link} 失败: {e}")
        except Exception as e:
            print(f"处理订阅链接 {link} 时发生未知错误: {e}")

    # 合并预加载的节点
    proxies.extend(load_nodes)
    # 过滤掉已排除的代理
    exclude_proxies = read_exclude_proxies()
    proxies = [p for p in proxies if p['name'] not in exclude_proxies]

    # 去重
    unique_proxies = {}
    for proxy in proxies:
        if 'name' in proxy:
            unique_proxies[proxy['name']] = proxy
    proxies = list(unique_proxies.values())
    
    # 限制节点数量
    if LIMIT and len(proxies) > LIMIT:
        # print(f"节点数量超过限制 {LIMIT}，将随机抽取 {LIMIT} 个节点。")
        proxies = random.sample(proxies, LIMIT)

    if not proxies:
        print("没有可用的代理节点，无法生成配置。")
        return

    # print(f"成功加载 {len(proxies)} 个代理节点。")

    # 创建代理组
    proxy_names = [p['name'] for p in proxies]
    proxy_groups = []

    # 包含DIRECT和REJECT的GLOBAL组
    global_group_proxies = ['DIRECT', 'REJECT'] + proxy_names
    proxy_groups.append({
        'name': 'GLOBAL',
        'type': 'select',
        'proxies': global_group_proxies
    })
    
    # 负载均衡组 (url-test)
    if proxy_names:
        proxy_groups.append({
            'name': '自动选择',
            'type': 'url-test',
            'proxies': proxy_names,
            'url': TEST_URL,
            'interval': 300 # 5分钟测试一次
        })
        proxy_groups.append({
            'name': '故障转移',
            'type': 'fallback',
            'proxies': proxy_names,
            'url': TEST_URL,
            'interval': 300 # 5分钟测试一次
        })

    # DNS 配置
    dns_config = {
        'enable': True,
        'ipv6': True,
        'listen': '0.0.0.0:53',
        'enhanced-mode': True,
        'fake-ip-range': '198.18.0.1/16',
        'fake-ip-filter': [
            '+.media.microsoft.com',
            '+.msftconnecttest.com',
            '+.msftncsi.com',
            'xbox.*.microsoft.com',
            '*.xboxlive.com',
            '*.log.spotify.com',
            '*.prod.doppler.io',
            '*.woken.app',
            '*.xn--ngstr-lra.com',
            '*.cloudflare.com',
            '*.segment.io',
            '*.segment.com',
            'events.gfe.nvidia.com',
            'api.content.clash.com',
            'config.getdoh.com',
            'dns.nextdns.io',
            'dns.google',
            'stun.*.*',
            'stun.*.*.*',
            '+.nflxvideo.net',
            '*.openai.com',
            '*.stripe.com',
            'no-api-metrics.sentry.io'
        ],
        'default-nameserver': [
            '114.114.114.114',
            '223.5.5.5',
            '1.1.1.1',
            '8.8.4.4',
            '8.8.8.8'
        ],
        'nameserver': [
            'https://dns.alidns.com/dns-query',
            'https://doh.pub/dns-query',
            'tls://dns.alidns.com:853',
            'tls://dns.pub:853'
        ],
        'fallback': [
            'https://1.1.1.1/dns-query',
            'https://dns.google/dns-query',
            'tls://1.0.0.1:853',
            'tls://8.8.8.8:853'
        ],
        'fallback-filter': {
            'geoip': True,
            'geoip-code': 'CN',
            'ipcidr': [
                '240.0.0.0/4',
                '0.0.0.0/32'
            ],
            'domain': [
                '+.google.com',
                '+.gstatic.com',
                '+.googleapis.com',
                '+.gvt1.com',
                '+.youtube.com',
                '+.ytimg.com',
                '+.googleusercontent.com',
                '+.xn--ngstr-lra.com'
            ]
        }
    }

    # 规则 (示例，可根据需求修改)
    rules = [
        "PROCESS-NAME,clash,DIRECT",
        "DOMAIN-SUFFIX,clash.com,DIRECT", # Example of keeping local domains direct
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,douyin.com,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,sogou.com,DIRECT",
        "DOMAIN-SUFFIX,sohu.com,DIRECT",
        "DOMAIN-SUFFIX,youku.com,DIRECT",
        "DOMAIN-SUFFIX,iqiyi.com,DIRECT",
        "DOMAIN-SUFFIX,tencent.com,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT", # Direct for China domains
        "GEOSITE,CN,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,GLOBAL" # 所有未匹配的流量走 GLOBAL 组
    ]

    # 构建完整的 Clash 配置
    clash_config = {
        'port': CLASH_API_PORTS[0],
        # 'socks-port': 7891, # socks5 端口
        'allow-lan': True,
        'mode': 'rule', # rule, direct, global
        'log-level': 'info', # debug, info, warning, error
        'external-controller': f'{CLASH_API_HOST}:{CLASH_API_PORTS[0]}',
        'secret': CLASH_API_SECRET,
        'proxies': proxies,
        'proxy-groups': proxy_groups,
        'rules': rules,
        'dns': dns_config,
        'tun': { # Enable TUN mode
            'enable': True,
            'stack': 'system',
            'dns-hijack': ['any:53'],
        },
        'unified-delay': True,
        'tcp-concurrent': True,
        'find-process-mode': 'strict'
    }

    # 创建 output 文件夹
    # os.makedirs(OUTPUT, exist_ok=True)
    config_path = os.path.join(CONFIG_FILE)

    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)
    # print(f"Clash 配置文件已生成: {config_path}")

def read_txt_files(folder_path):
    links = []
    # 确保文件夹存在
    if not os.path.exists(folder_path):
        return links
    
    for filename in glob.glob(os.path.join(folder_path, '*.txt')):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        links.append(stripped_line)
        except Exception as e:
            print(f"读取文件 {filename} 失败: {e}")
    return links

def read_yaml_files(folder_path):
    nodes = []
    # 确保文件夹存在
    if not os.path.exists(folder_path):
        return nodes

    for filename in glob.glob(os.path.join(folder_path, '*.yaml')):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if isinstance(config, dict) and 'proxies' in config:
                    nodes.extend(config['proxies'])
        except Exception as e:
            print(f"读取或解析 YAML 文件 {filename} 失败: {e}")
    return nodes

def filter_by_types_alt(allowed_types: List[str], nodes: List[Dict]) -> List[Dict]:
    """
    根据允许的代理类型过滤节点。
    """
    if not allowed_types:
        return nodes
    
    filtered_nodes = [node for node in nodes if node.get('type') in allowed_types]
    return filtered_nodes

def read_last_check_file():
    if not os.path.exists(LAST_CHECK_FILE):
        return []
    try:
        with open(LAST_CHECK_FILE, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"读取上次检测文件失败: {e}")
        return []

def write_last_check_file(successful_links):
    try:
        with open(LAST_CHECK_FILE, 'w', encoding='utf-8') as f:
            for link in successful_links:
                f.write(f"{link}\n")
    except Exception as e:
        print(f"写入上次检测文件失败: {e}")

def read_successful_proxies():
    if not os.path.exists(LAST_SUC_FILE):
        return []
    try:
        with open(LAST_SUC_FILE, 'r', encoding='utf-8') as f:
            proxies = []
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    try:
                        proxies.append(json.loads(stripped_line))
                    except json.JSONDecodeError:
                        # print(f"Warning: 无法解析为JSON的行: {stripped_line}")
                        pass
            return proxies
    except Exception as e:
        print(f"读取成功代理文件失败: {e}")
        return []

def save_successful_proxies(proxies_info):
    try:
        with open(LAST_SUC_FILE, 'w', encoding='utf-8') as f:
            for p in proxies_info:
                f.write(json.dumps(p, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"保存成功代理文件失败: {e}")

def read_exclude_proxies():
    if not os.path.exists(EXCLUDE_FILE):
        return []
    try:
        with open(EXCLUDE_FILE, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"读取排除代理文件失败: {e}")
        return []

def record_sub_links(links: List[str]):
    try:
        with open(SUB_FILE, 'a', encoding='utf-8') as f:
            for link in links:
                f.write(f"{link}\n")
    except Exception as e:
        print(f"记录订阅链接失败: {str(e)}")

    return result

def work(links,check=False,allowed_types=[],only_check=False):
    try:
        if not only_check:
            load_nodes = read_yaml_files(folder_path=INPUT)
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types,nodes=load_nodes)
            links = merge_lists(read_txt_files(folder_path=INPUT), links)
            if links or load_nodes:
                generate_clash_config(links,load_nodes)

        if check or only_check:
            clash_process = None
            try:
                # 启动clash
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
                # 切换节点到'节点选择-DIRECT'
                switch_proxy('DIRECT')
                asyncio.run(proxy_clean())
                print(f'批量检测完毕')
            except Exception as e:
                print("Error calling Clash API:", e)
            finally:
                print(f'关闭Clash API')
                if clash_process is not None:
                    clash_process.kill()

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        # Corrected line: terminated f-string literal
        print(f"程序执行出错: {e}")
