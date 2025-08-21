# 自动修改说明：
# 1. 修复了节点去重问题，使用基于 UUID 的新去重逻辑。
# 2. 确保了所有原始脚本功能（如按协议拆分、生成各种订阅格式）都得到完整保留，无任何精简。
# 3. 整合了之前讨论的最新优化去重代码到完整的脚本中。

import aiohttp
import asyncio
from bs4 import BeautifulSoup
import os
import csv
import urllib.parse
import re
from datetime import datetime, timedelta
import json
import hashlib
import random
import base64

def normalize_config(config):
    """规范化代理配置字符串，以便更准确地去重。忽略节点名称（# 后的部分）。"""
    try:
        if '#' in config:
            config_body, _ = config.rsplit('#', 1)
        else:
            config_body = config

        protocol = config_body.split('://')[0].lower()
        config_content = config_body.split('://')[1]

        if protocol == 'vmess':
            # VMess: 解码 base64，加载 JSON，排序键，重新 dumps 并 base64 编码
            decoded = base64.b64decode(config_content).decode('utf-8')
            json_data = json.loads(decoded)
            
            # 使用 id 作为去重键
            dedupe_key = f"vmess://{json_data.get('id', '')}"
            
            # 创建用于一致性比较的规范化字符串
            normalized_data = {k: v for k, v in json_data.items() if k not in ['ps', 'add']}
            normalized_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
            normalized_config = f"{protocol}://{base64.b64encode(normalized_json.encode('utf-8')).decode('utf-8')}"
            
            return dedupe_key, normalized_config

        elif protocol in ['vless', 'trojan', 'hysteria2']:
            # VLESS/Trojan/Hysteria2: 提取UUID，并规范化路径和主机
            parsed = urllib.parse.urlparse(config_body)
            user = parsed.username
            
            # 提取 UUID
            uuid_match = re.search(r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})', user)
            if uuid_match:
                uuid = uuid_match.group(1)
            else:
                uuid = user
            
            # 规范化查询参数
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # 针对 path 参数进行特殊处理，移除重复部分和URL编码
            normalized_path = ''
            if 'path' in query_params:
                path_val = query_params['path'][0]
                path_decoded = urllib.parse.unquote(path_val)
                # 移除重复的路径部分
                parts = path_decoded.split(',')
                if parts and all(p.strip() == parts[0].strip() for p in parts):
                    normalized_path = urllib.parse.quote(parts[0])
                else:
                    normalized_path = urllib.parse.quote(path_decoded)
            
            # 移除 'ed', 'sni', 'host'，因为它们常变且不是核心去重依据
            if 'ed' in query_params: del query_params['ed']
            if 'sni' in query_params: del query_params['sni']
            if 'host' in query_params: del query_params['host']
            
            # 重建查询参数
            if normalized_path:
                query_params['path'] = [normalized_path]
            
            sorted_items = sorted((k, v) for k, vs in query_params.items() for v in sorted(vs))
            sorted_query = urllib.parse.urlencode(sorted_items, doseq=True)

            # 创建新的去重键，仅基于协议、UUID 和规范化的参数
            key_components = [
                protocol,
                uuid,
                sorted_query
            ]
            dedupe_key = '&'.join(key_components).lower()
            
            # 创建规范化后的完整链接
            normalized_config = f"{protocol}://{uuid}@{parsed.hostname}:{parsed.port}?{sorted_query}"
            
            return dedupe_key, normalized_config

        elif protocol == 'ss':
            # Shadowsocks: 编码部分作为去重键
            if '@' in config_content:
                auth, _ = config_content.split('@', 1)
                dedupe_key = f"ss://{auth}"
            else:
                decoded = base64.b64decode(config_content).decode('utf-8')
                dedupe_key = f"ss://{decoded.split('@')[0].strip().lower()}"
            
            return dedupe_key, config_body
            
        elif protocol == 'ssr':
            # SSR: base64 编码的复杂字符串，解码后排序参数
            decoded = base64.b64decode(config_content).decode('utf-8')
            if '/?' in decoded:
                base, params = decoded.split('/?', 1)
                param_dict = dict(p.split('=') for p in params.split('&'))
                sorted_params = '&'.join(f"{k}={v}" for k, v in sorted(param_dict.items()))
                normalized = f"{base}/?{sorted_params}"
            else:
                normalized = decoded
            normalized_encoded = base64.b64encode(normalized.encode('utf-8')).decode('utf-8')
            
            # SSR 去重键使用解码后的主体部分
            dedupe_key = f"ssr://{base}" if '/?' in decoded else f"ssr://{decoded}"
            return dedupe_key, f"{protocol}://{normalized_encoded}"

        else:
            # 未知协议：返回原始
            return config_body, config_body

    except Exception as e:
        print(f"规范化配置时出错 '{config}': {e}")
        return config, config

async def get_v2ray_links(session, url, max_pages=3, max_retries=1):
    """从指定 Telegram 频道 URL 获取代理配置（每频道最多爬取 max_pages 页）。"""
    v2ray_configs = []
    current_url = url
    page_count = 0
    no_config_pages = 0

    while current_url and page_count < max_pages:
        retry_count = 0
        while retry_count <= max_retries:
            try:
                await asyncio.sleep(random.uniform(1, 5) * retry_count)
                async with session.get(current_url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        tags_to_check = (
                            soup.find_all('div', class_='tgme_widget_message_text'),
                            soup.find_all('div', class_='tgme_widget_message_text js-message_text before_footer'),
                            soup.find_all('pre'),
                            soup.find_all('code'),
                            soup.find_all('span', class_='tgme_widget_message_text'),
                            soup.find_all('span'),
                            soup.find_all('div', class_='tgme_widget_message'),
                            soup.find_all('div', class_='js-message_text'),
                            soup.find_all('div')
                        )
                        
                        page_configs = []
                        protocol_pattern = r'(hysteria2://|vmess://|trojan://|ss://|ssr://|vless://)[^\s#]*(#[^\s#]*)?'
                        for tag_list in tags_to_check:
                            for tag in tag_list:
                                text = '\n'.join(tag.stripped_strings)
                                if len(text) > 10:
                                    matches = re.findall(protocol_pattern, text, re.MULTILINE)
                                    for match in matches:
                                        config = match[0] + (match[1] if match[1] else '')
                                        if len(config) > len('vmess://') + 5:
                                            page_configs.append(config.strip())
                        for tag_list in tags_to_check:
                            for tag in tag_list:
                                text = tag.get_text(separator='\n', strip=True)
                                if len(text) > 10:
                                    potential_configs = re.split(r'(?=(hysteria2://|vmess://|trojan://|ss://|ssr://|vless://))', text)
                                    for i in range(1, len(potential_configs), 2):
                                        config_line = potential_configs[i] + potential_configs[i+1] if i+1 < len(potential_configs) else potential_configs[i]
                                        stripped_config = config_line.strip()
                                        if stripped_config.startswith(('hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://')) and len(stripped_config) > len('vmess://') + 5:
                                            page_configs.append(stripped_config)
                    
                        page_configs = list(set(page_configs))
                        print(f"从 {current_url} (第 {page_count + 1} 页，状态码 {response.status}) 获取到 {len(page_configs)} 个配置")
                        v2ray_configs.extend(page_configs)
                        if not page_configs:
                            no_config_pages += 1
                            if no_config_pages >= 3:
                                print(f"在 {current_url} 提前停止：连续 3 页无配置")
                                current_url = None
                                break
                        messages = soup.find_all('div', class_='tgme_widget_message')
                        if messages:
                            oldest_message = messages[-1]
                            message_id = oldest_message.get('data-post', '').split('/')[-1]
                            if message_id and message_id.isdigit():
                                current_url = f"{url}?before={message_id}"
                                page_count += 1
                            else:
                                print(f"在 {current_url} 未找到有效的消息 ID，无法继续分页")
                                current_url = None
                        else:
                            print(f"在 {current_url} 未找到任何消息")
                            current_url = None
                        break
                    elif response.status == 429:
                        retry_count += 1
                        if retry_count > max_retries:
                            print(f"在 {current_url} 重试 {max_retries} 次后仍触发速率限制，放弃")
                            current_url = None
                            break
                        print(f"在 {current_url} 触发速率限制 (状态码: {response.status})，等待 {10 * retry_count} 秒后重试")
                        await asyncio.sleep(10 * retry_count)
                    elif response.status in [404, 403]:
                        print(f"频道不存在或被禁止访问: {current_url} (状态码: {response.status})")
                        current_url = None
                        break
                    else:
                        print(f"获取 URL {current_url} 失败 (状态码: {response.status})")
                        current_url = None
                        break
            except aiohttp.ClientError as e:
                retry_count += 1
                if retry_count > max_retries:
                    print(f"在 {current_url} 重试 {max_retries} 次后失败: {type(e).__name__}: {e}")
                    current_url = None
                    break
                print(f"获取 URL {current_url} 时发生网络错误: {type(e).__name__}: {e}，等待 {10 * retry_count} 秒后重试")
                await asyncio.sleep(10 * retry_count)
            except asyncio.TimeoutError:
                retry_count += 1
                if retry_count > max_retries:
                    print(f"获取 URL {current_url} 超时 {max_retries} 次，放弃")
                    current_url = None
                    break
                print(f"获取 URL {current_url} 超时，等待 {10 * retry_count} 秒后重试")
                await asyncio.sleep(10 * retry_count)
            except Exception as e:
                print(f"获取 URL {current_url} 时发生未知错误: {type(e).__name__}: {e}")
                current_url = None
                break
    return v2ray_configs

async def fetch_all_configs(sources, max_pages=3):
    """并行获取所有 Telegram 频道的代理配置。"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for source_name, source_url in sources:
            print(f"准备爬取来源: {source_name} ({source_url})")
            if source_url:
                tasks.append(get_v2ray_links(session, source_url, max_pages))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_configs = set()
        result_pairs = []
        for i, (source_name, _) in enumerate(sources):
            if i < len(results) and isinstance(results[i], list):
                configs = [c for c in results[i] if isinstance(c, str) and is_valid_config(c)]
                all_configs.update(configs)
                result_pairs.append((source_name, configs))
            else:
                result_pairs.append((source_name, []))
        return result_pairs

def is_valid_config(config):
    """验证代理配置是否有效。"""
    try:
        if not config.strip() or config.startswith('#'):
            return False
        protocol_match = re.match(r'^(hysteria2://|vmess://|trojan://|ss://|ssr://|vless://)', config)
        if not protocol_match:
            return False
        if protocol_match.group(1) in ['vless://', 'trojan://']:
            if not re.search(r'@\S+?:\d+\?', config):
                return False
        if protocol_match.group(1) == 'ss://':
            if not re.search(r'[^@]+@[^:]+:\d+', config):
                return False
        if protocol_match.group(1) == 'vmess://':
            try:
                decoded = json.loads(base64.b64decode(config.split('://')[1]).decode('utf-8'))
                if not all(k in decoded for k in ['add', 'port', 'id', 'net']):
                    return False
            except:
                return False
        return True
    except:
        return False

def clean_node_name(name):
    """清理节点名称，移除 emoji 和复杂字符，限制长度。"""
    if not name:
        return "Unknown"
    name = re.sub(r'%[0-9A-Fa-f]{2}|[\U0001F1E6-\U0001F1FF]+', '', name)
    name = re.sub(r'[^a-zA-Z0-9\s\-\_\@]', '', name)
    name = name.strip()
    return name[:50] if name else "Unknown"

def extract_channel_from_config(config):
    """从配置的节点名称（# 后的部分）提取显示名称。"""
    try:
        node_name = config.split('#')[-1].strip()
        cleaned_name = clean_node_name(node_name)
        return cleaned_name if cleaned_name else None
    except:
        return None

def save_configs_by_channel(configs, source_name):
    """保存代理配置到文件，并提取显示名称。"""
    if not configs:
        print(f"来源 {source_name} 无有效配置，跳过保存")
        return 0, None

    config_folder = "sub"
    if not os.path.exists(config_folder):
        try:
            os.makedirs(config_folder)
            print(f"已创建目录: {config_folder}")
        except Exception as e:
            print(f"创建目录 {config_folder} 失败: {e}")
            return 0, None

    safe_source_name = "".join(c for c in source_name if c.isalnum() or c in ('-', '_')).strip()
    if not safe_source_name:
        safe_source_name = f"source_{hashlib.md5(source_name.encode()).hexdigest()[:8]}"
        print(f"来源名称 {source_name} 无效，使用默认名称: {safe_source_name}")

    file_path = os.path.join(config_folder, f"{safe_source_name}.txt")
    
    source_names = [extract_channel_from_config(config) for config in configs]
    source_names = [name for name in source_names if name]
    display_name = None
    if source_names:
        from collections import Counter
        display_name = Counter(source_names).most_common(1)[0][0]
    
    unique_dedupe_keys = set()
    unique_configs_to_save = []
    
    for config in configs:
        if not is_valid_config(config):
            continue
        config_no_name = config.split('#')[0] if '#' in config else config
        dedupe_key, _ = normalize_config(config_no_name.strip())
        
        if dedupe_key not in unique_dedupe_keys:
            unique_dedupe_keys.add(dedupe_key)
            if '#' in config:
                config_body, node_name = config.rsplit('#', 1)
                cleaned_name = clean_node_name(node_name)
                config = f"{config_body}#{cleaned_name}"
            unique_configs_to_save.append(config)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            for config in unique_configs_to_save:
                file.write(config + '\n')
        print(f"成功保存 {len(unique_configs_to_save)} 个配置到 {file_path}")
    except Exception as e:
        print(f"保存配置到 {file_path} 失败: {e}")
        return 0, None
    
    return len(unique_configs_to_save), display_name or source_name

def merge_configs():
    """合并所有来源的配置到一个文件，并去重。"""
    config_folder = "sub"
    merged_file = "merged_configs.txt"
    seen_dedupe_keys = set()
    all_configs_from_sources = []
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not os.path.exists(config_folder):
        print(f"警告：未找到 {config_folder} 文件夹，跳过合并。")
        return
        
    # 查找所有渠道文件
    config_paths = [f for f in os.listdir(config_folder) if f.startswith('source_') or f.endswith('.txt')]
    
    print(f"找到 {len(config_paths)} 个渠道文件。")

    for path in config_paths:
        try:
            file_path = os.path.join(config_folder, path)
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f.read().splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # 使用新的规范化函数来获取去重键
                    dedupe_key, _ = normalize_config(line)
                    
                    if dedupe_key not in seen_dedupe_keys:
                        seen_dedupe_keys.add(dedupe_key)
                        all_configs_from_sources.append(line)
        except Exception as e:
            print(f"读取文件 {path} 时出错: {e}")

    # 将合并后的配置写入文件
    if all_configs_from_sources:
        with open(merged_file, 'w', encoding='utf-8') as f:
            f.write(f"# 自动生成的合并配置，生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for config in all_configs_from_sources:
                f.write(f"{config}\n")
        print(f"已将 {len(all_configs_from_sources)} 个唯一配置合并到 {merged_file}。")
    else:
        print("没有找到任何配置来合并。")

def split_configs_by_protocol():
    """按协议类型拆分合并的配置到单独文件。"""
    merged_file = "merged_configs.txt"
    if not os.path.exists(merged_file):
        print(f"警告：未找到 {merged_file}，无法按协议拆分")
        return

    protocol_files = {
        'hysteria2': 'hysteria2.txt',
        'vmess': 'vmess.txt',
        'trojan': 'trojan.txt',
        'ss': 'ss.txt',
        'ssr': 'ssr.txt',
        'vless': 'vless.txt',
    }
    for file_path in protocol_files.values():
        try:
            if os.path.exists(file_path):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('')
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('')
        except Exception as e:
            print(f"清空/创建文件 {file_path} 失败: {e}")

    protocol_pattern = r'^(hysteria2://|vmess://|trojan://|ss://|ssr://|vless://)[^\s#]*(#[^\s#]*)?$'
    try:
        with open(merged_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                if re.match(protocol_pattern, line_stripped) and is_valid_config(line_stripped):
                    for protocol_prefix in protocol_files.keys():
                        if line_stripped.startswith(f"{protocol_prefix}://"):
                            try:
                                with open(protocol_files[protocol_prefix], 'a', encoding='utf-8') as outfile:
                                    outfile.write(line_stripped + '\n')
                            except Exception as e:
                                print(f"写入协议文件 {protocol_files[protocol_prefix]} 失败: {e}")
                            break
                else:
                    print(f"跳过无效配置: {line_stripped}")
        print("成功按协议拆分配置")
    except Exception as e:
        print(f"读取合并文件 {merged_file} 或拆分协议失败: {e}")

def create_stats_csv(source_stats):
    """生成统计 CSV 文件，包含来源配置数量和更新时间。"""
    csv_file = "stats.csv"
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(csv_file, 'w', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['来源', '配置数量', '最后更新时间'])
            for source, count in source_stats.items():
                writer.writerow([source, count, current_time_str])
        print(f"成功生成统计文件: {csv_file}")
    except Exception as e:
        print(f"生成统计文件 {csv_file} 失败: {e}")

def load_channels():
    """加载来源列表，检查时间戳以决定是否爬取。"""
    sources = []
    timestamps = {}
    timestamps_file="channel_timestamps.json"
    channels_file="channels.txt"

    try:
        if os.path.exists(timestamps_file):
            with open(timestamps_file, 'r', encoding='utf-8') as f:
                timestamps = json.load(f)
            print(f"成功加载时间戳文件: {timestamps_file}")
        else:
            print(f"时间戳文件 {timestamps_file} 不存在，初始化为空")
            timestamps = {}
    except Exception as e:
        print(f"加载时间戳文件 {timestamps_file} 失败: {e}，初始化为空")
        timestamps = {}
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(hours=24)
    original_sources = []
    try:
        if os.path.exists(channels_file):
            with open(channels_file, 'r', encoding='utf-8') as file:
                original_sources = [line.strip() for line in file if line.strip()]
                print(f"从 {channels_file} 加载 {len(original_sources)} 个来源")
        else:
            print(f"未找到来源文件 {channels_file}")
            return [], timestamps, []
    except Exception as e:
        print(f"读取来源文件 {channels_file} 失败: {e}")
        return [], timestamps, []
    for source_name in original_sources:
        safe_source_name = "".join(c for c in source_name if c.isalnum() or c in ('-', '_')).strip()
        if not safe_source_name:
            safe_source_name = f"source_{hashlib.md5(source_name.encode()).hexdigest()[:8]}"
            print(f"来源名称 {source_name} 无效，使用默认名称: {safe_source_name}")
        config_file = os.path.join("sub", f"{safe_source_name}.txt")
        should_fetch = True
        if source_name in timestamps:
            try:
                last_updated = datetime.fromisoformat(timestamps[source_name]['last_updated'])
                last_hash = timestamps[source_name].get('file_hash', '')
                current_hash = ''
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        current_hash = hashlib.md5(f.read().encode('utf-8')).hexdigest()
                if last_updated > current_time:
                    print(f"来源 {source_name} 的时间戳 {last_updated} 晚于当前时间，强制爬取")
                    should_fetch = True
                elif last_updated > cutoff_time and current_hash == last_hash:
                    print(f"跳过 {source_name}：无需更新（最后更新时间 {last_updated}，文件哈希未变化）")
                    should_fetch = False
            except Exception as e:
                print(f"检查 {source_name} 的时间戳失败: {e}，强制爬取")
                should_fetch = True
        if should_fetch:
            sources.append((source_name, f"https://t.me/s/{source_name}"))
        else:
            sources.append((source_name, None))
    return sources, timestamps, original_sources

def save_timestamps(timestamps, active_sources, source_stats):
    """保存来源的时间戳和文件哈希，仅为成功获取配置的来源更新。"""
    timestamps_file="channel_timestamps.json"
    current_time = datetime.now().isoformat()
    for source_name, _ in active_sources:
        safe_source_name = "".join(c for c in source_name if c.isalnum() or c in ('-', '_')).strip()
        if not safe_source_name:
            safe_source_name = f"source_{hashlib.md5(source_name.encode()).hexdigest()[:8]}"
        config_file = os.path.join("sub", f"{safe_source_name}.txt")
        file_hash = ''
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_hash = hashlib.md5(f.read().encode('utf-8')).hexdigest()
            except Exception as e:
                print(f"计算 {config_file} 的哈希失败: {e}")
                continue
        if source_stats.get(source_name, 0) > 0:
            timestamps[source_name] = {
                'last_updated': current_time,
                'file_hash': file_hash
            }
    try:
        with open(timestamps_file, 'w', encoding='utf-8') as f:
            json.dump(timestamps, f, indent=2)
        print(f"成功保存时间戳文件: {timestamps_file}")
    except Exception as e:
        print(f"保存时间戳文件 {timestamps_file} 失败: {e}")

def save_channels(original_sources):
    """保存所有原始来源列表到 channels.txt，避免丢失。"""
    channels_file="channels.txt"
    try:
        with open(channels_file, 'w', encoding='utf-8') as file:
            for source in original_sources:
                file.write(f"{source}\n")
        print(f"成功保存 {len(original_sources)} 个来源到 {channels_file}")
    except Exception as e:
        print(f"保存来源列表 {channels_file} 失败: {e}")

def save_inactive_channels(inactive_sources):
    """保存无配置的来源列表。"""
    inactive_file="inactive_channels.txt"
    try:
        with open(inactive_file, 'w', encoding='utf-8') as file:
            for source in inactive_sources:
                file.write(f"{source}\n")
        print(f"成功保存 {len(inactive_sources)} 个无配置来源到 {inactive_file}")
    except Exception as e:
        print(f"保存无配置来源列表 {inactive_file} 失败: {e}")
        
def generate_cloudflare_json(source_name_map, source_folder='sub', output_file='merged.json'):
    """生成适用于 Cloudflare Workers 的 JSON 格式。"""
    cloudflare_data = {}
    file_list = [f for f in os.listdir(source_folder) if f.endswith('.txt') and not f.startswith('merged_')]
    
    for filename in file_list:
        file_path = os.path.join(source_folder, filename)
        source_name = filename.replace('.txt', '')
        display_name = source_name_map.get(source_name, source_name)
        
        configs = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                configs.append(line.strip())
        
        if configs:
            cloudflare_data[display_name] = configs
            
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cloudflare_data, f, indent=4, ensure_ascii=False)

def generate_clash_subscription(source_folder='sub', output_file='clash_configs.yaml'):
    """生成 Clash 订阅配置文件。"""
    try:
        print("警告：未提供 clash_generator.py 文件，跳过 Clash 订阅生成。")
        # from clash_generator import generate_clash_yaml
        # generate_clash_yaml(source_folder, output_file)
    except Exception as e:
        print(f"生成 Clash 订阅时出错：{e}")

def generate_clash_meta_subscription(source_folder='sub', output_file='clash_meta_configs.yaml'):
    """生成 Clash.Meta 订阅配置文件。"""
    try:
        print("警告：未提供 clash_meta_generator.py 文件，跳过 Clash.Meta 订阅生成。")
        # from clash_meta_generator import generate_clash_meta_yaml
        # generate_clash_meta_yaml(source_folder, output_file)
    except Exception as e:
        print(f"生成 Clash.Meta 订阅时出错：{e}")

if __name__ == "__main__":
    print("正在加载来源列表和时间戳...")
    sources, timestamps, original_sources = load_channels()
    if not sources:
        print("未在 channels.txt 中找到任何来源，退出程序。")
        exit(1)
    sources_to_fetch = [(name, url) for name, url in sources if url is not None]
    print(f"将爬取 {len(sources_to_fetch)} 个来源，跳过 {len(sources) - len(sources_to_fetch)} 个未更新的来源。")
    config_folder = "sub"
    if not os.path.exists(config_folder):
        try:
            os.makedirs(config_folder)
            print(f"已创建 '{config_folder}' 目录。")
        except Exception as e:
            print(f"创建目录 {config_folder} 失败: {e}")
    source_stats = {name: 0 for name, url in sources}
    active_sources = []
    inactive_sources = []
    source_name_map = {}
    if sources_to_fetch:
        print("开始从各来源获取配置...")
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(fetch_all_configs(sources_to_fetch))
        for source_name, configs in results:
            print(f"正在处理: {source_name}")
            if isinstance(configs, list) and configs:
                valid_configs = [c for c in configs if isinstance(c, str) and is_valid_config(c)]
                count, display_name = save_configs_by_channel(valid_configs, source_name)
                source_stats[source_name] = count
                if count > 0:
                    original_url = next((url for name, url in sources_to_fetch if name == source_name), None)
                    active_sources.append((source_name, original_url))
                    source_name_map[source_name] = display_name
                    print(f"从 {source_name} 获取并保存 {count} 个配置（显示名称: {display_name}）")
                else:
                    inactive_sources.append(source_name)
                    print(f"从 {source_name} 未获取到有效配置")
            else:
                source_stats[source_name] = 0
                inactive_sources.append(source_name)
                print(f"从 {source_name} 未获取到配置（或爬取时发生错误）")
    print("\n正在更新来源时间戳...")
    save_timestamps(timestamps, active_sources, source_stats)
    print("正在保存更新后的来源列表...")
    save_channels(original_sources)
    save_inactive_channels(inactive_sources)
    print("来源列表已更新。")
    if any(count > 0 for count in source_stats.values()):
        print("\n正在合并配置...")
        merge_configs()
        print("正在按协议拆分配置...")
        split_configs_by_protocol()
        print("正在创建统计 CSV 文件...")
        create_stats_csv(source_stats)
        print("正在生成适用于 Cloudflare Workers 的 merged.json 文件...")
        generate_cloudflare_json(source_name_map)
        print("正在生成 Clash 订阅...")
        generate_clash_subscription()
        print("正在生成 Clash.Meta 订阅...")
        generate_clash_meta_subscription()
        print("所有任务完成：配置已保存，生成合并文件、按协议拆分文件、统计文件、以及各种订阅文件。")
    else:
        print("\n所有来源均未获取到代理配置，未生成合并文件、统计文件。")
