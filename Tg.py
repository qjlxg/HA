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

# --- 修正后的去重逻辑函数：根据协议提取核心参数 ---
def get_core_params(config):
    """
    根据协议类型提取核心参数，生成一个可哈希的字符串。
    这样可以忽略节点名称和非核心参数进行去重。
    """
    if config.startswith('vmess://'):
        try:
            # Vmess 特殊处理，需要 base64 解码并解析 JSON
            decoded_json = base64.b64decode(config[8:]).decode('utf-8')
            data = json.loads(decoded_json)
            # 修正：核心参数仅为 id，地址和端口可以变化
            return f"vmess_{data.get('id')}"
        except Exception:
            return None
            
    elif config.startswith('vless://'):
        # Vless 特殊处理，提取 uuid, address, port
        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', config)
        if match:
            uuid = match.group(1)
            # 修正：核心参数仅为 uuid，地址和端口可以变化
            return f"vless_{uuid}"
        return None

    elif config.startswith('trojan://'):
        # Trojan 特殊处理，提取 password, address, port
        match = re.search(r'trojan://([^@]+)@([^:]+):(\d+)', config)
        if match:
            password, address, port = match.groups()
            return f"trojan_{password}@{address}:{port}"
        return None
        
    elif config.startswith('ss://'):
        # SS 特殊处理，提取 method, password, address, port
        try:
            match = re.search(r'ss://([a-zA-Z0-9+/=]+)@([^:]+):(\d+)', config)
            if match:
                encoded_info = match.group(1)
                address = match.group(2)
                port = match.group(3)
                
                decoded_info = base64.b64decode(encoded_info).decode('utf-8')
                method, password = decoded_info.split(':', 1)
                
                return f"ss_{method}:{password}@{address}:{port}"
        except Exception:
            pass
        return None
    
    # 对于其他协议，保留原始去重逻辑（忽略 # 后内容）
    return config.split('#')[0]

# --- 以下是您的原始代码，仅修改了去重部分 ---

async def get_v2ray_links(session, url, max_pages=1, max_retries=3):
    """从指定 Telegram 频道 URL 获取代理配置（每频道最多爬取 max_pages 页）。"""
    v2ray_configs = []
    current_url = url
    page_count = 0
    no_config_pages = 0

    while current_url and page_count < max_pages:
        retry_count = 0
        while retry_count <= max_retries:
            try:
                await asyncio.sleep(random.uniform(1, 3) * retry_count)  # 添加随机延迟以避免触发速率限制
                async with session.get(current_url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')

                        # 查找可能包含代理配置的标签
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
                                text = ' '.join(tag.stripped_strings).strip()
                                if len(text) > 10:
                                    matches = re.findall(protocol_pattern, text, re.MULTILINE)
                                    for match in matches:
                                        config = match[0] + (match[1] if match[1] else '')
                                        if len(config) > len('vmess://') + 5:
                                            page_configs.append(config.strip())
                    
                        for tag_list in tags_to_check:
                            for tag in tag_list:
                                text = ' '.join(tag.stripped_strings).strip()
                                if len(text) > 10 and text.startswith(('hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://')):
                                    for config_line in text.split('\n'):
                                        stripped_config = config_line.strip()
                                        if stripped_config.startswith(('hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://')):
                                            if len(config) > len('vmess://') + 5:
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
    
    unique_configs = []
    seen_hashes = set()
    for config in configs:
        if not is_valid_config(config):
            continue
        
        # --- 优化后的去重逻辑开始 ---
        core_params = get_core_params(config)
        if core_params:
            config_hash = hashlib.md5(core_params.encode('utf-8')).hexdigest()
        else:
            config_no_name = config.split('#')[0] if '#' in config else config
            config_hash = hashlib.md5(config_no_name.encode('utf-8')).hexdigest()
        # --- 优化后的去重逻辑结束 ---

        if config_hash not in seen_hashes:
            if '#' in config:
                config_body, node_name = config.rsplit('#', 1)
                cleaned_name = clean_node_name(node_name)
                config = f"{config_body}#{cleaned_name}"
            unique_configs.append(config)
            seen_hashes.add(config_hash)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            for config in unique_configs:
                file.write(config + '\n')
        print(f"成功保存 {len(unique_configs)} 个配置到 {file_path}")
    except Exception as e:
        print(f"保存配置到 {file_path} 失败: {e}")
        return 0, None
    
    return len(unique_configs), display_name or source_name

def merge_configs():
    """合并所有来源的配置到一个文件，并去重。"""
    config_folder = "sub"
    merged_file = "merged_configs.txt"
    seen_hashes = set()
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 新增的正则匹配模式，用于从一行中提取所有配置
    protocol_pattern = r'(hysteria2://|vmess://|trojan://|ss://|ssr://|vless://)[^\s#]*(#[^\s#]*)?'

    try:
        with open(merged_file, 'w', encoding='utf-8') as outfile:
            outfile.write(f"# 自动生成的合并配置，生成时间：{current_time_str}\n\n")
            for filename in sorted(os.listdir(config_folder)):
                if filename.endswith('.txt') and filename not in ['merged_configs.txt', 'vless.txt', 'vmess.txt', 'trojan.txt', 'ss.txt', 'ssr.txt', 'hysteria2.txt']:
                    file_path = os.path.join(config_folder, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as infile:
                            # 更改：读取整个文件内容，然后用正则匹配所有配置
                            content = infile.read()
                            matches = re.findall(protocol_pattern, content, re.MULTILINE)
                            all_configs_from_file = [match[0] + match[1] for match in matches]

                            for config in all_configs_from_file:
                                if is_valid_config(config):
                                    core_params = get_core_params(config)
                                    if core_params:
                                        config_hash = hashlib.md5(core_params.encode('utf-8')).hexdigest()
                                    else:
                                        config_no_name = config.split('#')[0] if '#' in config else config
                                        config_hash = hashlib.md5(config_no_name.encode('utf-8')).hexdigest()

                                    if config_hash not in seen_hashes:
                                        if '#' in config:
                                            config_body, node_name = config.rsplit('#', 1)
                                            cleaned_name = clean_node_name(node_name)
                                            config = f"{config_body}#{cleaned_name}"
                                        outfile.write(config + '\n')
                                        seen_hashes.add(config_hash)
                            outfile.write('\n')
                    except Exception as e:
                        print(f"读取文件 {file_path} 失败: {e}")
            print(f"成功生成合并文件: {merged_file}")
    except Exception as e:
        print(f"生成合并文件 {merged_file} 失败: {e}")

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

def load_channels(channels_file="channels.txt", timestamps_file="channel_timestamps.json"):
    """加载来源列表，检查时间戳以决定是否爬取。"""
    sources = []
    timestamps = {}
    
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

def save_timestamps(timestamps, active_sources, source_stats, timestamps_file="channel_timestamps.json"):
    """保存来源的时间戳和文件哈希，仅为成功获取配置的来源更新。"""
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

def save_channels(original_sources, channels_file="channels.txt"):
    """保存所有原始来源列表到 channels.txt，避免丢失。"""
    try:
        with open(channels_file, 'w', encoding='utf-8') as file:
            for source in original_sources:
                file.write(f"{source}\n")
        print(f"成功保存 {len(original_sources)} 个来源到 {channels_file}")
    except Exception as e:
        print(f"保存来源列表 {channels_file} 失败: {e}")

def save_inactive_channels(inactive_sources, inactive_file="inactive_channels.txt"):
    """保存无配置的来源列表。"""
    try:
        with open(inactive_file, 'w', encoding='utf-8') as file:
            for source in inactive_sources:
                file.write(f"{source}\n")
        print(f"成功保存 {len(inactive_sources)} 个无配置来源到 {inactive_file}")
    except Exception as e:
        print(f"保存无配置来源列表 {inactive_file} 失败: {e}")

if __name__ == "__main__":
    print("正在加载来源列表和时间戳...")
    sources, timestamps, original_sources = load_channels("channels.txt", "channel_timestamps.json")

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

        print("正在创建统计 CSV 文件...")
        create_stats_csv(source_stats)
        print("所有任务完成：配置已保存，生成合并文件、统计文件。")
    else:
        print("\n所有来源均未获取到代理配置，未生成合并文件、统计文件。")
