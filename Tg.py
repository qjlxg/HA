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

async def get_v2ray_links(session, url, max_pages=1):
    """从指定 Telegram 频道 URL 获取代理配置（每频道最多爬取 max_pages 页）。"""
    v2ray_configs = []
    current_url = url
    page_count = 0
    no_config_pages = 0

    while current_url and page_count < max_pages:
        try:
            await asyncio.sleep(1)  # 添加 1 秒延迟以避免触发速率限制
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
                        soup.find_all('div')
                    )
                    
                    page_configs = []
                    for tag_list in tags_to_check:
                        for tag in tag_list:
                            text = ' '.join(tag.stripped_strings).strip()
                            if len(text) > 10 and text.startswith(('hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://')):
                                for config_line in text.split('\n'):
                                    stripped_config = config_line.strip()
                                    if stripped_config.startswith(('hysteria2://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'vless://')):
                                        if len(stripped_config) > len('vmess://') + 5:
                                            page_configs.append(stripped_config)
                    
                    page_configs = list(set(page_configs))  # 移除本页重复配置
                    print(f"从 {current_url} (第 {page_count + 1} 页，状态码 {response.status}) 获取到 {len(page_configs)} 个配置")
                    v2ray_configs.extend(page_configs)

                    if not page_configs:
                        no_config_pages += 1
                        if no_config_pages >= 3:  # 连续 3 页无配置则提前停止
                            print(f"在 {current_url} 提前停止：连续 3 页无配置")
                            current_url = None
                            break

                    # 查找分页所需的最旧消息 ID
                    messages = soup.find_all('div', class_='tgme_widget_message')
                    if messages:
                        oldest_message = messages[-1]  # 最旧消息通常在列表末尾
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
                elif response.status == 429:
                    print(f"在 {current_url} 触发速率限制 (状态码: {response.status})，等待 10 秒后重试")
                    await asyncio.sleep(10)
                    continue
                elif response.status in [404, 403]:
                    print(f"频道不存在或被禁止访问: {current_url} (状态码: {response.status})")
                    current_url = None
                else:
                    print(f"获取 URL {current_url} 失败 (状态码: {response.status})")
                    current_url = None
        except aiohttp.ClientError as e:
            print(f"获取 URL {current_url} 时发生网络错误: {e}")
            current_url = None
        except asyncio.TimeoutError:
            print(f"获取 URL {current_url} 超时，跳过")
            current_url = None
        except Exception as e:
            print(f"获取 URL {current_url} 时发生未知错误: {e}")
            current_url = None

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
        return [(sources[i][0], results[i]) for i in range(len(sources))]

def extract_channel_from_config(config):
    """从配置的节点名称（# 后的部分）提取显示名称。"""
    try:
        node_name = config.split('#')[-1].strip()
        cleaned_name = re.sub(r'[_-]\d{4}[-]\d{2}[-]\d{2}|\d+|[_\-](free|vpn|config|new|official|v\d+)$', '', node_name, flags=re.IGNORECASE)
        cleaned_name = cleaned_name.strip('_- ')
        return cleaned_name if cleaned_name else None
    except:
        return None

def save_configs_by_channel(configs, source_name):
    """保存代理配置到文件，并提取显示名称。"""
    if not configs:
        print(f"来源 {source_name} 无有效配置，跳过保存")
        return 0, None

    config_folder = "sub" # 这个路径不变，独立来源文件仍保存在 sub 文件夹
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
    
    # 从配置中提取显示名称
    source_names = [extract_channel_from_config(config) for config in configs]
    source_names = [name for name in source_names if name]
    display_name = None
    if source_names:
        from collections import Counter
        display_name = Counter(source_names).most_common(1)[0][0]
    
    # 去重配置
    unique_configs = list(set(configs))
    
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
    # 将 merged_file 路径改为根目录
    merged_file = "merged_configs.txt" # 放到根目录
    seen_configs = set()
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(merged_file, 'w', encoding='utf-8') as outfile:
            outfile.write(f"# 自动生成的合并配置，生成时间：{current_time_str}\n\n")
            # 遍历 sub 文件夹中的独立来源文件
            for filename in sorted(os.listdir(config_folder)):
                # 仅处理 .txt 文件，并且排除可能在 sub 文件夹中意外生成的合并或协议文件
                if filename.endswith('.txt') and filename not in ['merged_configs.txt', 'vless.txt', 'vmess.txt', 'trojan.txt', 'ss.txt', 'ssr.txt', 'hysteria2.txt']:
                    file_path = os.path.join(config_folder, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as infile:
                            outfile.write(f"# 来源: {filename}\n")
                            for line in infile:
                                if line.strip() and not line.strip().startswith('#') and line not in seen_configs:
                                    outfile.write(line)
                                    seen_configs.add(line)
                            outfile.write('\n')
                    except Exception as e:
                        print(f"读取文件 {file_path} 失败: {e}")
            print(f"成功生成合并文件: {merged_file}")
    except Exception as e:
        print(f"生成合并文件 {merged_file} 失败: {e}")

def split_configs_by_protocol():
    """按协议类型拆分合并的配置到单独文件。"""
    # merged_file 从根目录读取
    merged_file = "merged_configs.txt" # 从根目录读取

    if not os.path.exists(merged_file):
        print(f"警告：未找到 {merged_file}，无法按协议拆分")
        return

    protocol_files = {
        'hysteria2': 'hysteria2.txt', # 放到根目录
        'vmess': 'vmess.txt',       # 放到根目录
        'trojan': 'trojan.txt',     # 放到根目录
        'ss': 'ss.txt',             # 放到根目录
        'ssr': 'ssr.txt',           # 放到根目录
        'vless': 'vless.txt',       # 放到根目录
    }

    # 清空或创建协议文件
    for file_path in protocol_files.values():
        try:
            # 直接使用文件名，因为它现在指向根目录
            if os.path.exists(file_path):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('') # 清空文件内容
            else: # 如果文件不存在，也创建它
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('')
        except Exception as e:
            print(f"清空/创建文件 {file_path} 失败: {e}")

    try:
        with open(merged_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                for protocol_prefix in protocol_files.keys():
                    if line_stripped.startswith(f"{protocol_prefix}://"):
                        try:
                            # 直接使用文件名，因为它现在指向根目录
                            with open(protocol_files[protocol_prefix], 'a', encoding='utf-8') as outfile:
                                outfile.write(line_stripped + '\n')
                        except Exception as e:
                            print(f"写入协议文件 {protocol_files[protocol_prefix]} 失败: {e}")
                            continue
                        break
        print("成功按协议拆分配置")
    except Exception as e:
        print(f"读取合并文件 {merged_file} 或拆分协议失败: {e}")

def create_stats_csv(source_stats):
    """生成统计 CSV 文件，包含来源配置数量和更新时间。"""
    # 将 csv_file 路径改为根目录
    csv_file = "stats.csv" # 放到根目录
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

# 删除 create_sub_section 函数
# def create_sub_section(source_name_map):
#     """更新 README.md 的 Sub 部分，使用从配置提取的显示名称。"""
#     readme_path = "README.md"
#     sub_folder = "sub"
#     existing_links = set()

#     content = ""
#     if os.path.exists(readme_path):
#         try:
#             with open(readme_path, 'r', encoding='utf-8') as readme_file:
#                 content = readme_file.read()
#                 sub_section_match = re.search(r'(## Sub\n\| Sub \|\n\|-----.*?)(?=\n##|\Z)', content, re.DOTALL)
#                 if sub_section_match:
#                     links = re.findall(r'\[([^\]]+)\]\(https://raw\.githubusercontent\.com/qjlxg/ClashForge/main/(sub/)?([^\)]+)\.txt\)', sub_section_match.group(1))
#                     for link_name, _, _ in links:
#                         existing_links.add(link_name)
#         except Exception as e:
#             print(f"读取 README.md 文件失败: {e}")

#     new_sub_section_lines = ["## Sub", "| Sub |", "|-----|"]

#     for filename in sorted(os.listdir(sub_folder)):
#         if filename.endswith('.txt') and filename not in ['merged_configs.txt', 'vless.txt', 'vmess.txt', 'trojan.txt', 'ss.txt', 'ssr.txt', 'hysteria2.txt']:
#             source_name = filename[:-4]
#             display_name = source_name_map.get(source_name, urllib.parse.unquote(source_name))
#             url = f"https://raw.githubusercontent.com/qjlxg/ClashForge/main/sub/{urllib.parse.quote(filename)}"
#             new_sub_section_lines.append(f"| [{display_name}]({url}) |")

#     new_sub_section_lines.append(f"| [merged_configs](https://raw.githubusercontent.com/qjlxg/ClashForge/main/merged_configs.txt) |")
#     for protocol in ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']:
#         protocol_filename = f"{protocol}.txt"
#         protocol_url = f"https://raw.githubusercontent.com/qjlxg/ClashForge/main/{protocol_filename}"
#         new_sub_section_lines.append(f"| [{protocol}]({protocol_url}) |")

#     new_content_section = "\n".join(new_sub_section_lines) + "\n"

#     try:
#         with open(readme_path, 'w', encoding='utf-8') as readme_file:
#             if '## Sub' in content:
#                 content = re.sub(r'## Sub\n\| Sub \|\n\|-----.*?(?=\n##|\Z)', new_content_section, content, flags=re.DOTALL)
#             else:
#                 content += "\n" + new_content_section
#             readme_file.write(content)
#         print(f"成功更新 README.md")
#     except Exception as e:
#         print(f"更新 README.md 失败: {e}")

def load_channels(channels_file="channels.txt", timestamps_file="channel_timestamps.json"):
    """加载来源列表，检查时间戳以决定是否爬取。"""
    sources = []
    timestamps = {}
    
    # 加载现有时间戳
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
    
    # 从文件读取来源
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
        # 检查来源是否需要更新
        safe_source_name = "".join(c for c in source_name if c.isalnum() or c in ('-', '_')).strip()
        if not safe_source_name:
            safe_source_name = f"source_{hashlib.md5(source_name.encode()).hexdigest()[:8]}"
            print(f"来源名称 {source_name} 无效，使用默认名称: {safe_source_name}")
        
        config_file = os.path.join("sub", f"{safe_source_name}.txt") # 独立来源文件路径不变
        should_fetch = True
        
        if source_name in timestamps:
            try:
                last_updated = datetime.fromisoformat(timestamps[source_name]['last_updated'])
                last_hash = timestamps[source_name].get('file_hash', '')
                
                # 计算当前文件哈希（如果存在）
                current_hash = ''
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        current_hash = hashlib.md5(f.read().encode('utf-8')).hexdigest()
                
                # 如果时间戳晚于当前时间（可能错误），强制爬取
                if last_updated > current_time:
                    print(f"来源 {source_name} 的时间戳 {last_updated} 晚于当前时间，强制爬取")
                    should_fetch = True
                # 如果 24 小时内未更改（哈希相同），跳过
                elif last_updated > cutoff_time and current_hash == last_hash:
                    print(f"跳过 {source_name}：无需更新（最后更新时间 {last_updated}，文件哈希未变化）")
                    should_fetch = False
            except Exception as e:
                print(f"检查 {source_name} 的时间戳失败: {e}，强制爬取")
                should_fetch = True
        
        if should_fetch:
            sources.append((source_name, f"https://t.me/s/{source_name}"))
        else:
            sources.append((source_name, None))  # 标记为跳过但保留在列表中
    
    return sources, timestamps, original_sources

def save_timestamps(timestamps, active_sources, source_stats, timestamps_file="channel_timestamps.json"):
    """保存来源的时间戳和文件哈希，仅为成功获取配置的来源更新。"""
    current_time = datetime.now().isoformat()
    
    for source_name, _ in active_sources:
        safe_source_name = "".join(c for c in source_name if c.isalnum() or c in ('-', '_')).strip()
        if not safe_source_name:
            safe_source_name = f"source_{hashlib.md5(source_name.encode()).hexdigest()[:8]}"
        config_file = os.path.join("sub", f"{safe_source_name}.txt") # 独立来源文件路径不变
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
    # 加载来源列表和时间戳
    print("正在加载来源列表和时间戳...")
    sources, timestamps, original_sources = load_channels("channels.txt", "channel_timestamps.json")

    if not sources:
        print("未在 channels.txt 中找到任何来源，退出程序。")
        exit(1)

    # 筛选需要爬取的来源（URL 不为 None）
    sources_to_fetch = [(name, url) for name, url in sources if url is not None]
    print(f"将爬取 {len(sources_to_fetch)} 个来源，跳过 {len(sources) - len(sources_to_fetch)} 个未更新的来源。")

    # 初始化 sub 目录（不删除旧文件）
    config_folder = "sub"
    if not os.path.exists(config_folder):
        try:
            os.makedirs(config_folder)
            print(f"已创建 '{config_folder}' 目录。")
        except Exception as e:
            print(f"创建目录 {config_folder} 失败: {e}")

    # 获取配置
    source_stats = {name: 0 for name, _ in sources}  # 为所有来源初始化统计
    active_sources = []
    inactive_sources = []
    source_name_map = {}  # 存储文件名到显示名称的映射 (虽然不再用于 README，但可能在其他地方有用)

    if sources_to_fetch:
        print("开始从各来源获取配置...")
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(fetch_all_configs(sources_to_fetch))

        for source_name, configs in results:
            print(f"正在处理: {source_name}")
            if isinstance(configs, list) and configs:
                valid_configs = [c for c in configs if isinstance(c, str) and c.strip()]
                count, display_name = save_configs_by_channel(valid_configs, source_name)
                source_stats[source_name] = count
                if count > 0:
                    # 确保 active_sources 中的 source_name 能够正确映射回原始的 URL
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

    # 更新时间戳
    print("\n正在更新来源时间戳...")
    save_timestamps(timestamps, active_sources, source_stats)

    # 保存更新后的来源列表
    print("正在保存更新后的来源列表...")
    save_channels(original_sources)  # 保存原始来源列表，避免丢失
    save_inactive_channels(inactive_sources)
    print("来源列表已更新。")

    if any(count > 0 for count in source_stats.values()):
        print("\n正在合并配置...")
        merge_configs()
        print("正在按协议拆分配置...")
        split_configs_by_protocol()
        print("正在创建统计 CSV 文件...")
        create_stats_csv(source_stats)
        # 移除对 create_sub_section 的调用
        # print("正在更新 README.md...")
        # create_sub_section(source_name_map)
        print("所有任务完成：配置已保存，生成合并文件、协议文件、统计文件。") # 更新完成消息
    else:
        print("\n所有来源均未获取到代理配置，未生成合并文件、统计文件。") # 更新完成消息
