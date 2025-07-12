import asyncio
import re
import ipaddress
from urllib.parse import unquote, urlparse, parse_qs
import aiodns
import geoip2.database
import logging
import base64
import json

# --- 日志配置 ---
# 注意：在模块内部独立配置日志，以防主脚本未配置
_logger = logging.getLogger(__name__)
if not _logger.handlers:
    _logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    _logger.addHandler(ch)

# --- GeoIP Reader 实例 (模块级) ---
_GEOIP_READER = None

def init_geoip_reader(db_path: str):
    """
    初始化 GeoIP 数据库读取器。
    这个函数会在 deduplicate_and_rename_nodes 内部被调用。
    """
    global _GEOIP_READER
    if _GEOIP_READER is None:
        try:
            _GEOIP_READER = geoip2.database.Reader(db_path)
            _logger.info("GeoIP 数据库加载成功: %s", db_path)
        except Exception as e:
            _logger.error("加载 GeoIP 数据库失败: %s", e)
            _GEOIP_READER = None
    return _GEOIP_READER

def get_country_name(ip_address: str) -> str:
    """根据 IP 地址获取国家名称。"""
    if _GEOIP_READER is None:
        return "Unknown"
    try:
        response = _GEOIP_READER.country(ip_address)
        if response.country.names.get('zh-CN'):
            return response.country.names['zh-CN']
        elif response.country.name:
            return response.country.name
        return "Unknown"
    except Exception as e:
        # 调试级别，避免过多日志干扰
        _logger.debug("GeoIP 查询失败 for %s: %s", ip_address, e)
        return "Unknown"

def _decode_base64_urlsafe(data: str) -> str:
    """解码 Base64 URL 安全字符串，并处理填充问题。"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8')

def parse_node_url_to_dict(node_url: str) -> dict | None:
    """
    将各种代理协议的 URL 解析为标准化字典。
    **重要提示：您需要根据支持的协议类型（例如 VLESS, SSR, HTTP, SOCKS5 等）
    在此函数中补充更完整的解析逻辑，以确保所有关键参数都被提取。**
    """
    try:
        parsed_url = urlparse(node_url)
        protocol = parsed_url.scheme.lower()
        node_info = {
            'protocol': protocol,
            'server': parsed_url.hostname or '',
            'port': parsed_url.port or 0,
            'remark': unquote(parsed_url.fragment or '') # fragment通常是备注
        }

        if protocol == 'vmess':
            # VMess URL 结构: vmess://base64(json_config)
            try:
                b64_config = parsed_url.netloc # netloc 是 base64 部分
                json_str = _decode_base64_urlsafe(b64_config)
                config_data = json.loads(json_str)
                node_info['uuid'] = config_data.get('id')
                node_info['alterId'] = config_data.get('aid', 0)
                node_info['security'] = config_data.get('scy', '')
                node_info['network'] = config_data.get('net', '')
                node_info['tls'] = config_data.get('tls', '') == 'tls'
                node_info['sni'] = config_data.get('host', '') # host 在 json 中用于 SNI
                node_info['path'] = config_data.get('path', '')
                node_info['remark'] = config_data.get('ps', node_info['remark']) # ps 是 VMess 中的备注
            except Exception as e:
                _logger.warning(f"解析 VMess 节点失败: {node_url}, 错误: {e}")
                return None
        elif protocol == 'ss':
            # Shadowsocks URL 结构: ss://base64(method:password@server:port)#remark
            if parsed_url.netloc and '=' in parsed_url.netloc: # 判断是否为 base64 编码
                try:
                    decoded_part = _decode_base64_urlsafe(parsed_url.netloc)
                    parts = decoded_part.split('@')
                    if len(parts) == 2:
                        method_pass = parts[0].split(':')
                        node_info['method'] = method_pass[0] if len(method_pass) > 0 else ''
                        node_info['password'] = method_pass[1] if len(method_pass) > 1 else ''
                        server_port = parts[1].split(':')
                        node_info['server'] = server_port[0] if len(server_port) > 0 else ''
                        node_info['port'] = int(server_port[1]) if len(server_port) > 1 and server_port[1].isdigit() else 0
                except Exception as e:
                    _logger.warning(f"解析 Shadowsocks base64 节点失败: {node_url}, 错误: {e}")
                    return None
            else: # 非 base64 编码，直接从 URL components 解析
                # 例如：ss://AES-256-GCM:password@server:port
                # urlparse 会将 AES-256-GCM:password 放入 username:password 字段
                node_info['method'] = parsed_url.username or ''
                node_info['password'] = parsed_url.password or ''
        elif protocol == 'ssr':
            # SSR URL 结构: ssr://base64(server:port:protocol:method:obfs:password_base64/?params)#remark_base64
            try:
                b64_config = parsed_url.netloc
                decoded_part = _decode_base64_urlsafe(b64_config)
                parts = decoded_part.split(':')
                if len(parts) >= 6:
                    node_info['server'] = parts[0]
                    node_info['port'] = int(parts[1])
                    node_info['protocol_ssr'] = parts[2] # SSR 协议
                    node_info['method'] = parts[3]
                    node_info['obfs'] = parts[4]
                    node_info['password'] = _decode_base64_urlsafe(parts[5].split('/?')[0]) # 密码
                    
                    # 解析参数
                    query_params_str = parts[5].split('/?')[1] if '/?' in parts[5] else ''
                    query_params = parse_qs(query_params_str)
                    node_info['obfsparam'] = _decode_base64_urlsafe(query_params.get('obfsparam', [''])[0])
                    node_info['protoparam'] = _decode_base64_urlsafe(query_params.get('protoparam', [''])[0])
                    
                    # SSR 备注通常在 fragment 中，但有时也在 query 中
                    if parsed_url.fragment:
                        node_info['remark'] = _decode_base64_urlsafe(parsed_url.fragment)
                else:
                    _logger.warning(f"SSR 节点格式不完整: {node_url}")
                    return None
            except Exception as e:
                _logger.warning(f"解析 SSR 节点失败: {node_url}, 错误: {e}")
                return None
        elif protocol == 'trojan':
            # Trojan URL 结构: trojan://password@server:port?param=value#remark
            node_info['password'] = parsed_url.username or '' # username 是密码
            query_params = parse_qs(parsed_url.query)
            node_info['tls'] = 'sni' in query_params or 'allowInsecure' in query_params or 'fingerprint' in query_params # 简单判断是否启用 TLS
            node_info['sni'] = query_params.get('sni', [node_info['server']])[0]
        elif protocol == 'vless':
            # VLESS URL 结构: vless://uuid@server:port?params#remark
            node_info['uuid'] = parsed_url.username or '' # username 是 UUID
            query_params = parse_qs(parsed_url.query)
            node_info['network'] = query_params.get('type', ['tcp'])[0]
            node_info['tls'] = query_params.get('security', [''])[0] == 'tls'
            node_info['flow'] = query_params.get('flow', [''])[0]
            node_info['sni'] = query_params.get('sni', [''])[0]
            node_info['path'] = query_params.get('path', [''])[0]
            node_info['host'] = query_params.get('host', [''])[0]
            # ... 其他 VLESS 参数
        elif protocol == 'hysteria2':
            # Hysteria2 URL: hysteria2://password@server:port?param=value#remark
            node_info['password'] = parsed_url.username or '' # username 是密码
            query_params = parse_qs(parsed_url.query)
            node_info['obfs'] = query_params.get('obfs', [''])[0]
            node_info['obfs_param'] = query_params.get('obfs-password', [''])[0]
            node_info['tls'] = True # Hysteria2 总是使用 TLS
            node_info['sni'] = query_params.get('sni', [node_info['server']])[0]
        elif protocol in ['http', 'socks5']:
            # 对于明文 HTTP/SOCKS5 代理，直接从 URL 解析
            node_info['username'] = parsed_url.username or ''
            node_info['password'] = parsed_url.password or ''

        # 确保 remark 字段存在且解码
        if 'remark' in node_info and node_info['remark']:
            node_info['remark'] = unquote(node_info['remark'])
        else:
            node_info['remark'] = '' # 默认空字符串

        # 如果解析失败， server 或 port 可能为空，返回 None
        if not node_info['server'] or not node_info['port']:
            _logger.debug(f"节点解析不完整，跳过: {node_url}")
            return None

        return node_info
    except Exception as e:
        _logger.error(f"解析节点 URL 失败: {node_url}, 错误: {e}", exc_info=True)
        return None

async def generate_node_key_async(node_info: dict, resolver: aiodns.DNSResolver) -> tuple | None:
    """
    根据节点信息生成唯一的键，包含异步 DNS 解析。
    这个键将用于去重。
    """
    if not node_info or not node_info.get('protocol') or not node_info.get('server') or not node_info.get('port'):
        _logger.debug("节点信息不完整，无法生成键: %s", node_info)
        return None

    protocol = node_info['protocol']
    server = node_info['server']
    port = node_info['port']

    resolved_server_ip = server
    # 如果是域名且不是私有IP或环回地址，则尝试解析
    # 优先判断是否为合法的IP地址，避免对已经解析的IP再次进行查询
    try:
        ip_obj = ipaddress.ip_address(server)
        if ip_obj.is_private or ip_obj.is_loopback:
            _logger.debug(f"服务器 {server} 是私有或回环地址，跳过 DNS 解析。")
            resolved_server_ip = server
        else:
            resolved_server_ip = str(ip_obj) # 已经是公共IP
    except ValueError: # 不是IP地址，尝试DNS解析
        try:
            result = await resolver.query(server, 'A')
            if result:
                resolved_server_ip = result[0].host
            else:
                _logger.warning(f"DNS 解析无结果 for {server}. 使用原始域名。")
        except aiodns.error.DNSError as e:
            _logger.warning(f"DNS 解析失败 for {server}: {e}. 使用原始域名。")
        except Exception as e:
            _logger.warning(f"DNS 解析时发生未知错误 for {server}: {e}. 使用原始域名。")

    key_components = [protocol, resolved_server_ip, port]

    # 根据协议添加特定的唯一参数，这些参数是判断节点是否“相同”的关键
    if protocol == 'vmess':
        key_components.append(node_info.get('uuid'))
        key_components.append(node_info.get('alterId'))
        key_components.append(node_info.get('security'))
        key_components.append(node_info.get('network'))
        key_components.append(node_info.get('tls'))
        key_components.append(node_info.get('sni')) # SNI
        key_components.append(node_info.get('path')) # WebSocket Path
        key_components.append(node_info.get('host')) # WebSocket Host header
    elif protocol == 'ss':
        key_components.append(node_info.get('password'))
        key_components.append(node_info.get('method'))
    elif protocol == 'ssr':
        key_components.append(node_info.get('password'))
        key_components.append(node_info.get('method'))
        key_components.append(node_info.get('protocol_ssr'))
        key_components.append(node_info.get('obfs'))
        key_components.append(node_info.get('obfsparam'))
        key_components.append(node_info.get('protoparam'))
    elif protocol == 'trojan':
        key_components.append(node_info.get('password'))
        key_components.append(node_info.get('tls'))
        key_components.append(node_info.get('sni'))
    elif protocol == 'vless':
        key_components.append(node_info.get('uuid'))
        key_components.append(node_info.get('network'))
        key_components.append(node_info.get('tls'))
        key_components.append(node_info.get('flow'))
        key_components.append(node_info.get('sni'))
        key_components.append(node_info.get('path'))
        key_components.append(node_info.get('host'))
    elif protocol == 'hysteria2':
        key_components.append(node_info.get('password'))
        key_components.append(node_info.get('obfs'))
        key_components.append(node_info.get('obfs_param'))
        key_components.append(node_info.get('sni'))
    elif protocol in ['http', 'socks5']:
        key_components.append(node_info.get('username'))
        key_components.append(node_info.get('password'))

    # 将列表转换为元组，以便作为 set 元素
    return tuple(key_components)

async def deduplicate_and_rename_nodes(
    nodes_urls: list[str],
    resolver: aiodns.DNSResolver,
    geoip_db_path: str # 传递数据库路径
) -> list[dict]:
    """
    主要的去重和 GeoIP 命名函数。
    它将节点 URL 解析为标准化字典，生成唯一键，进行去重，并添加 GeoIP 名称。
    返回去重并命名的节点信息字典列表。
    """
    init_geoip_reader(geoip_db_path) # 确保 GeoIP Reader 已初始化

    seen_keys = set()
    unique_node_infos = [] # 存储去重后的节点信息字典列表
    
    _logger.info("开始去重和 GeoIP 命名...")
    
    # 批量解析和生成键的任务
    tasks = []
    # 存储原始 URL 到解析后的字典的映射，以便在生成键后再次使用
    parsed_node_map = {} 
    for node_url in nodes_urls:
        node_info = parse_node_url_to_dict(node_url)
        if node_info:
            # 存储原始 URL 和解析结果，方便后续通过原始 URL 找到对应的解析结果
            parsed_node_map[node_url] = node_info 
            tasks.append(generate_node_key_async(node_info, resolver))
        else:
            tasks.append(None) # 对于无法解析的 URL，仍然在 tasks 中占位

    # 并发执行所有键生成任务 (包括 DNS 查询)
    node_keys_results = await asyncio.gather(*tasks)

    # 遍历原始 URL 列表，结合其解析结果和生成的键进行去重和命名
    for i, node_url in enumerate(nodes_urls):
        node_key = node_keys_results[i] # 获取对应的键
        node_info = parsed_node_map.get(node_url) # 获取对应的解析信息

        if node_info and node_key:
            if node_key not in seen_keys:
                seen_keys.add(node_key)
                
                server_ip_for_geo = node_key[1] # 键的第二个元素是解析后的 IP
                country = get_country_name(server_ip_for_geo) # 获取国家名称

                # 更新节点的备注，添加国家信息并截断前5位
                original_remark = node_info.get('remark', '')
                # 只保留原节点名称前5位，多余的全部删除
                truncated_remark = original_remark[:5] if original_remark else ''
                new_remark = f"{country}-{truncated_remark}" if truncated_remark else country
                node_info['remark'] = new_remark
                
                unique_node_infos.append(node_info) # 添加去重并命名的节点信息字典
            else:
                _logger.debug(f"发现重复节点 (基于核心参数): {node_url} (键: {node_key})")
        # else: node_info or node_key was None, 警告或错误已在 parse_node_url_to_dict 或 generate_node_key_async 中记录

    _logger.info(f"去重和 GeoIP 命名完成，得到 {len(unique_node_infos)} 个唯一节点。")
    
    # 返回的是处理后的节点信息字典列表
    return unique_node_infos

