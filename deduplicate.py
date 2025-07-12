import re
import os
import json
import hashlib
import asyncio
import logging
from urllib.parse import unquote, urlparse
from typing import Set, Dict, Optional
from dataclasses import dataclass, field
import aiofiles
import geoip2.database
import aiodns
from cachetools import TTLCache
from .proxy_scraper import parse_node_url_to_info, update_node_remark, test_node_latency, CrawlerConfig

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deduplicate.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def load_dns_cache(config: CrawlerConfig) -> Dict[str, str]:
    """加载 DNS 缓存"""
    try:
        async with aiofiles.open(config.dns_cache_file, 'r', encoding='utf-8') as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"加载 DNS 缓存失败 '{config.dns_cache_file}': {e}")
        return {}

async def save_dns_cache(config: CrawlerConfig, cache: Dict[str, str]) -> None:
    """保存 DNS 缓存"""
    try:
        async with aiofiles.open(config.dns_cache_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(cache, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.error(f"保存 DNS 缓存失败 '{config.dns_cache_file}': {e}")

async def load_geoip_cache(config: CrawlerConfig) -> Dict[str, str]:
    """加载 GeoIP 缓存"""
    try:
        async with aiofiles.open(config.geoip_cache_file, 'r', encoding='utf-8') as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"加载 GeoIP 缓存失败 '{config.geoip_cache_file}': {e}")
        return {}

async def save_geoip_cache(config: CrawlerConfig, cache: Dict[str, str]) -> None:
    """保存 GeoIP 缓存"""
    try:
        async with aiofiles.open(config.geoip_cache_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(cache, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.error(f"保存 GeoIP 缓存失败 '{config.geoip_cache_file}': {e}")

async def log_duplicate_node(node1: str, node2: str, unique_key: str, config: CrawlerConfig, latency1: Optional[float] = None, latency2: Optional[float] = None) -> None:
    """异步记录重复节点到文件，包含差异字段和延迟信息"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        node1_info = parse_node_url_to_info(node1, config)
        node2_info = parse_node_url_to_info(node2, config)
        diff = {k: (node1_info.get(k), node2_info.get(k)) for k in node1_info if node1_info.get(k) != node2_info.get(k)} if node1_info and node2_info else {}
        latency_info = f", Latency: {latency1:.2f}ms vs {latency2:.2f}ms" if latency1 is not None and latency2 is not None else ""
        os.makedirs(os.path.dirname(config.duplicate_nodes_file), exist_ok=True)
        async with aiofiles.open(config.duplicate_nodes_file, mode='a', encoding='utf-8') as f:
            await f.write(f"[{timestamp}] 重复节点: {node1[:50]}... 与 {node2[:50]}... (唯一键: {unique_key}, 差异: {diff}{latency_info})\n")
    except Exception as e:
        logger.error(f"记录重复节点失败 '{config.duplicate_nodes_file}': {e}")

async def log_node_details(node: str, ip: Optional[str], country_code: str, config: CrawlerConfig, latency: Optional[float] = None) -> None:
    """异步记录节点详细信息"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        os.makedirs(os.path.dirname(config.node_details_file), exist_ok=True)
        async with aiofiles.open(config.node_details_file, mode='a', encoding='utf-8') as f:
            latency_info = f", Latency: {latency:.2f}ms" if latency is not None else ""
            await f.write(f"[{timestamp}] 节点: {node[:50]}... IP: {ip or 'N/A'}, 国家代码: {country_code}{latency_info}\n")
    except Exception as e:
        logger.error(f"记录节点详情失败 '{config.node_details_file}': {e}")

async def resolve_hostname_async(hostname: str, config: CrawlerConfig) -> Optional[str]:
    """异步解析域名到 IP 地址，带缓存和多服务器重试"""
    cache = TTLCache(maxsize=config.geoip['cache_size'], ttl=86400)
    dns_cache = await load_dns_cache(config)
    cache.update(dns_cache)
    if hostname in cache:
        return cache[hostname]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        cache[hostname] = hostname
        dns_cache[hostname] = hostname
        await save_dns_cache(config, dns_cache)
        return hostname
    resolver = aiodns.DNSResolver(timeout=config.geoip['dns_timeout'], nameservers=config.geoip['dns_servers'])
    for server in config.geoip['dns_servers']:
        resolver.nameservers = [server]
        try:
            result = await resolver.query(hostname, 'A')
            ip = result[0].host if result else None
            if ip:
                cache[hostname] = ip
                dns_cache[hostname] = ip
                await save_dns_cache(config, dns_cache)
                return ip
        except aiodns.error.DNSError as e:
            logger.debug(f"DNS 解析失败 {hostname} 使用 {server}: {e}")
            async with aiofiles.open(config.dns_failed_log, 'a', encoding='utf-8') as f:
                await f.write(f"[{datetime.now(timezone.utc)}] Failed to resolve {hostname} with {server}: {e}\n")
        except Exception as e:
            logger.debug(f"解析 {hostname} 时发生意外错误 使用 {server}: {e}")
    try:
        ip = socket.gethostbyname(hostname)
        cache[hostname] = ip
        dns_cache[hostname] = ip
        await save_dns_cache(config, dns_cache)
        return ip
    except socket.gaierror:
        logger.debug(f"同步 DNS 解析失败 {hostname}")
        async with aiofiles.open(config.dns_failed_log, 'a', encoding='utf-8') as f:
            await f.write(f"[{datetime.now(timezone.utc)}] Failed to resolve {hostname} with socket: gaierror\n")
        return None

async def get_country_code_from_ip(ip: str, config: CrawlerConfig) -> str:
    """从 IP 地址获取国家代码，带缓存"""
    cache = TTLCache(maxsize=config.geoip['cache_size'], ttl=86400)
    geoip_cache = await load_geoip_cache(config)
    cache.update(geoip_cache)
    if ip in cache:
        return cache[ip]
    try:
        with geoip2.database.Reader(config.geoip['database_path']) as reader:
            response = reader.country(ip)
            country_code = response.country.iso_code or config.geoip['default_country']
            cache[ip] = country_code
            geoip_cache[ip] = country_code
            await save_geoip_cache(config, geoip_cache)
            return country_code
    except geoip2.errors.AddressNotFoundError:
        cache[ip] = config.geoip['default_country']
        geoip_cache[ip] = config.geoip['default_country']
        await save_geoip_cache(config, geoip_cache)
        return config.geoip['default_country']
    except Exception as e:
        logger.debug(f"查询 GeoIP 失败 {ip}: {e}")
        cache[ip] = config.geoip['default_country']
        geoip_cache[ip] = config.geoip['default_country']
        await save_geoip_cache(config, geoip_cache)
        return config.geoip['default_country']

async def rename_and_deduplicate_by_geo(nodes: Set[str], config: CrawlerConfig) -> Set[str]:
    """根据地理位置重命名和去重节点，优化 path 中的 IP 处理"""
    if not config.geoip.get('enable_geo_rename', False):
        logger.info("GeoIP 命名和去重功能未启用。")
        return nodes
    geoip_db_path = config.geoip.get('database_path')
    if not os.path.exists(geoip_db_path):
        logger.error(f"GeoIP 数据库文件 '{geoip_db_path}' 不存在，无法进行地理位置命名。")
        return nodes
    logger.info(f"开始 GeoIP 命名和去重，使用数据库: {geoip_db_path}")
    node_details = []
    ip_lookup_tasks = []
    dns_failed = 0
    semaphore = asyncio.Semaphore(config.concurrent_requests_limit)
    async def resolve_with_semaphore(server):
        async with semaphore:
            return await resolve_hostname_async(server, config)
    for node_url in nodes:
        info = parse_node_url_to_info(node_url, config)
        if info and info.get('server'):
            server = info['path_ip'] or info['server']
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country'], 'latency': None})
            ip_lookup_tasks.append(resolve_with_semaphore(server))
        else:
            logger.debug(f"无法解析节点服务器信息: {node_url[:50]}...")
            node_details.append({'original_url': node_url, 'info': info, 'ip': None, 'country': config.geoip['default_country'], 'latency': None})
    logger.info(f"开始并发解析 {len(ip_lookup_tasks)} 个域名/IP。")
    resolved_ips = await asyncio.gather(*ip_lookup_tasks, return_exceptions=True)
    for i, ip_result in enumerate(resolved_ips):
        if not isinstance(ip_result, Exception) and ip_result:
            node_details[i]['ip'] = ip_result
        else:
            dns_failed += 1
            logger.debug(f"解析 {node_details[i]['info'].get('server', 'N/A')} 失败: {ip_result}")
    geoip_tasks = []
    for detail in node_details:
        if detail['ip']:
            geoip_tasks.append(get_country_code_from_ip(detail['ip'], config))
        else:
            geoip_tasks.append(asyncio.sleep(0, result=config.geoip['default_country']))
    logger.info(f"开始并发查询 {len(geoip_tasks)} 个IP的地理位置。")
    country_codes = await asyncio.gather(*geoip_tasks)
    geoip_failed = 0
    for i, country_code in enumerate(country_codes):
        if country_code == config.geoip['default_country']:
            geoip_failed += 1
        node_details[i]['country'] = country_code
        if config.node_test['enable'] and node_details[i]['info']:
            node_details[i]['latency'] = await test_node_latency(node_details[i]['original_url'], config)
        await log_node_details(node_details[i]['original_url'], node_details[i]['ip'], country_code, config, node_details[i]['latency'])
    grouped_nodes: Dict[str, List[Dict]] = defaultdict(list)
    seen_unique_identifiers = set()
    for detail in node_details:
        info = detail['info']
        if not info:
            continue
        protocol = info.get('protocol', '')
        server = info.get('path_ip') or info.get('server', '')
        port = str(info.get('path_port') or info.get('port', ''))
        auth_id = ''
        if not config.geoip['strict_dedup']:
            if protocol in ['vmess', 'vless', 'tuic']:
                auth_id = info.get('id', info.get('uuid', '')).lower()
            elif protocol == 'trojan':
                auth_id = info.get('password', '').lower()
            elif protocol == 'ss':
                auth_id = f"{info.get('cipher', '')}:{info.get('password', '').lower()}"
            elif protocol == 'ssr':
                auth_id = f"{info.get('method', '')}:{info.get('protocol', '')}:{info.get('obfs', '')}:{info.get('password', '').lower()}"
            elif protocol == 'hysteria2':
                auth_id = info.get('auth_str', info.get('password', '')).lower()
        unique_key = f"{protocol}:{server}:{port}:{auth_id}"
        unique_identifier = hashlib.sha256(unique_key.encode('utf-8')).hexdigest()
        detail['unique_identifier'] = unique_identifier
        grouped_nodes[detail['country']].append(detail)
    final_renamed_nodes = set()
    for country_code, details_list in sorted(grouped_nodes.items()):
        details_list.sort(key=lambda x: hashlib.sha256(x['original_url'].encode()).hexdigest())
        counter = 0
        for detail in details_list:
            if detail['unique_identifier'] not in seen_unique_identifiers:
                if config.node_test['enable'] and detail['latency'] is not None and detail['latency'] > config.node_test['latency_threshold']:
                    logger.debug(f"节点 {detail['original_url'][:50]}... 延迟 {detail['latency']:.2f}ms 超出阈值，跳过")
                    continue
                counter += 1
                new_remark = f"{country_code}_{counter:03d}"
                updated_node_url = update_node_remark(detail['original_url'], new_remark)
                final_renamed_nodes.add(updated_node_url)
                seen_unique_identifiers.add(detail['unique_identifier'])
            else:
                for orig_detail in [d for group in grouped_nodes.values() for d in group]:
                    if orig_detail['unique_identifier'] == detail['unique_identifier'] and orig_detail['original_url'] != detail['original_url']:
                        if config.node_test['enable'] and detail['latency'] is not None and orig_detail['latency'] is not None:
                            if detail['latency'] < orig_detail['latency'] and detail['latency'] <= config.node_test['latency_threshold']:
                                final_renamed_nodes.remove(update_node_remark(orig_detail['original_url'], orig_detail['info']['name']))
                                counter += 1
                                new_remark = f"{country_code}_{counter:03d}"
                                updated_node_url = update_node_remark(detail['original_url'], new_remark)
                                final_renamed_nodes.add(updated_node_url)
                                seen_unique_identifiers.add(detail['unique_identifier'])
                                await log_duplicate_node(detail['original_url'], orig_detail['original_url'], detail['unique_identifier'], config, detail['latency'], orig_detail['latency'])
                                break
                        else:
                            await log_duplicate_node(detail['original_url'], orig_detail['original_url'], detail['unique_identifier'], config)
                            break
                logger.debug(f"发现功能性重复节点，跳过: {detail['original_url'][:50]}...")
    logger.info(f"GeoIP 命名和去重完成，得到 {len(final_renamed_nodes)} 个唯一节点，DNS 解析失败 {dns_failed} 次，GeoIP 查询失败 {geoip_failed} 次")
    return final_renamed_nodes
