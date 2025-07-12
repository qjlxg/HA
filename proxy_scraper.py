import asyncio
import logging
import base64
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any
import httpx
import aiofiles
import yaml
from bs4 import BeautifulSoup
from deduplicate import rename_and_deduplicate_by_geo  # 绝对导入

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def fetch_url(client: httpx.AsyncClient, url: str, cache: Dict[str, str]) -> str:
    """异步获取网页内容"""
    if url in cache:
        logger.debug(f"从缓存获取 URL: {url}")
        return cache[url]
    try:
        response = await client.get(url, timeout=10.0)
        response.raise_for_status()
        content = response.text
        cache[url] = content
        return content
    except Exception as e:
        logger.error(f"获取 URL 失败: {url}, 错误: {e}")
        return ""

def decode_base64_recursive(b64: str) -> str:
    """递归解码 Base64 字符串"""
    try:
        decoded = base64.b64decode(b64 + '==').decode('utf-8', errors='ignore')
        try:
            json.loads(decoded)
            return decoded
        except json.JSONDecodeError:
            return decode_base64_recursive(decoded)
    except Exception:
        return ""

def standardize_node_url(node_url: str) -> str:
    """标准化节点链接，确保一致性"""
    if not isinstance(node_url, str):
        return ""
    try:
        parsed = urlparse(node_url)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted([(k, v) for k, values in query_params.items() for v in values])
            encoded_query = urlencode(sorted_params, doseq=True)
            parsed = parsed._replace(query=encoded_query)
        if node_url.lower().startswith("vmess://"):
            try:
                b64_content = parsed.netloc
                decoded = decode_base64_recursive(b64_content)
                if decoded:
                    vmess_json = json.loads(decoded)
                    sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                    normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                    normalized_b64_clean = normalized_b64.replace('\n', '').replace('\r', '')
                    return f"vmess://{normalized_b64_clean}"
            except Exception as e:
                logger.debug(f"标准化 VMess URL 失败: {e}, url: {node_url}")
        elif node_url.lower().startswith("ssr://"):
            try:
                decoded_ssr = decode_base64_recursive(parsed.netloc)
                if decoded_ssr:
                    parts = decoded_ssr.split(':')
                    if len(parts) >= 6:
                        password_b64 = parts[5].split('/?')[0].split('/#')[0]
                        base64.urlsafe_b64decode(password_b64 + '==')
                        query_str = decoded_ssr.split('/?', 1)[1].split('/#')[0] if '/?' in decoded_ssr else ''
                        query_params = parse_qs(query_str)
                        sorted_params = sorted([(k, v[0]) for k, v in query_params.items() if v], key=lambda x: x[0])
                        encoded_query = urlencode(sorted_params)
                        core_parts = parts[:5] + [password_b64]
                        ssr_base = ':'.join(core_parts)
                        if encoded_query:
                            ssr_base += f"/?{encoded_query}"
                        normalized_b64 = base64.urlsafe_b64encode(ssr_base.encode()).decode().rstrip('=')
                        normalized_b64_clean = normalized_b64.replace('\n', '').replace('\r', '')
                        return f"ssr://{normalized_b64_clean}" + (f"#{parsed.fragment}" if parsed.fragment else "")
            except Exception as e:
                logger.debug(f"标准化 SSR URL 失败: {e}, url: {node_url}")
        elif node_url.lower().startswith("tuic://"):
            try:
                query_params = parse_qs(parsed.query)
                sorted_params = sorted([(k, v[0]) for k, v in query_params.items() if v], key=lambda x: x[0])
                encoded_query = urlencode(sorted_params)
                new_url = parsed._replace(query=encoded_query).geturl()
                return new_url.replace('\n', '').replace('\r', '')
            except Exception as e:
                logger.debug(f"标准化 TUIC URL 失败: {e}, url: {node_url}")
        return parsed.geturl().replace('\n', '').replace('\r', '')
    except ValueError as e:
        logger.warning(f"标准化节点URL时遇到无效格式错误: {e} - URL: {node_url}")
        return node_url.replace('\n', '').replace('\r', '')

def update_node_remark(node_url: str, new_remark: str) -> str:
    """更新节点 URL 中的备注字段"""
    parsed = urlparse(node_url)
    scheme = parsed.scheme.lower()
    if scheme == "vmess":
        try:
            b64_content = parsed.netloc
            decoded = decode_base64_recursive(b64_content)
            if decoded:
                vmess_json = json.loads(decoded)
                vmess_json['ps'] = new_remark
                sorted_vmess = dict(sorted(vmess_json.items(), key=lambda item: str(item[0])))
                normalized_b64 = base64.b64encode(json.dumps(sorted_vmess, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                normalized_b64_clean = normalized_b64.replace('\n', '').replace('\r', '')
                return f"vmess://{normalized_b64_clean}"
        except Exception as e:
            logger.debug(f"更新 VMess 备注失败: {e} - {node_url}")
            return node_url
    elif scheme in ["vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]:
        new_parsed = parsed._replace(fragment=new_remark)
        return new_parsed.geturl().replace('\n', '').replace('\r', '')
    return node_url

async def load_sources(source_file: str = 'data/sources.list') -> List[str]:
    """加载源 URL 列表"""
    try:
        async with aiofiles.open(source_file, mode='r', encoding='utf-8') as f:
            sources = [line.strip() for line in await f.readlines() if line.strip() and not line.startswith('#')]
        logger.info(f"加载了 {len(sources)} 个源")
        return sources
    except Exception as e:
        logger.error(f"加载源文件失败: {e}")
        return []

async def scrape_nodes(source_urls: List[str]) -> List[str]:
    """从源 URL 爬取节点"""
    nodes = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        cache = {}
        for url in source_urls:
            content = await fetch_url(client, url, cache)
            if content:
                soup = BeautifulSoup(content, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith(('vmess://', 'ssr://', 'trojan://', 'vless://', 'ss://', 'hysteria2://', 'tuic://')):
                        nodes.append(standardize_node_url(href))
                for line in content.splitlines():
                    if line.startswith(('vmess://', 'ssr://', 'trojan://', 'vless://', 'ss://', 'hysteria2://', 'tuic://')):
                        nodes.append(standardize_node_url(line.strip()))
        logger.info(f"从 {len(source_urls)} 个源中爬取到 {len(nodes)} 个节点")
    return nodes

async def save_nodes(nodes: List[str], output_file: str = 'data/all_nodes.txt'):
    """保存节点到文件"""
    async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
        for node in nodes:
            await f.write(node + '\n')
    logger.info(f"已保存 {len(nodes)} 个节点到 {output_file}")

async def generate_clash_config(nodes: List[str], output_file: str = 'data/clash_config.yaml'):
    """生成 Clash 配置文件"""
    clash_config = {
        'proxies': [],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': []}]
    }
    for i, node in enumerate(nodes):
        proxy_name = f"Proxy-{i}"
        clash_config['proxies'].append({'name': proxy_name, 'type': node.split('://')[0], 'url': node})
        clash_config['proxy-groups'][0]['proxies'].append(proxy_name)
    async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
        await f.write(yaml.dump(clash_config, allow_unicode=True))
    logger.info(f"已生成 Clash 配置文件: {output_file}")

async def main():
    """主函数"""
    os.makedirs('data', exist_ok=True)
    sources = await load_sources()
    if not sources:
        logger.error("无有效源，退出")
        return
    nodes = await scrape_nodes(sources)
    if not nodes:
        logger.error("未爬取到节点，退出")
        return
    deduplicated_nodes = await rename_and_deduplicate_by_geo(nodes)
    await save_nodes(deduplicated_nodes)
    await generate_clash_config(deduplicated_nodes)

if __name__ == "__main__":
    asyncio.run(main())
