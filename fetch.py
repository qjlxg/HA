
import asyncio
import base64
import json
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import aiohttp
import yaml
from loguru import logger

logger.add("fetch.log", rotation="1 MB", retention="7 days", level="INFO")
exc_queue = []

class Node:
    def __init__(self, url, type, data):
        self.url = url
        self.type = type
        self.data = data

    @classmethod
    def load_url(cls, url, exc_queue):
        try:
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme.lower()
            if scheme not in {'vmess', 'vless', 'ss', 'ssr', 'trojan', 'hysteria2'}:
                return None
            data = {}
            if scheme == 'vmess':
                info = base64.urlsafe_b64decode(url.split('://')[1]).decode()
                data = json.loads(info)
                data.update({
                    'server': data['add'],
                    'port': int(data['port']),
                    'uuid': data['id'],
                    'name': data.get('ps', '')
                })
            elif scheme == 'vless':
                params = urllib.parse.parse_qs(parts.query)
                data = {
                    'server': parts.netloc.split('@')[1].split(':')[0],
                    'port': int(parts.netloc.split(':')[1]),
                    'uuid': parts.netloc.split('@')[0],
                    'name': parts.fragment,
                    'type': params.get('type', ['tcp'])[0],
                    'security': params.get('security', ['none'])[0]
                }
            elif scheme == 'trojan':
                params = urllib.parse.parse_qs(parts.query)
                data = {
                    'server': parts.netloc.split('@')[1].split(':')[0],
                    'port': int(parts.netloc.split(':')[1]),
                    'password': parts.netloc.split('@')[0],
                    'name': parts.fragment,
                    'sni': params.get('sni', [''])[0]
                }
            elif scheme == 'ss':
                auth, host = parts.netloc.split('@')
                cipher, password = base64.urlsafe_b64decode(auth + '==').decode().split(':')
                data = {
                    'server': host.split(':')[0],
                    'port': int(host.split(':')[1]),
                    'cipher': cipher,
                    'password': password,
                    'name': parts.fragment
                }
            elif scheme == 'ssr':
                info = base64.urlsafe_b64decode(url.split('://')[1]).decode()
                # Simplified SSR parsing (adjust as needed)
                data = {'server': '', 'port': 0, 'password': '', 'name': parts.fragment}
            elif scheme == 'hysteria2':
                params = urllib.parse.parse_qs(parts.query)
                data = {
                    'server': parts.netloc.split('@')[1].split(':')[0],
                    'port': int(parts.netloc.split(':')[1]),
                    'password': parts.netloc.split('@')[0],
                    'name': parts.fragment,
                    'sni': params.get('sni', [''])[0]
                }
            return cls(url, scheme, data)
        except Exception as e:
            exc_queue.append(f"Invalid {scheme}:// format: {str(e)}")
            return None

    def gen_key(self):
        data = self.data
        if self.type in {'vmess', 'vless', 'trojan', 'hysteria2'}:
            return (self.type, data['server'], data['port'], data.get('uuid') or data.get('password'))
        elif self.type in {'ss', 'ssr'}:
            return (self.type, data['server'], data['port'], data['cipher'], data['password'])
        return (self.type, data['server'], data['port'])

    def to_yaml(self):
        data = self.data.copy()
        data['name'] = data.get('name', f"{self.type}-{data['server']}:{data['port']}")
        return {'name': data['name'], **data}

class Source:
    def __init__(self, url):
        self.url = url
        self.nodes = []

    async def fetch(self, session):
        try:
            async with session.get(self.url, timeout=10) as resp:
                if resp.status != 200:
                    exc_queue.append(f"Failed to fetch {self.url}: {resp.status}")
                    return
                return await resp.text()
        except Exception as e:
            exc_queue.append(f"Error fetching {self.url}: {str(e)}")
            return None

    def parse(self, text):
        nodes = []
        if not text:
            return nodes
        # Try Base64 decoding
        try:
            decoded = base64.urlsafe_b64decode(text.strip() + '==').decode('utf-8')
            for line in decoded.split('\n'):
                if line.startswith(('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://')):
                    node = Node.load_url(line.strip(), exc_queue)
                    if node:
                        nodes.append(node)
            if nodes:
                return nodes
        except:
            pass
        # Try YAML parsing
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and 'proxies' in data:
                for proxy in data['proxies']:
                    url = proxy.get('url') or proxy.get('link')
                    if url and url.startswith(('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://')):
                        node = Node.load_url(url, exc_queue)
                        if node:
                            nodes.append(node)
            return nodes
        except yaml.YAMLError:
            pass
        # Try JSON parsing
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    url = item.get('url') or item.get('link')
                    if url and url.startswith(('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://')):
                        node = Node.load_url(url, exc_queue)
                        if node:
                            nodes.append(node)
            return nodes
        except json.JSONDecodeError:
            pass
        # Try plain text lines
        for line in text.strip().split('\n'):
            if line.startswith(('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://')):
                node = Node.load_url(line.strip(), exc_queue)
                if node:
                    nodes.append(node)
        return nodes

def load_sources():
    sources = []
    with open('sources.list', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('+date'):
                date = datetime.now().strftime('%Y%m%d')
                url = line.replace('+date', '').strip().replace('%Y%m%d', date)
                sources.append(Source(url))
    return sources

async def main():
    sources = load_sources()
    logger.info(f"Loaded {len(sources)} sources")
    nodes = {}
    async with aiohttp.ClientSession() as session:
        with ThreadPoolExecutor(max_workers=20) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(executor, lambda s=src: src.parse(src.fetch(session).result())) for src in sources]
            results = await asyncio.gather(*[loop.create_task(t) for t in tasks], return_exceptions=True)
            for src, result in zip(sources, results):
                if isinstance(result, Exception):
                    exc_queue.append(f"Error processing {src.url}: {str(result)}")
                    continue
                for node in result:
                    if node:
                        nodes[node.gen_key()] = node
                src.nodes = result
    # Save raw nodes
    max_size = 100 * 1024 * 1024  # 100MB
    part = 1
    size = 0
    f = open(f'nodes_part{part}.txt', 'w', encoding='utf-8')
    for node in nodes.values():
        line = node.url + '\n'
        size += len(line.encode('utf-8'))
        if size > max_size:
            f.close()
            part += 1
            size = 0
            f = open(f'nodes_part{part}.txt', 'w', encoding='utf-8')
        f.write(line)
    f.close()
    # Save YAML
    with open('list.yml', 'w', encoding='utf-8') as f:
        yaml.safe_dump({'proxies': [node.to_yaml() for node in nodes.values()]}, f, allow_unicode=True)
    # Save node counts
    with open('node_counts.csv', 'w', encoding='utf-8') as f:
        f.write('Source,NodeCount\n')
        for src in sources:
            f.write(f'{src.url},{len(src.nodes)}\n')
    # Save errors
    with open('errors.log', 'w', encoding='utf-8') as f:
        for error in exc_queue:
            f.write(f'{error}\n')
    logger.info(f"Collected {len(nodes)} unique nodes")

if __name__ == '__main__':
    asyncio.run(main())
