import asyncio
import base64
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import aiohttp
import yaml
from loguru import logger

class Source:
    def __init__(self, line: str):
        self.is_date = line.startswith("+date")
        self.url = line[6:] if self.is_date else line
        self.nodes = []

    def get_url(self, date: str = None):
        if not self.is_date:
            return self.url
        return self.url.replace("%Y%m%d", date).replace("%Y/%m/%d", date[:4] + "/" + date[4:6] + "/" + date[6:])

    @staticmethod
    async def fetch_url(url: str, session: aiohttp.ClientSession, exc_queue: asyncio.Queue):
        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                return await response.text()
        except Exception as e:
            await exc_queue.put(f"Fetch failed for {url}: {str(e)}")
            return None

    @staticmethod
    def load_url(url: str, exc_queue: asyncio.Queue):
        try:
            if url.startswith(("vmess://", "vless://", "ss://", "ssr://", "trojan://", "hysteria2://")):
                return Node(url)
        except Exception as e:
            exc_queue.put_nowait(f"Invalid node {url}: {str(e)}")
        return None

    async def parse(self, date: str, session: aiohttp.ClientSession, exc_queue: asyncio.Queue):
        url = self.get_url(date)
        text = await self.fetch_url(url, session, exc_queue)
        if not text:
            return

        try:
            if url.endswith(".txt"):
                if "://" not in text:
                    text = base64.b64decode(text).decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if line and (node := self.load_url(line, exc_queue)):
                        self.nodes.append(node)
            elif url.endswith((".yaml", ".yml")):
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for proxy in data["proxies"]:
                        if isinstance(proxy, dict) and (url := proxy.get("url") or proxy.get("link")):
                            if node := self.load_url(url, exc_queue):
                                self.nodes.append(node)
            elif "://" not in text:
                data = json.loads(base64.b64decode(text).decode("utf-8", errors="ignore"))
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict) and (url := item.get("url") or item.get("link")):
                                    if node := self.load_url(url, exc_queue):
                                        self.nodes.append(node)
        except Exception as e:
            await exc_queue.put(f"Parse failed for {url}: {str(e)}")

class Node:
    def __init__(self, url: str):
        self.url = url
        self.protocol = url.split("://")[0]
        self.name = self.generate_name()

    def generate_name(self):
        try:
            if self.protocol == "vmess":
                config = json.loads(base64.b64decode(self.url[8:]).decode("utf-8"))
                return f"{config.get('ps', 'unnamed')} ({self.protocol})"
            elif self.protocol in ("vless", "trojan", "hysteria2"):
                match = re.match(r"^(vless|trojan|hysteria2)://([^\s@]+)@([^\s:]+):(\d+)", self.url)
                if match:
                    return f"{match.group(3)}:{match.group(4)} ({self.protocol})"
            elif self.protocol in ("ss", "ssr"):
                return f"shadowsocks ({self.protocol})"
            return f"node ({self.protocol})"
        except Exception:
            return f"unnamed ({self.protocol})"

    def to_yaml(self):
        try:
            if self.protocol == "vmess":
                config = json.loads(base64.b64decode(self.url[8:]).decode("utf-8"))
                return {
                    "name": self.name,
                    "type": "vmess",
                    "server": config.get("add"),
                    "port": config.get("port"),
                    "uuid": config.get("id"),
                    "alterId": config.get("aid", 0),
                    "cipher": config.get("scy", "auto"),
                    "network": config.get("net", "tcp"),
                    "tls": config.get("tls") == "tls",
                    "sni": config.get("sni", ""),
                    "ws-opts": {"path": config.get("path", "/")} if config.get("net") == "ws" else {}
                }
            elif self.protocol in ("vless", "trojan"):
                match = re.match(r"^(vless|trojan)://([^\s@]+)@([^\s:]+):(\d+)\?([^#]+)#(.+)", self.url)
                if match:
                    params = dict(p.split("=") for p in match.group(5).split("&"))
                    return {
                        "name": self.name,
                        "type": self.protocol,
                        "server": match.group(3),
                        "port": int(match.group(4)),
                        "uuid": match.group(2),
                        "tls": params.get("security") == "tls",
                        "sni": params.get("sni", ""),
                        "network": params.get("type", "tcp"),
                        "ws-opts": {"path": params.get("path", "/")} if params.get("type") == "ws" else {}
                    }
            elif self.protocol == "hysteria2":
                match = re.match(r"^hysteria2://([^\s@]+)@([^\s:]+):(\d+)\?([^#]+)#(.+)", self.url)
                if match:
                    params = dict(p.split("=") for p in match.group(4).split("&"))
                    return {
                        "name": self.name,
                        "type": "hysteria2",
                        "server": match.group(2),
                        "port": int(match.group(3)),
                        "password": match.group(1),
                        "sni": params.get("sni", ""),
                        "obfs": params.get("obfs"),
                        "obfs-password": params.get("obfs-password")
                    }
            elif self.protocol in ("ss", "ssr"):
                return {
                    "name": self.name,
                    "type": self.protocol,
                    "server": "unknown",
                    "port": 0,
                    "cipher": "unknown",
                    "password": "unknown"
                }
        except Exception as e:
            logger.error(f"Failed to convert node {self.url} to YAML: {str(e)}")
        return None

def load_sources():
    sources = []
    file_path = 'sources.list'
    if not os.path.exists(file_path):
        logger.error(f"{file_path} not found in {os.getcwd()}")
        raise FileNotFoundError(f"{file_path} not found")
    logger.info(f"Loading sources from {file_path}")
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                sources.append(Source(line))
                logger.debug(f"Loaded source: {line}")
    logger.info(f"Loaded {len(sources)} sources")
    return sources

async def main():
    logger.add("fetch.log", rotation="1 MB")
    date = time.strftime("%Y%m%d")
    sources = load_sources()
    logger.info(f"Loaded {len(sources)} sources")

    exc_queue = asyncio.Queue()
    async with aiohttp.ClientSession() as session:
        tasks = [source.parse(date, session, exc_queue) for source in sources]
        await asyncio.gather(*tasks)

    nodes = []
    for source in sources:
        nodes.extend(source.nodes)
    nodes = list(dict.fromkeys(nodes))  # Remove duplicates
    logger.info(f"Collected {len(nodes)} unique nodes")

    Path("output").mkdir(exist_ok=True)
    part_size = 100 * 1024 * 1024  # 100MB
    part_index = 1
    current_size = 0
    current_nodes = []

    for node in nodes:
        node_str = node.url + "\n"
        current_size += len(node_str.encode("utf-8"))
        current_nodes.append(node)

        if current_size >= part_size:
            with open(f"output/nodes_part{part_index}.txt", "w", encoding="utf-8") as f:
                for n in current_nodes:
                    f.write(n.url + "\n")
            current_nodes = []
            current_size = 0
            part_index += 1

    if current_nodes:
        with open(f"output/nodes_part{part_index}.txt", "w", encoding="utf-8") as f:
            for n in current_nodes:
                f.write(n.url + "\n")

    yaml_nodes = [node.to_yaml() for node in nodes if node.to_yaml()]
    with open("output/list.yml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": yaml_nodes}, f, allow_unicode=True)

    with open("node_counts.csv", "w", encoding="utf-8") as f:
        f.write("Source,NodeCount\n")
        for source in sources:
            f.write(f"{source.url},{len(source.nodes)}\n")

    with open("errors.log", "w", encoding="utf-8") as f:
        while not exc_queue.empty():
            f.write(exc_queue.get_nowait() + "\n")

if __name__ == "__main__":
    asyncio.run(main())
