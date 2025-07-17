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
import os

class Source:
    def __init__(self, line: str):
        self.is_date = line.startswith("+date")
        self.url = line[6:] if self.is_date else line
        self.nodes = []
        self.raw_content = None # To store raw fetched content for debugging/analysis

    def get_url(self, date: str = None):
        if not self.is_date:
            return self.url
        return self.url.replace("%Y%m%d", date).replace("%Y/%m/%d", date[:4] + "/" + date[4:6] + "/" + date[6:])

    @staticmethod
    async def fetch_url(url: str, session: aiohttp.ClientSession, exc_queue: asyncio.Queue):
        try:
            logger.debug(f"Fetching URL: {url}")
            async with session.get(url, timeout=30) as response: # Increased timeout
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                text = await response.text()
                logger.debug(f"Successfully fetched {len(text)} bytes from {url}")
                return text
        except aiohttp.ClientError as e:
            await exc_queue.put(f"Network error fetching {url}: {str(e)}")
            logger.error(f"Network error fetching {url}: {e}")
            return None
        except asyncio.TimeoutError:
            await exc_queue.put(f"Timeout fetching {url}")
            logger.error(f"Timeout fetching {url}")
            return None
        except Exception as e:
            await exc_queue.put(f"Fetch failed for {url}: {str(e)}")
            logger.error(f"Fetch failed for {url}: {e}")
            return None

    @staticmethod
    def load_url_to_node(url: str, exc_queue: asyncio.Queue):
        try:
            if url.startswith(("vmess://", "vless://", "ss://", "ssr://", "trojan://", "hysteria2://")):
                return Node(url)
        except Exception as e:
            exc_queue.put_nowait(f"Invalid node URL {url}: {str(e)}")
            logger.warning(f"Invalid node URL {url}: {e}")
        return None

    async def parse(self, date: str, session: aiohttp.ClientSession, exc_queue: asyncio.Queue):
        url = self.get_url(date)
        text = await self.fetch_url(url, session, exc_queue)
        self.raw_content = text # Store raw content
        if not text:
            return

        try:
            # Attempt to decode Base64 if it doesn't look like a direct link list or YAML
            if "://" not in text and not (url.endswith((".yaml", ".yml"))):
                try:
                    decoded_text = base64.b64decode(text).decode("utf-8", errors="ignore")
                    text = decoded_text
                    logger.debug(f"Successfully Base64 decoded content from {url}")
                except (base64.binascii.Error, UnicodeDecodeError):
                    logger.debug(f"Content from {url} is not base64 encoded, processing as plain text/JSON.")
                    pass # Not base64, proceed to other parsers

            if url.endswith((".yaml", ".yml")):
                logger.debug(f"Parsing YAML from {url}")
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for proxy in data["proxies"]:
                        if isinstance(proxy, dict) and (node_url := proxy.get("url") or proxy.get("link")):
                            if node := self.load_url_to_node(node_url, exc_queue):
                                self.nodes.append(node)
                elif isinstance(data, list): # Some YAML files might be just a list of proxies
                     for proxy_config in data:
                        # Attempt to reconstruct URL for generic YAML proxy config if possible
                        # This is a simplified example, a real parser would need more logic for different types
                        if isinstance(proxy_config, dict) and 'type' in proxy_config and 'server' in proxy_config:
                            # This part would need extensive logic to convert dict to URL
                            # For now, let's just skip unless it explicitly has a 'url' or 'link' field
                            if (node_url := proxy_config.get("url") or proxy_config.get("link")):
                                if node := self.load_url_to_node(node_url, exc_queue):
                                    self.nodes.append(node)
                else:
                    logger.warning(f"YAML from {url} has unexpected structure.")

            elif text.strip().startswith(("{", "[")): # Likely JSON
                logger.debug(f"Parsing JSON from {url}")
                data = json.loads(text)
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict) and (node_url := item.get("url") or item.get("link")):
                                    if node := self.load_url_to_node(node_url, exc_queue):
                                        self.nodes.append(node)
                elif isinstance(data, list): # Directly a list of nodes/objects
                    for item in data:
                        if isinstance(item, dict) and (node_url := item.get("url") or item.get("link")):
                            if node := self.load_url_to_node(node_url, exc_queue):
                                self.nodes.append(node)
                else:
                    logger.warning(f"JSON from {url} has unexpected structure.")

            else: # Treat as plain text, line by line
                logger.debug(f"Parsing plain text/links from {url}")
                for line in text.splitlines():
                    line = line.strip()
                    if line and (node := self.load_url_to_node(line, exc_queue)):
                        self.nodes.append(node)

        except yaml.YAMLError as e:
            await exc_queue.put(f"YAML parsing failed for {url}: {str(e)}")
            logger.error(f"YAML parsing failed for {url}: {e}")
        except json.JSONDecodeError as e:
            await exc_queue.put(f"JSON parsing failed for {url}: {str(e)}")
            logger.error(f"JSON parsing failed for {url}: {e}")
        except Exception as e:
            await exc_queue.put(f"Generic parsing failed for {url}: {type(e).__name__}: {str(e)}")
            logger.error(f"Generic parsing failed for {url}: {e}", exc_info=True)


class Node:
    def __init__(self, url: str):
        self.url = url
        self.protocol = url.split("://")[0]
        self.name = self.generate_name()

    def __hash__(self):
        return hash(self.url) # Use URL as hash for uniqueness

    def __eq__(self, other):
        return self.url == other.url

    def generate_name(self):
        try:
            if self.protocol == "vmess":
                config = json.loads(base64.b64decode(self.url[8:]).decode("utf-8"))
                return config.get('ps', f"vmess-{config.get('add', 'unnamed')}")
            elif self.protocol in ("vless", "trojan", "hysteria2"):
                # Extract part after last # for name, or hostname:port if no fragment
                parsed_url = re.match(r"^(vless|trojan|hysteria2)://(?:[^@]+@)?([^\s:]+):(\d+)(?:[^#]*)#?(.+)?", self.url)
                if parsed_url:
                    name_fragment = parsed_url.group(4)
                    if name_fragment:
                        return name_fragment # Use the fragment as name
                    else:
                        return f"{parsed_url.group(2)}:{parsed_url.group(3)} ({self.protocol})"
                return f"unnamed-{self.protocol}"
            elif self.protocol in ("ss", "ssr"):
                # SS/SSR names are typically after # or require more complex parsing
                match_name = re.search(r'#([^&]+)$', self.url)
                if match_name:
                    try:
                        return base64.urlsafe_b64decode(match_name.group(1) + '=' * (-len(match_name.group(1)) % 4)).decode('utf-8')
                    except Exception:
                        return match_name.group(1)
                return f"shadowsocks ({self.protocol})"
            return f"node ({self.protocol})"
        except Exception as e:
            logger.warning(f"Failed to generate name for {self.protocol} node: {self.url}. Error: {e}")
            return f"unnamed ({self.protocol})"

    def to_yaml(self):
        # Simplified conversion to YAML suitable for Clash/Sing-box (requires more detailed parsing for full compatibility)
        config = {"name": self.name, "type": self.protocol}

        try:
            if self.protocol == "vmess":
                data = json.loads(base64.b64decode(self.url[8:]).decode("utf-8"))
                config.update({
                    "server": data.get("add"),
                    "port": int(data.get("port")),
                    "uuid": data.get("id"),
                    "alterId": int(data.get("aid", 0)),
                    "cipher": data.get("scy", "auto"),
                    "network": data.get("net", "tcp"),
                    "tls": data.get("tls") == "tls",
                    "udp": True # Default to true for better compatibility
                })
                if config["network"] == "ws":
                    config["ws-opts"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", data.get("add"))}}
                if config["network"] == "grpc":
                    config["grpc-opts"] = {"grpc-service-name": data.get("path", "")} # path is often serviceName in vmess grpc
                if data.get("sni"):
                    config["sni"] = data["sni"]

            elif self.protocol in ("vless", "trojan"):
                # Regex to parse vless/trojan: //uuid@server:port?params#name
                match = re.match(r"^(vless|trojan)://([^@]+)@([^\s:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?", self.url)
                if not match: raise ValueError("Invalid VLESS/Trojan URL format")
                _, user_id, server, port_str, query_params_str, name_fragment = match.groups()
                config.update({
                    "server": server,
                    "port": int(port_str),
                    "password": user_id if self.protocol == "trojan" else None,
                    "uuid": user_id if self.protocol == "vless" else None,
                    "udp": True
                })

                if query_params_str:
                    params = dict(p.split("=") for p in query_params_str.split("&"))
                    config["network"] = params.get("type", "tcp")
                    if params.get("security") == "tls":
                        config["tls"] = True
                        config["sni"] = params.get("sni", server)
                        if params.get("alpn"):
                            config["alpn"] = params["alpn"].split(',')
                        if params.get("fp"):
                            config["fingerprint"] = params["fp"]
                        config["skip-cert-verify"] = params.get("allowInsecure") == "1"

                    if config["network"] == "ws":
                        config["ws-opts"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", server)}}
                    elif config["network"] == "grpc":
                        config["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}

            elif self.protocol == "hysteria2":
                # hysteria2://password@server:port?params#name
                match = re.match(r"^hysteria2://([^@]+)@([^\s:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?", self.url)
                if not match: raise ValueError("Invalid Hysteria2 URL format")
                _, password, server, port_str, query_params_str, name_fragment = match.groups()
                config.update({
                    "server": server,
                    "port": int(port_str),
                    "password": password,
                    "udp": True # Hysteria2 is UDP based
                })
                if query_params_str:
                    params = dict(p.split("=") for p in query_params_str.split("&"))
                    if params.get("sni"): config["sni"] = params["sni"]
                    if params.get("obfs"): config["obfs"] = params["obfs"]
                    if params.get("obfs-password"): config["obfs-password"] = params["obfs-password"]
                    if params.get("alpn"): config["alpn"] = params["alpn"].split(',')
                    if params.get("fastopen"): config["fast-open"] = params["fastopen"] == "1"
                    if params.get("insecure"): config["skip-cert-verify"] = params["insecure"] == "1"
                    if params.get("mptcp"): config["mptcp"] = params["mptcp"] == "1"
                    if params.get("up"): config["up"] = f"{params['up']}Mbps"
                    if params.get("down"): config["down"] = f"{params['down']}Mbps"
                    if params.get("recv_window"): config["recv-window"] = int(params["recv_window"])
                    if params.get("recv_window_conn"): config["recv-window-conn"] = int(params["recv_window_conn"])
                    if params.get("lazy"): config["lazy"] = params["lazy"] == "1"
                    if params.get("udptun"): config["udp-relay-mode"] = params["udptun"] # Clash specific

            elif self.protocol == "ss":
                # ss://method:password@server:port#name
                # ss://base64encoded_info@server:port#name
                parsed = re.match(r"ss://(?:([^@]+)@)?([^\s:]+):(\d+)(?:#(.+))?", self.url)
                if parsed:
                    auth_info, server, port_str, name_fragment = parsed.groups()
                    config.update({
                        "server": server,
                        "port": int(port_str),
                        "udp": True
                    })
                    if auth_info:
                        try: # Try decoding if it's base64 encoded auth
                            decoded_auth = base64.urlsafe_b64decode(auth_info + '=' * (-len(auth_info) % 4)).decode('utf-8')
                            method, password = decoded_auth.split(':', 1)
                            config["cipher"] = method
                            config["password"] = password
                        except Exception: # Not base64, assume method:password directly
                            if ':' in auth_info:
                                method, password = auth_info.split(':', 1)
                                config["cipher"] = method
                                config["password"] = password
                            else: # Just method, no password in auth part
                                config["cipher"] = auth_info
                                config["password"] = "" # Default to empty password
                    else: # No auth_info, try to get from userinfo if present
                         parsed_url = urlparse(self.url)
                         if parsed_url.username and parsed_url.password:
                             config["cipher"] = parsed_url.username
                             config["password"] = parsed_url.password
                else: raise ValueError("Invalid SS URL format")

            elif self.protocol == "ssr":
                # ssr://base64encoded_params
                decoded_params = base64.urlsafe_b64decode(self.url[6:] + '=' * (-len(self.url[6:]) % 4)).decode('utf-8')
                parts = decoded_params.split(':')
                if len(parts) >= 6:
                    server, port_str, protocol, method, obfs, password_encoded_fragment = parts[0:6]
                    password_encoded = password_encoded_fragment.split('/?')[0]
                    password = base64.urlsafe_b64decode(password_encoded + '=' * (-len(password_encoded) % 4)).decode('utf-8')

                    config.update({
                        "server": server,
                        "port": int(port_str),
                        "protocol": protocol,
                        "cipher": method,
                        "obfs": obfs,
                        "password": password,
                        "udp": True
                    })
                    # Parse additional parameters from fragment
                    if '/?' in decoded_params:
                        query_str = decoded_params.split('/?')[1]
                        params = dict(p.split('=') for p in query_str.split('&') if '=' in p)
                        if 'remarks' in params: config["name"] = base64.urlsafe_b64decode(params['remarks'] + '=' * (-len(params['remarks']) % 4)).decode('utf-8')
                        if 'protoparam' in params: config["protocol-param"] = base64.urlsafe_b64decode(params['protoparam'] + '=' * (-len(params['protoparam']) % 4)).decode('utf-8')
                        if 'obfsparam' in params: config["obfs-param"] = base64.urlsafe_b64decode(params['obfsparam'] + '=' * (-len(params['obfsparam']) % 4)).decode('utf-8')
                else: raise ValueError("Invalid SSR URL format")

            # Remove password field for VLESS as it uses UUID
            if self.protocol == "vless" and "password" in config:
                del config["password"]

            # Set a default name if still unnamed
            if not config.get("name"):
                config["name"] = self.name # Use the auto-generated name if original was empty

            return config

        except Exception as e:
            logger.error(f"Failed to convert node {self.url} to YAML: {type(e).__name__}: {e}", exc_info=True)
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
    logger.remove()
    logger.add(sys.stderr, level="INFO") # Log to stderr for GitHub Actions output
    logger.add("fetch.log", rotation="1 MB", level="DEBUG") # Detailed logs to file

    date = time.strftime("%Y%m%d")
    sources = load_sources()
    logger.info(f"Starting parsing for {len(sources)} sources...")

    exc_queue = asyncio.Queue()
    # Use a custom header for better request success rate
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [source.parse(date, session, exc_queue) for source in sources]
        await asyncio.gather(*tasks)

    all_nodes = []
    for source in sources:
        all_nodes.extend(source.nodes)
    
    # Use a set to remove duplicates based on Node's __hash__ and __eq__
    unique_nodes = list(dict.fromkeys(all_nodes))  
    logger.info(f"Collected {len(unique_nodes)} unique nodes")

    Path("output").mkdir(exist_ok=True)
    
    # Write all unique nodes to a single .txt file
    with open("output/all_nodes.txt", "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node.url + "\n")
    logger.info("All unique nodes written to output/all_nodes.txt")

    # Split nodes into multiple files if total size exceeds 100MB (adjusted to a more reasonable default for typical nodes)
    # This feature might be less critical for typical node counts.
    # Let's write the `nodes_partX.txt` files directly using the unique_nodes.
    # The previous `part_size` was 100MB which is very large for simple text links.
    # Re-evaluating this part for practical use: A single `all_nodes.txt` is often sufficient.
    # If splitting is truly desired based on file size, it needs careful implementation
    # to avoid creating too many tiny files or overcomplicating.
    # For now, let's keep it simple with `all_nodes.txt` and `list.yml`.
    
    yaml_nodes = [node.to_yaml() for node in unique_nodes if node.to_yaml()]
    # Ensure all names are unique for Clash/Singbox compatibility
    name_counts = {}
    for y_node in yaml_nodes:
        original_name = y_node["name"]
        count = name_counts.get(original_name, 0)
        if count > 0:
            y_node["name"] = f"{original_name} #{count + 1}"
        name_counts[original_name] = count + 1

    with open("output/list.yml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": yaml_nodes}, f, allow_unicode=True, sort_keys=False) # sort_keys=False to preserve order
    logger.info(f"Converted {len(yaml_nodes)} nodes to output/list.yml")


    with open("node_counts.csv", "w", encoding="utf-8") as f:
        f.write("Source,NodeCount\n")
        for source in sources:
            f.write(f"{source.url},{len(source.nodes)}\n")
    logger.info("Node counts written to node_counts.csv")

    errors_count = 0
    with open("errors.log", "w", encoding="utf-8") as f:
        while not exc_queue.empty():
            f.write(exc_queue.get_nowait() + "\n")
            errors_count += 1
    logger.info(f"Wrote {errors_count} errors to errors.log")

if __name__ == "__main__":
    asyncio.run(main())
