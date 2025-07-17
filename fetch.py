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
from urllib.parse import urlparse # Import urlparse for generic URL parsing
import sys # <-- **确保已添加此行**

class Source:
    def __init__(self, line: str):
        self.is_date = line.startswith("+date")
        self.url = line[6:] if self.is_date else line
        self.nodes = []
        self.raw_content = None # To store raw fetched content for debugging/analysis

    def get_url(self, date: str = None):
        if not self.is_date:
            return self.url
        # Replace date placeholders
        formatted_url = self.url.replace("%Y%m%d", date)
        if "%Y/%m/%d" in formatted_url:
            formatted_url = formatted_url.replace("%Y/%m/%d", date[:4] + "/" + date[4:6] + "/" + date[6:])
        elif "%Y-%m-%d" in formatted_url:
            formatted_url = formatted_url.replace("%Y-%m-%d", date[:4] + "-" + date[4:6] + "-" + date[6:])
        elif "%Y/%m/%d" in formatted_url:
            formatted_url = formatted_url.replace("%Y/%m/%d", date[:4] + "/" + date[4:6] + "/" + date[6:])
        # Telegram channel links often need special handling, but direct parsing might be limited
        # For 't.me/s/channelname/date.txt', aiohttp will likely fetch the Telegram HTML page,
        # which then needs to be scraped for content, which is beyond direct fetching.
        # The current script assumes a direct text/file link.
        # For Telegram 's/' links, they typically serve HTML content, not raw text.
        # This script's `fetch_url` will get the HTML. The `parse` method may fail
        # to find nodes within HTML unless specific scraping logic is added.
        # For now, it will attempt to parse, but likely produce errors for Telegram links.
        return formatted_url

    @staticmethod
    async def fetch_url(url: str, session: aiohttp.ClientSession, exc_queue: asyncio.Queue):
        try:
            logger.debug(f"Fetching URL: {url}")
            async with session.get(url, timeout=30) as response: # Increased timeout
                if response.status != 200:
                    # For Telegram 't.me/s/' links, status is usually 200 but content is HTML.
                    # We might want to check content-type or infer from URL.
                    logger.warning(f"HTTP Status {response.status} for {url}")
                    # If it's a Telegram link, and not a direct file, it's expected to be HTML.
                    # We don't want to raise an exception here for expected non-direct content.
                    if "t.me/s/" in url: # Heuristic for Telegram channel pages
                        text = await response.text()
                        if "tgme_page_extra" in text: # Common div in Telegram channel pages
                            logger.info(f"Detected Telegram channel page for {url}. Attempting to extract links from HTML.")
                            return text # Return HTML for potential scraping in parse()
                        else:
                            raise Exception(f"Unexpected content for Telegram link: HTTP {response.status}")
                    else:
                        raise Exception(f"HTTP {response.status}")
                
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type and "t.me/s/" not in url: # If it's unexpected HTML
                    logger.warning(f"Received HTML content for {url} (Content-Type: {content_type}), expected text/yaml/json. Attempting to parse anyway.")

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
            # Basic validation before creating a Node
            if re.match(r"^(vmess|vless|ss|ssr|trojan|hysteria2)://", url):
                return Node(url)
            else:
                raise ValueError("Unsupported protocol or invalid URL format")
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

        # --- Telegram Channel HTML Parsing (Specific for t.me/s/ links) ---
        if "t.me/s/" in url and "tgme_page_extra" in text:
            logger.info(f"Attempting to extract links from Telegram HTML for {url}")
            # Find all potential links that look like vmess/vless etc.
            # This is a basic regex, could be improved. Telegram often puts links in <pre> or <code> blocks.
            found_links = re.findall(r'(vmess|vless|ss|ssr|trojan|hysteria2)://[a-zA-Z0-9+/=%\-._~:@]+(?:#.+?)?', text)
            for link_match in found_links:
                full_link = link_match # The regex group will be the full link if it's the whole pattern
                if link_match.startswith(('vmess', 'vless', 'ss', 'ssr', 'trojan', 'hysteria2')):
                    # Re-find with the full protocol prefix to get the complete URL
                    full_match = re.search(r'(' + re.escape(link_match.split('://')[0]) + r'://[a-zA-Z0-9+/=%\-._~:@]+(?:#.+?)?)', text)
                    if full_match:
                        full_link = full_match.group(1)
                        if node := self.load_url_to_node(full_link, exc_queue):
                            self.nodes.append(node)
            if not found_links:
                logger.warning(f"No direct node links found in Telegram HTML for {url}.")
            return # HTML processed, do not try other parsers on HTML

        # --- Generic Content Parsing ---
        try:
            # Attempt to decode Base64 if it doesn't look like a direct link list or YAML/JSON
            if "://" not in text.splitlines()[0] and not (url.endswith((".yaml", ".yml", ".json"))) and not text.strip().startswith(("{", "[")):
                try:
                    decoded_text = base64.b64decode(text).decode("utf-8", errors="ignore")
                    text = decoded_text
                    logger.debug(f"Successfully Base64 decoded content from {url}")
                except (base64.binascii.Error, UnicodeDecodeError):
                    logger.debug(f"Content from {url} is not base64 encoded or invalid, processing as plain text/JSON.")
                    pass # Not base64, proceed to other parsers

            if url.endswith((".yaml", ".yml")):
                logger.debug(f"Parsing YAML from {url}")
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for proxy_config in data["proxies"]:
                        if isinstance(proxy_config, dict):
                            # Attempt to reconstruct a URI for common proxy types
                            node_url = None
                            if proxy_config.get("type") == "vmess":
                                # Minimal VMESS reconstruction for demonstration
                                # This is a simplification; a full implementation needs to handle all fields
                                try:
                                    vmess_obj = {
                                        "v": "2",
                                        "ps": proxy_config.get("name", "vmess-node"),
                                        "add": proxy_config["server"],
                                        "port": proxy_config["port"],
                                        "id": proxy_config["uuid"],
                                        "aid": proxy_config.get("alterId", 0),
                                        "net": proxy_config.get("network", "tcp"),
                                        "type": proxy_config.get("tls", "") if proxy_config.get("tls") else "none", # e.g., 'tls'
                                        "host": proxy_config.get("servername", ""), # For SNI
                                    }
                                    if vmess_obj["net"] == "ws":
                                        ws_opts = proxy_config.get("ws-opts", {})
                                        vmess_obj["path"] = ws_opts.get("path", "/")
                                        if "headers" in ws_opts and "Host" in ws_opts["headers"]:
                                            vmess_obj["host"] = ws_opts["headers"]["Host"]
                                    
                                    # Base64 encode the JSON string of the config
                                    vmess_b64 = base64.b64encode(json.dumps(vmess_obj).encode('utf-8')).decode('utf-8')
                                    node_url = f"vmess://{vmess_b64}"
                                except KeyError as e:
                                    logger.warning(f"Missing key in VMESS config from {url}: {e}")
                                    continue # Skip this proxy
                                except Exception as e:
                                    logger.warning(f"Error reconstructing VMESS link from {url}: {e}")
                                    continue # Skip this proxy

                            elif proxy_config.get("type") == "vless":
                                # Minimal VLESS reconstruction
                                try:
                                    node_url = f"vless://{proxy_config['uuid']}@{proxy_config['server']}:{proxy_config['port']}"
                                    params = []
                                    if proxy_config.get("tls"):
                                        params.append("security=tls")
                                    if proxy_config.get("flow"):
                                        params.append(f"flow={proxy_config['flow']}")
                                    if proxy_config.get("network") == "ws":
                                        ws_opts = proxy_config.get("ws-opts", {})
                                        params.append("type=ws")
                                        if ws_opts.get("path"):
                                            params.append(f"path={ws_opts['path']}")
                                        if ws_opts.get("headers", {}).get("Host"):
                                            params.append(f"host={ws_opts['headers']['Host']}")
                                    if params:
                                        node_url += "?" + "&".join(params)
                                    node_url += f"#{proxy_config.get('name', 'vless-node')}"
                                except KeyError as e:
                                    logger.warning(f"Missing key in VLESS config from {url}: {e}")
                                    continue
                                except Exception as e:
                                    logger.warning(f"Error reconstructing VLESS link from {url}: {e}")
                                    continue

                            elif proxy_config.get("type") == "trojan":
                                try:
                                    node_url = f"trojan://{proxy_config['password']}@{proxy_config['server']}:{proxy_config['port']}"
                                    params = []
                                    if proxy_config.get("tls"):
                                        params.append("security=tls")
                                    if proxy_config.get("network") == "ws":
                                        ws_opts = proxy_config.get("ws-opts", {})
                                        params.append("type=ws")
                                        if ws_opts.get("path"):
                                            params.append(f"path={ws_opts['path']}")
                                        if ws_opts.get("headers", {}).get("Host"):
                                            params.append(f"host={ws_opts['headers']['Host']}")
                                    if params:
                                        node_url += "?" + "&".join(params)
                                    node_url += f"#{proxy_config.get('name', 'trojan-node')}"
                                except KeyError as e:
                                    logger.warning(f"Missing key in Trojan config from {url}: {e}")
                                    continue
                                except Exception as e:
                                    logger.warning(f"Error reconstructing Trojan link from {url}: {e}")
                                    continue

                            elif proxy_config.get("type") == "ss":
                                # Shadowsocks in Clash YAML can be complex.
                                # This is a very basic attempt and might not cover all cases.
                                try:
                                    cipher = proxy_config.get("cipher")
                                    password = proxy_config.get("password")
                                    server = proxy_config.get("server")
                                    port = proxy_config.get("port")
                                    name = proxy_config.get("name", "ss-node")

                                    if all([cipher, password, server, port]):
                                        # SS link format: ss://base64_encoded_method:password@server:port#name
                                        creds = f"{cipher}:{password}"
                                        encoded_creds = base64.b64encode(creds.encode('utf-8')).decode('utf-8').replace('=', '')
                                        node_url = f"ss://{encoded_creds}@{server}:{port}#{name}"
                                except KeyError as e:
                                    logger.warning(f"Missing key in Shadowsocks config from {url}: {e}")
                                    continue
                                except Exception as e:
                                    logger.warning(f"Error reconstructing Shadowsocks link from {url}: {e}")
                                    continue


                            if node_url and (node := self.load_url_to_node(node_url, exc_queue)):
                                self.nodes.append(node)
                        else:
                            logger.warning(f"Unexpected proxy format in YAML from {url}: {proxy_config}")
                else:
                    logger.warning(f"YAML from {url} does not contain a 'proxies' key or is not a dictionary.")
            elif url.endswith(".json") or text.strip().startswith(("{", "[")):
                logger.debug(f"Parsing JSON from {url}")
                data = json.loads(text)
                # Assuming JSON is a list of node URLs or a specific structure
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str) and (node := self.load_url_to_node(item, exc_queue)):
                            self.nodes.append(node)
                        elif isinstance(item, dict):
                            # Attempt to parse common JSON structures for nodes
                            if "protocol" in item and "details" in item:
                                # Example: {"protocol": "vmess", "details": {...}}
                                # This would need specific logic per protocol
                                logger.warning(f"Structured JSON content detected, but not yet fully supported for {url}: {item}")
                            elif "ps" in item and "add" in item and "port" in item:
                                # Assume it might be a direct VMESS JSON object
                                try:
                                    vmess_b64 = base64.b64encode(json.dumps(item).encode('utf-8')).decode('utf-8')
                                    node_url = f"vmess://{vmess_b64}"
                                    if node := self.load_url_to_node(node_url, exc_queue):
                                        self.nodes.append(node)
                                except Exception as e:
                                    logger.warning(f"Could not parse JSON item as VMESS from {url}: {e} - {item}")
                            else:
                                logger.warning(f"Unhandled JSON item format from {url}: {item}")

                elif isinstance(data, dict):
                    # For a dictionary, might be a single node or a collection under a key
                    if "proxies" in data and isinstance(data["proxies"], list):
                        for proxy_config in data["proxies"]:
                            if isinstance(proxy_config, dict):
                                # Re-use the YAML proxy reconstruction logic if applicable
                                node_url = None
                                if proxy_config.get("type") == "vmess":
                                    try:
                                        vmess_obj = {
                                            "v": "2",
                                            "ps": proxy_config.get("name", "vmess-node"),
                                            "add": proxy_config["server"],
                                            "port": proxy_config["port"],
                                            "id": proxy_config["uuid"],
                                            "aid": proxy_config.get("alterId", 0),
                                            "net": proxy_config.get("network", "tcp"),
                                            "type": proxy_config.get("tls", "") if proxy_config.get("tls") else "none",
                                            "host": proxy_config.get("servername", ""),
                                        }
                                        if vmess_obj["net"] == "ws":
                                            ws_opts = proxy_config.get("ws-opts", {})
                                            vmess_obj["path"] = ws_opts.get("path", "/")
                                            if "headers" in ws_opts and "Host" in ws_opts["headers"]:
                                                vmess_obj["host"] = ws_opts["headers"]["Host"]
                                        vmess_b64 = base64.b64encode(json.dumps(vmess_obj).encode('utf-8')).decode('utf-8')
                                        node_url = f"vmess://{vmess_b64}"
                                    except KeyError as e:
                                        logger.warning(f"Missing key in VMESS config from {url} (JSON): {e}")
                                        continue
                                    except Exception as e:
                                        logger.warning(f"Error reconstructing VMESS link from {url} (JSON): {e}")
                                        continue
                                # Add similar logic for vless, trojan, ss if found in JSON
                                elif proxy_config.get("type") == "vless":
                                    try:
                                        node_url = f"vless://{proxy_config['uuid']}@{proxy_config['server']}:{proxy_config['port']}"
                                        params = []
                                        if proxy_config.get("tls"):
                                            params.append("security=tls")
                                        if proxy_config.get("flow"):
                                            params.append(f"flow={proxy_config['flow']}")
                                        if proxy_config.get("network") == "ws":
                                            ws_opts = proxy_config.get("ws-opts", {})
                                            params.append("type=ws")
                                            if ws_opts.get("path"):
                                                params.append(f"path={ws_opts['path']}")
                                            if ws_opts.get("headers", {}).get("Host"):
                                                params.append(f"host={ws_opts['headers']['Host']}")
                                        if params:
                                            node_url += "?" + "&".join(params)
                                        node_url += f"#{proxy_config.get('name', 'vless-node')}"
                                    except KeyError as e:
                                        logger.warning(f"Missing key in VLESS config from {url} (JSON): {e}")
                                        continue
                                    except Exception as e:
                                        logger.warning(f"Error reconstructing VLESS link from {url} (JSON): {e}")
                                        continue
                                elif proxy_config.get("type") == "trojan":
                                    try:
                                        node_url = f"trojan://{proxy_config['password']}@{proxy_config['server']}:{proxy_config['port']}"
                                        params = []
                                        if proxy_config.get("tls"):
                                            params.append("security=tls")
                                        if proxy_config.get("network") == "ws":
                                            ws_opts = proxy_config.get("ws-opts", {})
                                            params.append("type=ws")
                                            if ws_opts.get("path"):
                                                params.append(f"path={ws_opts['path']}")
                                            if ws_opts.get("headers", {}).get("Host"):
                                                params.append(f"host={ws_opts['headers']['Host']}")
                                        if params:
                                            node_url += "?" + "&".join(params)
                                        node_url += f"#{proxy_config.get('name', 'trojan-node')}"
                                    except KeyError as e:
                                        logger.warning(f"Missing key in Trojan config from {url} (JSON): {e}")
                                        continue
                                    except Exception as e:
                                        logger.warning(f"Error reconstructing Trojan link from {url} (JSON): {e}")
                                        continue
                                elif proxy_config.get("type") == "ss":
                                    try:
                                        cipher = proxy_config.get("cipher")
                                        password = proxy_config.get("password")
                                        server = proxy_config.get("server")
                                        port = proxy_config.get("port")
                                        name = proxy_config.get("name", "ss-node")

                                        if all([cipher, password, server, port]):
                                            creds = f"{cipher}:{password}"
                                            encoded_creds = base64.b64encode(creds.encode('utf-8')).decode('utf-8').replace('=', '')
                                            node_url = f"ss://{encoded_creds}@{server}:{port}#{name}"
                                    except KeyError as e:
                                        logger.warning(f"Missing key in Shadowsocks config from {url} (JSON): {e}")
                                        continue
                                    except Exception as e:
                                        logger.warning(f"Error reconstructing Shadowsocks link from {url} (JSON): {e}")
                                        continue

                                if node_url and (node := self.load_url_to_node(node_url, exc_queue)):
                                    self.nodes.append(node)
                            else:
                                logger.warning(f"Unexpected proxy format in JSON from {url}: {proxy_config}")
                    else:
                        logger.warning(f"JSON from {url} is a dictionary but does not contain a 'proxies' key or it's not a list.")
                else:
                    logger.warning(f"Unsupported JSON format from {url}: {type(data)}")
            else:
                logger.debug(f"Parsing plain text content from {url}")
                # Treat as plain text, line by line
                for line in text.splitlines():
                    line = line.strip()
                    if line and (node := self.load_url_to_node(line, exc_queue)):
                        self.nodes.append(node)
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            await exc_queue.put(f"Parsing error (JSON/YAML) for {url}: {str(e)}")
            logger.error(f"Parsing error (JSON/YAML) for {url}: {e}")
        except Exception as e:
            await exc_queue.put(f"Unknown parsing error for {url}: {str(e)}")
            logger.error(f"Unknown parsing error for {url}: {e}")


class Node:
    def __init__(self, url: str):
        self.url = url
        self.protocol = ""
        self.config = {}
        self.parse_url()

    def parse_url(self):
        # Determine protocol and parse accordingly
        if self.url.startswith("vmess://"):
            self.protocol = "vmess"
            self._parse_vmess()
        elif self.url.startswith("vless://"):
            self.protocol = "vless"
            self._parse_vless()
        elif self.url.startswith("ss://"):
            self.protocol = "ss"
            self._parse_ss()
        elif self.url.startswith("trojan://"):
            self.protocol = "trojan"
            self._parse_trojan()
        elif self.url.startswith("hysteria2://"):
            self.protocol = "hysteria2"
            self._parse_hysteria2()
        else:
            logger.warning(f"Unsupported protocol for URL: {self.url[:50]}...")
            self.protocol = "unknown"

    def _parse_vmess(self):
        try:
            encoded_config = self.url[8:]
            decoded_config = base64.b64decode(encoded_config).decode("utf-8")
            self.config = json.loads(decoded_config)
        except Exception as e:
            logger.error(f"Error parsing VMESS URL {self.url}: {e}")
            self.config = {}

    def _parse_vless(self):
        try:
            # vless://uuid@server:port?params#name
            match = re.match(r"vless://([^@]+)@([^:]+):(\d+)(?:\?(.*))?(?:#(.+))?", self.url)
            if match:
                self.config["uuid"] = match.group(1)
                self.config["server"] = match.group(2)
                self.config["port"] = int(match.group(3))
                if match.group(4): # params
                    params = match.group(4).split("&")
                    for param in params:
                        key_val = param.split("=", 1)
                        if len(key_val) == 2:
                            self.config[key_val[0]] = key_val[1]
                self.config["name"] = match.group(5) if match.group(5) else self.config["server"]
        except Exception as e:
            logger.error(f"Error parsing VLESS URL {self.url}: {e}")
            self.config = {}

    def _parse_ss(self):
        try:
            # ss://method:password@server:port#name or ss://base64_encoded_method:password@server:port#name
            # Simplified parsing, assuming base64(method:password)
            parts = self.url[5:].split("#", 1)
            name = ""
            if len(parts) > 1:
                name = parts[1]
            
            creds_server_port = parts[0]
            
            # Check if it's base64 encoded credentials
            if '@' in creds_server_port:
                b64_creds, server_port = creds_server_port.split('@', 1)
                try:
                    decoded_creds = base64.b64decode(b64_creds + "===").decode('utf-8') # Add padding
                    method, password = decoded_creds.split(":", 1)
                    self.config["method"] = method
                    self.config["password"] = password
                except (base64.binascii.Error, UnicodeDecodeError):
                    # Not base64, assume it's direct method:password
                    method_pass, server_port = creds_server_port.split("@", 1)
                    method, password = method_pass.split(":", 1)
                    self.config["method"] = method
                    self.config["password"] = password
            else: # No '@' means base64 encoded method:password@server:port
                decoded_entire = base64.b64decode(creds_server_port + "===").decode('utf-8')
                method_pass_server_port = decoded_entire
                
                parts_decoded = method_pass_server_port.split('@', 1)
                if len(parts_decoded) == 2:
                    method_password_str, server_port = parts_decoded
                    method, password = method_password_str.split(':', 1)
                    self.config["method"] = method
                    self.config["password"] = password
                else:
                    raise ValueError("Invalid Shadowsocks format")

            server, port = server_port.rsplit(":", 1)
            self.config["server"] = server
            self.config["port"] = int(port)
            self.config["name"] = name if name else server
            
        except Exception as e:
            logger.error(f"Error parsing SS URL {self.url}: {e}")
            self.config = {}

    def _parse_trojan(self):
        try:
            # trojan://password@server:port?params#name
            match = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(?:\?(.*))?(?:#(.+))?", self.url)
            if match:
                self.config["password"] = match.group(1)
                self.config["server"] = match.group(2)
                self.config["port"] = int(match.group(3))
                if match.group(4): # params
                    params = match.group(4).split("&")
                    for param in params:
                        key_val = param.split("=", 1)
                        if len(key_val) == 2:
                            self.config[key_val[0]] = key_val[1]
                self.config["name"] = match.group(5) if match.group(5) else self.config["server"]
        except Exception as e:
            logger.error(f"Error parsing Trojan URL {self.url}: {e}")
            self.config = {}

    def _parse_hysteria2(self):
        try:
            # hysteria2://password@server:port?params#name
            match = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)(?:\?(.*))?(?:#(.+))?", self.url)
            if match:
                self.config["password"] = match.group(1)
                self.config["server"] = match.group(2)
                self.config["port"] = int(match.group(3))
                if match.group(4): # params
                    params = match.group(4).split("&")
                    for param in params:
                        key_val = param.split("=", 1)
                        if len(key_val) == 2:
                            self.config[key_val[0]] = key_val[1]
                self.config["name"] = match.group(5) if match.group(5) else self.config["server"]
        except Exception as e:
            logger.error(f"Error parsing Hysteria2 URL {self.url}: {e}")
            self.config = {}


async def main():
    # Setup logging
    logger.remove()
    logger.add(sys.stderr, level="INFO") # Log to stderr for GitHub Actions output

    today_date = time.strftime("%Y%m%d")
    logger.info(f"Today's date: {today_date}")

    sources_file = Path("sources.list")
    if not sources_file.exists():
        logger.error("sources.list not found. Please create it with node URLs.")
        return

    sources_obj = []
    with open(sources_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                sources_obj.append(Source(line))

    # Use a single session for all requests
    connector = aiohttp.TCPConnector(limit=50) # Limit concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        exc_queue = asyncio.Queue() # Queue to collect exceptions and warnings

        parse_tasks = [source.parse(today_date, session, exc_queue) for source in sources_obj]
        await asyncio.gather(*parse_tasks)

    all_nodes = []
    for source in sources_obj:
        all_nodes.extend(source.nodes)

    logger.info(f"Total nodes collected: {len(all_nodes)}")

    # Group nodes by protocol
    nodes_by_protocol = {
        "vmess": [],
        "vless": [],
        "ss": [],
        "trojan": [],
        "hysteria2": []
    }

    for node in all_nodes:
        if node.protocol in nodes_by_protocol:
            nodes_by_protocol[node.protocol].append(node.url)

    # Save to files
    output_dir = Path("parsed_nodes")
    output_dir.mkdir(exist_ok=True)

    for protocol, nodes_list in nodes_by_protocol.items():
        output_file = output_dir / f"{protocol}_nodes.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            for node_url in nodes_list:
                f.write(f"{node_url}\n")
        logger.info(f"Saved {len(nodes_list)} {protocol} nodes to {output_file}")

    # Generate an all_nodes.txt file
    with open(output_dir / "all_nodes.txt", "w", encoding="utf-8") as f:
        for node in all_nodes:
            f.write(f"{node.url}\n")
    logger.info(f"Saved {len(all_nodes)} total nodes to {output_dir / 'all_nodes.txt'}")

    # Process and print exceptions/warnings
    errors = []
    while not exc_queue.empty():
        errors.append(await exc_queue.get())
    
    if errors:
        logger.warning("\n--- Collected Errors and Warnings ---")
        for error_msg in errors:
            logger.warning(error_msg)
        logger.warning("-------------------------------------")
    
    logger.info("Node parsing completed.")

if __name__ == "__main__":
    asyncio.run(main())
