import requests
import re
import os
import csv
import base64
import yaml
import json
import hashlib
import random
from urllib.parse import unquote, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration Section ---
DATA_DIR = "data"
SOURCES_FILE = "sources.list"
NODE_OUTPUT_PREFIX = os.path.join(DATA_DIR, "proxy_nodes_") # Prefix for sliced files
MAX_NODES_PER_SLICE = 2000 # Max nodes per slice file

NODE_COUNTS_FILE = os.path.join(DATA_DIR, "node_counts.csv")
CACHE_FILE = os.path.join(DATA_DIR, "url_cache.json")

# Concurrency configuration
MAX_WORKERS = 10 # Number of URLs to process concurrently
REQUEST_TIMEOUT = 10 # Timeout for a single request, in seconds

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Define supported node protocol regular expressions
NODE_PATTERNS = {
    "hysteria2": re.compile(r"hysteria2://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vmess": re.compile(r"vmess://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "trojan": re.compile(r"trojan://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    # FIX: Corrected the character range from 'a-9' to 'a-zA-Z0-9'
    "ss": re.compile(r"ss://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "ssr": re.compile(r"ssr://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE),
    "vless": re.compile(r"vless://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
}

# Random User-Agent pool
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.56',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
]

# --- Helper Functions ---

def read_sources(file_path):
    """Reads all URLs from the sources.list file"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    urls.append(stripped_line)
        print(f"Successfully read {len(urls)} source URLs.")
    except FileNotFoundError:
        print(f"Error: Source file '{file_path}' not found. Please ensure it's in the same directory as the script.")
    return urls

def load_cache(cache_file):
    """Loads the URL cache"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("Warning: Cache file corrupted, will regenerate.")
            return {}
    return {}

def save_cache(cache_file, cache_data):
    """Saves the URL cache"""
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(cache_data, f, indent=4)

def fetch_content(url, retries=3, cache_data=None):
    """
    Attempts to fetch web content via HTTP or HTTPS, with retry mechanism.
    Simulates a random browser user agent.
    Tries to use ETag or Last-Modified for conditional requests.
    If the URL has no scheme, it will first try http, then https.
    """
    current_headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'DNT': '1',
        'Connection': 'keep-alive'
    }

    if cache_data and url in cache_data:
        if 'etag' in cache_data[url]:
            current_headers['If-None-Match'] = cache_data[url]['etag']
        if 'last_modified' in cache_data[url]:
            current_headers['If-Modified-Since'] = cache_data[url]['last_modified']
    
    test_urls = []
    if urlparse(url).scheme:
        test_urls.append(url)
    else:
        test_urls.append(f"http://{url}")
        test_urls.append(f"https://{url}")

    for attempt in range(retries):
        for current_url_to_test in test_urls:
            try:
                response = requests.get(current_url_to_test, timeout=REQUEST_TIMEOUT, headers=current_headers, allow_redirects=True, verify=False)
                
                if response.status_code == 304:
                    print(f"  {url} Content not modified (304).")
                    return None, None
                    
                response.raise_for_status()
                
                new_etag = response.headers.get('ETag')
                new_last_modified = response.headers.get('Last-Modified')
                
                return response.text, {'etag': new_etag, 'last_modified': new_last_modified, 'content_hash': hashlib.sha256(response.text.encode('utf-8')).hexdigest()}
                
            except requests.exceptions.Timeout:
                print(f"  {url} Request timed out.")
            except requests.exceptions.RequestException as e:
                print(f"  {url} Failed to fetch ({e}).")
        
        if attempt < retries - 1:
            import time
            time.sleep(2 ** attempt + 1)

    print(f"  {url} All {retries} attempts failed.")
    return None, None

def decode_base64(data):
    """Attempts to decode a Base64 string"""
    if not isinstance(data, str):
        return None
    data = data.strip()
    try:
        decoded_bytes = base64.urlsafe_b64decode(data + '==')
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        try:
            decoded_bytes = base64.b64decode(data + '==')
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None

def is_valid_node(node_url):
    """
    Checks the basic validity of a node URL.
    """
    if not isinstance(node_url, str) or len(node_url) < 10:
        return False

    parsed_url = urlparse(node_url)
    
    found_protocol = False
    for proto in NODE_PATTERNS.keys():
        if node_url.lower().startswith(f"{proto}://"):
            found_protocol = True
            break
    if not found_protocol:
        return False

    if not node_url.lower().startswith(("ss://", "ssr://", "vmess://")):
        if not parsed_url.hostname:
            return False

    if node_url.lower().startswith("vmess://"):
        try:
            b64_content = node_url[len("vmess://"):]
            decoded = decode_base64(b64_content)
            if not decoded or not decoded.strip().startswith('{') or not decoded.strip().endswith('}'):
                return False
            json.loads(decoded)
        except (ValueError, json.JSONDecodeError, TypeError):
            return False
    
    return True

def parse_content(content):
    """
    Attempts to parse content, which can be plain text, HTML, Base64, or YAML.
    """
    if not content:
        return ""

    decoded_content = decode_base64(content)
    if decoded_content:
        if any(pattern.search(decoded_content) for pattern in NODE_PATTERNS.values()):
            print("Content identified as Base64 encoded, decoded.")
            return decoded_content

    try:
        parsed_yaml = yaml.safe_load(content)
        if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml):
            print("Content identified as YAML format.")
            nodes_from_yaml_structure = []
            if 'proxies' in parsed_yaml and isinstance(parsed_yaml['proxies'], list):
                for proxy in parsed_yaml['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        try:
                            if proxy['type'].lower() == 'vmess':
                                nodes_from_yaml_structure.append(f"vmess://{base64.b64encode(json.dumps(proxy).encode('utf-8')).decode('utf-8')}")
                            elif proxy['type'].lower() == 'ss' and 'password' in proxy:
                                method_pwd = f"{proxy.get('cipher')}:{proxy.get('password')}"
                                nodes_from_yaml_structure.append(f"ss://{base64.b64encode(method_pwd.encode('utf-8')).decode('utf-8')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'trojan' and 'password' in proxy:
                                nodes_from_yaml_structure.append(f"trojan://{proxy.get('password')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'vless' and 'uuid' in proxy:
                                nodes_from_yaml_structure.append(f"vless://{proxy.get('uuid')}@{proxy.get('server')}:{proxy.get('port')}")
                            elif proxy['type'].lower() == 'hysteria2' and 'password' in proxy:
                                nodes_from_yaml_structure.append(f"hysteria2://{proxy.get('server')}:{proxy.get('port')}?password={proxy.get('password')}")
                        except Exception as e:
                            print(f"  Warning: Failed to parse YAML proxy entry ({proxy.get('type')}): {e}")
            
            return content + "\n" + "\n".join(nodes_from_yaml_structure)
    except yaml.YAMLError:
        pass

    if '<html' in content.lower() or '<body' in content.lower() or '<!doctype html>' in content.lower():
        print("Content identified as HTML format.")
        soup = BeautifulSoup(content, 'html.parser')
        
        extracted_text = []
        potential_node_containers = soup.find_all(['pre', 'code', 'textarea'])
        for tag in potential_node_containers:
            extracted_text.append(tag.get_text(separator="\n", strip=True))

        if soup.body:
            body_text = soup.body.get_text(separator="\n", strip=True)
            if len(body_text) > 100 or any(pattern.search(body_text) for pattern in NODE_PATTERNS.values()):
                extracted_text.append(body_text)
            
        return "\n".join(extracted_text)
        
    print("Content identified as plain text format.")
    return content

def extract_and_validate_nodes(content):
    """
    Extracts and validates all supported format node URLs from the parsed content.
    """
    if not content:
        return []
    
    found_nodes = set()
    
    for pattern_name, pattern_regex in NODE_PATTERNS.items():
        matches = pattern_regex.findall(content)
        for match in matches:
            decoded_match = unquote(match).strip()
            if is_valid_node(decoded_match):
                found_nodes.add(decoded_match)

    return list(found_nodes)

def load_existing_nodes_from_slices(directory, prefix):
    """Loads existing node list from multiple sliced files for incremental updates"""
    existing_nodes = set()
    loaded_count = 0
    for filename in os.listdir(directory):
        if filename.startswith(os.path.basename(prefix)) and filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(' = ', 1)
                        if len(parts) == 2:
                            existing_nodes.add(parts[1])
                            loaded_count += 1
            except Exception as e:
                print(f"Warning: Failed to load existing node file ({file_path}): {e}")
    print(f"Loaded {loaded_count} existing nodes from {len(os.listdir(directory))} slice files.")
    return existing_nodes

def save_nodes_to_sliced_files(output_prefix, nodes, max_nodes_per_slice):
    """Saves processed nodes as sliced text files with ascending custom names"""
    total_nodes = len(nodes)
    num_slices = (total_nodes + max_nodes_per_slice - 1) // max_nodes_per_slice
    
    # Clean up old slice files
    for filename in os.listdir(DATA_DIR):
        if filename.startswith(os.path.basename(output_prefix)) and filename.endswith('.txt'):
            os.remove(os.path.join(DATA_DIR, filename))
            print(f"Deleted old slice file: {filename}")

    saved_files_count = 0
    for i in range(num_slices):
        start_index = i * max_nodes_per_slice
        end_index = min((i + 1) * max_nodes_per_slice, total_nodes)
        
        slice_nodes = nodes[start_index:end_index]
        slice_file_name = f"{output_prefix}{i+1:03d}.txt"
        
        with open(slice_file_name, 'w', encoding='utf-8') as f:
            for j, node in enumerate(slice_nodes):
                global_index = start_index + j
                f.write(f"Proxy-{global_index+1:05d} = {node}\n")
        print(f"Saved slice file: {slice_file_name} (containing {len(slice_nodes)} nodes)")
        saved_files_count += 1
    
    print(f"Final node list sliced and saved to {saved_files_count} files.")

def save_node_counts_to_csv(file_path, counts_data):
    """Saves node count statistics for each URL to a CSV file."""
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Source URL", "Node Count"])
        for url, count in counts_data.items():
            writer.writerow([url, count])
    print(f"Node count statistics saved to {file_path}")

# --- Main Logic ---

def process_single_url(url, url_cache_data):
    """Logic to process a single URL for concurrent calls"""
    content, new_cache_meta = fetch_content(url, cache_data=url_cache_data)

    if content is None and new_cache_meta is None:
        return url, 0, None, url_cache_data.get(url, {})

    last_content_hash = url_cache_data.get(url, {}).get('content_hash')
    current_content_hash = new_cache_meta['content_hash'] if new_cache_meta else None

    if last_content_hash and current_content_hash == last_content_hash:
        return url, url_cache_data.get(url, {}).get('node_count', 0), None, url_cache_data.get(url, {})

    parsed_content = parse_content(content)
    nodes_from_url = extract_and_validate_nodes(parsed_content)
    
    print(f"Extracted {len(nodes_from_url)} valid nodes from {url}.")

    if new_cache_meta:
        new_cache_meta['node_count'] = len(nodes_from_url)
    else:
        new_cache_meta = url_cache_data.get(url, {})
        new_cache_meta['node_count'] = len(nodes_from_url)
        
    return url, len(nodes_from_url), new_cache_meta, nodes_from_url


def main():
    source_urls = read_sources(SOURCES_FILE)
    if not source_urls:
        print("No source URLs found, script terminated.")
        return

    url_cache = load_cache(CACHE_FILE)
    existing_nodes = load_existing_nodes_from_slices(DATA_DIR, NODE_OUTPUT_PREFIX)
    
    all_new_and_existing_nodes = set(existing_nodes)
    url_node_counts = {}

    processed_urls_count = 0
    skipped_urls_count = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(process_single_url, url, url_cache.get(url, {}).copy()): url for url in source_urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                processed_url, node_count, updated_cache_meta, extracted_nodes_list = future.result()
                
                url_node_counts[processed_url] = node_count
                
                if extracted_nodes_list:
                    all_new_and_existing_nodes.update(extracted_nodes_list)
                
                if updated_cache_meta:
                    url_cache[processed_url] = updated_cache_meta
                    processed_urls_count += 1
                else:
                    url_cache[processed_url] = url_cache.get(processed_url, {})
                    url_cache[processed_url]['node_count'] = node_count
                    skipped_urls_count += 1
                
                # Save cache more frequently, but be aware it might slow down slightly
                # For very large number of URLs, consider saving less frequently or using a lock
                save_cache(CACHE_FILE, url_cache)
            except Exception as exc:
                print(f'{url} generated an exception: {exc}')
                url_node_counts[url] = url_cache.get(url, {}).get('node_count', 0)
                skipped_urls_count += 1
                save_cache(CACHE_FILE, url_cache)

    print(f"\nProcessing complete. Processed {processed_urls_count} URLs, skipped {skipped_urls_count} URLs.")
    final_nodes_list = sorted(list(all_new_and_existing_nodes))
    print(f"Total {len(final_nodes_list)} unique nodes collected (including existing ones).")

    save_nodes_to_sliced_files(NODE_OUTPUT_PREFIX, final_nodes_list, MAX_NODES_PER_SLICE)
    save_node_counts_to_csv(NODE_COUNTS_FILE, url_node_counts)
    save_cache(CACHE_FILE, url_cache)

if __name__ == "__main__":
    main()
