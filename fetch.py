#!/usr/bin/env python3
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
from requests_file import FileAdapter
import datetime
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Dict, Union, Any

# 基本配置
FETCH_TIMEOUT = (6, 5)
DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

# V2Ray 和 Clash 字段映射
CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id', 
               'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH = {v: k for k, v in CLASH2VMESS.items()}
VMESS_EXAMPLE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

# 请求会话配置
session = requests.Session()
session.trust_env = False
session.headers["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
session.mount('file://', FileAdapter())

exc_queue: List[str] = []

class Node:
    names: Set[str] = set()

    def __init__(self, data: Union[Dict[str, Any], str]) -> None:
        if isinstance(data, dict):
            self.data = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else:
            raise TypeError(f"Got {type(data)}")
        self.data['name'] = self.data.get('name', '未命名')
        self.name = self.data['name']
        self.data['type'] = self.type

    def load_url(self, url: str) -> None:
        try:
            self.type, dt = url.split("://", 1)
        except ValueError:
            raise ValueError(f"Invalid node URL: {url}")
        if self.type == 'hy2': self.type = 'hysteria2'

        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            try:
                v.update(json.loads(base64.b64decode(dt + '=' * ((4 - len(dt) % 4) % 4)).decode('utf-8')))
            except Exception:
                raise ValueError('Invalid vmess URL')
            self.data = {VMESS2CLASH.get(k, k): v for k, v in v.items()}
            self.data['tls'] = (v['tls'] == 'tls')
            self.data['alterId'] = int(self.data['alterId'])
            if v['net'] == 'ws':
                opts = {'path': v.get('path', ''), 'headers': {'Host': v.get('host', '')}} if 'path' in v or 'host' in v else {}
                self.data['ws-opts'] = opts
            elif v['net'] == 'h2':
                opts = {'path': v.get('path', ''), 'host': v.get('host', '').split(',')} if 'path' in v or 'host' in v else {}
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}

        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            server, port = srvname.split('#')[0].rsplit(':', 1) if '#' in srvname else (srvname, '')
            name = unquote(srvname.split('#')[1]) if '#' in srvname else ''
            try:
                port = int(port)
            except ValueError:
                raise ValueError(f"Invalid port: {port}")
            info = base64.urlsafe_b64decode(info[0] + '=' * ((4 - len(info[0]) % 4) % 4)).decode('utf-8')
            cipher, passwd = info.split(':', 1) if ':' in info else (info, '')
            self.data = {'name': name, 'server': server, 'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {
                'name': unquote(parsed.fragment), 'server': parsed.hostname, 'port': parsed.port,
                'type': 'trojan', 'password': unquote(parsed.username)
            }
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k, v = kv.split('=')
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni':
                        self.data['sni'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        self.data['grpc-opts'] = {'grpc-service-name': v}
                    elif k == 'host':
                        self.data['ws-opts'] = {'headers': {'Host': v}}
                    elif k == 'path':
                        self.data['ws-opts'] = self.data.get('ws-opts', {}) | {'path': v}

        else:
            raise ValueError(f"Unsupported type: {self.type}")

    def format_name(self, max_len=30) -> None:
        self.data['name'] = self.name[:max_len] + '...' if len(self.name) > max_len else self.name
        if self.data['name'] in Node.names:
            i = 0
            new = self.data['name']
            while new in Node.names:
                i += 1
                new = f"{self.data['name']} #{i}"
            self.data['name'] = new
        Node.names.add(self.data['name'])

    @property
    def url(self) -> str:
        data = self.data
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            for key, val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws' and 'ws-opts' in data:
                v['host'] = data['ws-opts'].get('headers', {}).get('Host', '')
                v['path'] = data['ws-opts'].get('path', '')
            elif v['net'] == 'h2' and 'h2-opts' in data:
                v['host'] = ','.join(data['h2-opts'].get('host', []))
                v['path'] = data['h2-opts'].get('path', '')
            elif v['net'] == 'grpc' and 'grpc-opts' in data:
                v['path'] = data['grpc-opts'].get('grpc-service-name', '')
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://' + base64.b64encode(json.dumps(v, ensure_ascii=False).encode('utf-8')).decode('utf-8')

        elif self.type == 'ss':
            passwd = base64.urlsafe_b64encode(f"{data['cipher']}:{data['password']}".encode('utf-8')).decode('utf-8')
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

        elif self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        ret += f"host={data['ws-opts']['headers']['Host']}&path={data['ws-opts']['path']}"
            return ret.rstrip('&') + '#' + name

        raise ValueError(f"Unsupported type: {self.type}")

    @property
    def clash_data(self) -> Dict[str, Any]:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str ' + ret['password']
        return ret

class Source:
    def __init__(self, url: str) -> None:
        self.url = url
        self.content: Union[str, int] = None
        self.sub: List[Union[str, Dict[str, str]]] = None

    def gen_url(self) -> None:
        if '+date' in self.url:
            date = datetime.datetime.now()
            self.url = date.strftime(self.url.replace('+date ', ''))

    def get(self) -> None:
        if self.content:
            return
        self.gen_url()
        try:
            with session.get(self.url, timeout=FETCH_TIMEOUT) as r:
                if r.status_code != 200:
                    self.content = r.status_code
                    return
                self.content = r.text
        except requests.exceptions.RequestException as e:
            self.content = -1
            exc_queue.append(f"Fetch failed for '{self.url}': {str(e)}")

    def parse(self) -> None:
        if not isinstance(self.content, str):
            self.sub = []
            exc_queue.append(f"Invalid content type for '{self.url}': {type(self.content)}")
            return
        text = self.content.strip()
        if not text:
            self.sub = []
            exc_queue.append(f"Empty content from '{self.url}'")
            return

        try:
            data = json.loads(text)
            self.sub = data if isinstance(data, list) else data.get('proxies', [])
            return
        except json.JSONDecodeError:
            pass

        try:
            data = yaml.safe_load(text)
            self.sub = data.get('proxies', []) if isinstance(data, dict) else data
            return
        except yaml.YAMLError:
            pass

        try:
            decoded = base64.b64decode(text + '=' * ((4 - len(text) % 4) % 4)).decode('utf-8')
            lines = decoded.strip().splitlines()
            self.sub = [line.strip() for line in lines if '://' in line and line.strip()]
            return
        except (base64.binascii.Error, UnicodeDecodeError):
            pass

        lines = text.splitlines()
        self.sub = [line.strip() for line in lines if '://' in line and line.strip()]

merged: Dict[int, Node] = {}
unknown: Set[str] = set()

def merge(source_obj: Source) -> None:
    global merged, unknown
    if not source_obj.sub:
        exc_queue.append(f"Empty subscription '{source_obj.url}'")
        return
    for p in source_obj.sub:
        try:
            n = Node(p)
            n.format_name()
            Node.names.add(n.data['name'])
            hashn = hash(str(n))
            merged[hashn] = n
        except Exception as e:
            unknown.add(str(p))
            exc_queue.append(f"Parse node failed: {str(e)}")

def main():
    global exc_queue, merged, unknown
    sources = [
        "+date https://node.freeclashnode.com/uploads/%Y/%m/0-%Y%m%d.txt",
        "+date https://node.freeclashnode.com/uploads/%Y/%m/1-%Y%m%d.txt",
        # ... 其他源链接（已省略，实际使用时应包含完整列表）
    ]

    sources_final = set()
    for source in sources:
        if source and source[0] != '#':
            sources_final.add(source.replace('+date ', ''))

    sources_obj = [Source(url) for url in sources_final]
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_source = {executor.submit(source.get): source for source in sources_obj}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            print(f"Fetching '{source.url}'... ", end='', flush=True)
            try:
                future.result()
                print("Parsing... ", end='', flush=True)
                source.parse()
                print("Merging... ", end='', flush=True)
                merge(source)
                print("Done!")
            except Exception:
                print("Failed!")
                traceback.print_exc()

    txt = ""
    for p in merged.values():
        try:
            txt += p.url + '\n'
        except Exception as e:
            exc_queue.append(f"Generate URL failed: {str(e)}")
    for p in unknown:
        txt += p + '\n'

    with open("list_raw.txt", 'w', encoding="utf-8") as f:
        f.write(txt)
    with open("list.txt", 'w', encoding="utf-8") as f:
        f.write(base64.b64encode(txt.encode('utf-8')).decode('utf-8'))

    conf = {'proxies': [p.clash_data for p in merged.values()]}
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ', ''))

    print(f"Total: {len(merged)} nodes, {len(unknown)} unknown nodes")

if __name__ == '__main__':
    main()
