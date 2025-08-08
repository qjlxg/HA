import os
import requests
import yaml
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from bs4 import BeautifulSoup
import re

# 配置
GOOGLE_API_KEY = "AIzaSyAMtL0YSMv9yU3yU31X5xDIlnflZUaw9gQ"  # 替换为你的 Google API 密钥
SEARCH_ENGINE_ID = "82b4522b9c2db4b64"  # 替换为你的 Custom Search Engine ID
OUTPUT_DIR = "sc"
SEARCH_QUERY = 'filetype:yaml "proxies:" "clash" site:github.com'

def create_output_dir():
    """创建输出目录"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def search_github():
    """使用 Google Custom Search API 搜索 GitHub"""
    try:
        service = build("customsearch", "v1", developerKey=GOOGLE_API_KEY)
        result = service.cse().list(q=SEARCH_QUERY, cx=SEARCH_ENGINE_ID, num=10).execute()
        return [item["link"] for item in result.get("items", [])]
    except HttpError as e:
        print(f"搜索失败: {e}")
        return []

def fetch_content(url):
    """获取网页内容"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        return None
    except requests.RequestException as e:
        print(f"获取 {url} 失败: {e}")
        return None

def is_valid_clash_yaml(content):
    """验证是否为有效的 Clash YAML 配置"""
    try:
        # 初步检查关键词
        if "proxies:" not in content:
            return False, None
        
        # 尝试解析 YAML
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or "proxies" not in data:
            return False, None
            
        # 检查 proxies 是否为列表
        if not isinstance(data["proxies"], list):
            return False, None
            
        # 验证每个代理是否包含必要字段
        for proxy in data["proxies"]:
            if not all(key in proxy for key in ["name", "server", "port"]):
                return False, None
                
        return True, data["proxies"]
    except yaml.YAMLError:
        return False, None

def extract_yaml_from_html(html_content):
    """从 HTML 中提取 YAML 内容"""
    soup = BeautifulSoup(html_content, "html.parser")
    # 查找可能的 YAML 内容（通常在 <pre> 或 <code> 标签中）
    code_blocks = soup.find_all(["pre", "code"])
    for block in code_blocks:
        content = block.get_text()
        if "proxies:" in content:
            return content
    return None

def save_proxies(proxies, output_file):
    """保存代理节点到 YAML 文件"""
    output_data = {"proxies": proxies}
    output_path = os.path.join(OUTPUT_DIR, output_file)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(output_data, f, allow_unicode=True)
    print(f"已保存 {len(proxies)} 个节点到 {output_path}")

def main():
    create_output_dir()
    links = search_github()
    
    all_proxies = []
    for i, link in enumerate(links, 1):
        print(f"处理链接 {i}/{len(links)}: {link}")
        content = fetch_content(link)
        if not content:
            continue
            
        # 从 HTML 中提取 YAML 内容
        yaml_content = extract_yaml_from_html(content)
        if not yaml_content:
            continue
            
        # 验证并解析 YAML
        is_valid, proxies = is_valid_clash_yaml(yaml_content)
        if is_valid:
            all_proxies.extend(proxies)
            print(f"从 {link} 提取到 {len(proxies)} 个有效节点")
    
    if all_proxies:
        output_file = f"clash_proxies_{len(all_proxies)}.yaml"
        save_proxies(all_proxies, output_file)
    else:
        print("未找到任何有效的 Clash 代理配置")

if __name__ == "__main__":
    main()
