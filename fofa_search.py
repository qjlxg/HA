import requests
import base64
import json
import os
import sys

def fofa_search(email, key, query):
    """
    使用 FOFA API 进行搜索。

    Args:
        email (str): 您的 FOFA 注册邮箱。
        key (str): 您的 FOFA API 密钥。
        query (str): FOFA 搜索语法。

    Returns:
        dict: 包含搜索结果的字典，如果请求失败则返回 None。
    """
    if not all([email, key, query]):
        print("错误：邮箱、API 密钥和查询内容都不能为空。")
        return None
    
    # 对查询进行 Base64 编码
    try:
        base64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"查询编码失败: {e}")
        return None
    
    # 构建 API 请求 URL
    url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={base64_query}&size=10"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if data.get("error"):
            print("API 请求错误:", data.get("errmsg"))
            return None
            
        return data
        
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP 错误: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"请求发生错误: {req_err}")
    except json.JSONDecodeError:
        print("无法解析服务器响应，可能不是有效的 JSON 格式。")
    
    return None

def main():
    """主函数，用于从环境变量获取参数并调用搜索函数。"""
    # 从环境变量中获取 FOFA 邮箱、API 密钥和搜索关键词
    email = os.environ.get('FOFA_EMAIL')
    key = os.environ.get('FOFA_API_KEY')
    search_query = os.environ.get('FOFA_SEARCH_QUERY', 'domain="example.com"')
    
    if not all([email, key]):
        print("错误：请通过环境变量 FOFA_EMAIL 和 FOFA_API_KEY 设置您的邮箱和密钥。")
        sys.exit(1)

    print(f"正在搜索 FOFA，查询内容为: {search_query}")
    
    search_results = fofa_search(email, key, search_query)
    
    if search_results:
        print("\n搜索结果：")
        print(json.dumps(search_results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
