import requests
import base64
import json
import os
import sys
from datetime import datetime

def fofa_search(email, key, query, output_path):
    """
    使用 FOFA API 进行搜索，并将结果保存到指定路径。

    Args:
        email (str): 您的 FOFA 注册邮箱。
        key (str): 您的 FOFA API 密钥。
        query (str): FOFA 搜索语法。
        output_path (str): 结果保存的文件夹路径。

    Returns:
        bool: 如果成功则返回 True，否则返回 False。
    """
    if not all([email, key, query]):
        print("错误：邮箱、API 密钥和查询内容都不能为空。")
        return False
    
    try:
        base64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"查询编码失败: {e}")
        return False
    
    url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={base64_query}&size=10000" # 将 size 调整到 10000 以获取更多结果
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if data.get("error"):
            print("API 请求错误:", data.get("errmsg"))
            return False
        
        # 确保输出文件夹存在
        os.makedirs(output_path, exist_ok=True)
        
        # 创建一个文件名，包含查询和时间戳，确保唯一性
        safe_query = query.replace('"', '').replace(' ', '_').replace('=', '_').replace('&', '_').replace('|', '_')[:50]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_query}_{timestamp}.json"
        full_path = os.path.join(output_path, filename)
        
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"搜索完成，结果已保存到 {full_path}")
        return True
        
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP 错误: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"请求发生错误: {req_err}")
    except json.JSONDecodeError:
        print("无法解析服务器响应，可能不是有效的 JSON 格式。")
    
    return False

def main():
    """主函数，用于从环境变量获取参数并调用搜索函数。"""
    email = os.environ.get('FOFA_EMAIL_SECRET')
    key = os.environ.get('FOFA_API_KEY_SECRET')
    search_query = os.environ.get('FOFA_SEARCH_QUERY')
    output_path = os.environ.get('OUTPUT_PATH', 'sub') # 新增：从环境变量获取输出路径
    
    if not all([email, key, search_query]):
        print("错误：请通过环境变量 FOFA_EMAIL_SECRET, FOFA_API_KEY_SECRET 和 FOFA_SEARCH_QUERY 设置参数。")
        sys.exit(1)

    print(f"正在搜索 FOFA，查询内容为: {search_query}")
    
    success = fofa_search(email, key, search_query, output_path)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
