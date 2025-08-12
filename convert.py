import yaml
import sys

def load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def main():
    if len(sys.argv) != 3:
        print("用法: python convert.py <测速结果.yaml> <原始config.yaml>")
        return

    result_file = sys.argv[1]
    original_file = sys.argv[2]

    results = load_yaml(result_file)
    original = load_yaml(original_file)

    name_map = {node['name']: node for node in original.get('proxies', [])}
    output_proxies = []

    for r in results:
        original_node = name_map.get(r['name'])
        if original_node:
            original_node['name'] = r['name']  # 保留测速结果里的名字
            output_proxies.append(original_node)

    output = {
        'proxies': output_proxies,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in output_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            }
        ],
        'rules': [
            'MATCH,自动选择'
        ]
    }

    with open('clash-use.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, sort_keys=False)

    print("✅ 已生成 clash-use.yaml，节点名已替换为测速结果中的格式")

if __name__ == '__main__':
    main()
