import os

def clean_duplicate_nodes(file_path):
    """
    Reads a file, removes duplicate lines, and writes the unique lines back to the file.
    Each line is treated as a single node.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Use a set to store unique lines, preserving order for now if possible
        # Convert to a list of unique lines
        unique_lines = []
        seen = set()
        for line in lines:
            # Strip whitespace to treat " line" and "line " as the same
            stripped_line = line.strip()
            if stripped_line and stripped_line not in seen:
                unique_lines.append(line) # Keep original line ending
                seen.add(stripped_line)

        # Write the unique lines back to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)
        
        print(f"成功清理重复节点。唯一节点已保存到: {file_path}")
        return True
    except FileNotFoundError:
        print(f"错误：文件未找到在 {file_path}")
        return False
    except Exception as e:
        print(f"清理节点时发生错误: {e}")
        return False

if __name__ == "__main__":
    # The user specified the file path as data/a.isidomain.web.id.txt based on context
    # Adjust this path if your actual file is different
    nodes_file = os.path.join('data', 'a.isidomain.web.id.txt')
    clean_duplicate_nodes(nodes_file)
