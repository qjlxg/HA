# deduplicate_nodes.py
import os
import glob

def deduplicate_nodes(data_dir="data/", output_file="data/proxy_nodes_deduplicated.txt"):
    """
    Reads all proxy node files from a specified directory,
    removes duplicate entries based on the URL part before '#',
    and writes the unique entries (keeping the first encountered full line)
    to an output file.
    """
    unique_nodes_base = set()
    ordered_unique_nodes = [] # To preserve order of first appearance

    input_files = sorted(glob.glob(os.path.join(data_dir, "proxy_nodes_*.txt")))

    for file_path in input_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue

                    # Extract the base URL (part before #)
                    base_url = stripped_line.split('#', 1)[0]

                    if base_url not in unique_nodes_base:
                        unique_nodes_base.add(base_url)
                        ordered_unique_nodes.append(stripped_line)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

    try:
        os.makedirs(data_dir, exist_ok=True) # Ensure data directory exists
        with open(output_file, 'w', encoding='utf-8') as f:
            for node_line in ordered_unique_nodes:
                f.write(node_line + '\n')
        print(f"Deduplication complete. Unique nodes written to {output_file}")
    except Exception as e:
        print(f"Error writing to output file {output_file}: {e}")

if __name__ == "__main__":
    deduplicate_nodes()
