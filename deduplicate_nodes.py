# deduplicate_nodes.py
import os
import glob

def deduplicate_nodes(data_dir="data/", output_file="data/proxy_nodes_deduplicated.txt"):
    """
    Reads all proxy node files from a specified directory,
    removes duplicate entries, and writes the unique entries to an output file.
    """
    all_nodes = set()
    input_files = sorted(glob.glob(os.path.join(data_dir, "proxy_nodes_*.txt")))

    for file_path in input_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line:  # Only add non-empty lines
                        all_nodes.add(stripped_line)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

    try:
        os.makedirs(data_dir, exist_ok=True) # Ensure data directory exists
        with open(output_file, 'w', encoding='utf-8') as f:
            for node in sorted(list(all_nodes)): # Sort for consistent output
                f.write(node + '\n')
        print(f"Deduplication complete. Unique nodes written to {output_file}")
    except Exception as e:
        print(f"Error writing to output file {output_file}: {e}")

if __name__ == "__main__":
    deduplicate_nodes()
