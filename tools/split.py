# LemonHaze420 - 2025

import re
from pathlib import Path

input_file = "file"
output_base_dir = Path("intermediate")
output_base_dir.mkdir(parents=True, exist_ok=True)

source_comment_re = re.compile(
    r'^//\s*(?P<path>([A-Z]:\\|/)?(?:[\w\s./\\-]+)\.(cpp|c|cc|cxx|h|hpp|s))',
    re.IGNORECASE
)

current_path = None
current_lines = []

def flush_current_file(current_path, lines):
    normalized_path = current_path.replace(":", "").lstrip("/\\")
    relative_path = Path(normalized_path.replace("\\", "/"))

    output_path = output_base_dir / relative_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'a', encoding='utf-8') as out_f:
        out_f.writelines(lines)

with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        match = source_comment_re.match(line)
        if match:
            new_path = match.group("path").strip()
            if current_path and current_lines:
                flush_current_file(current_path, current_lines)
                current_lines = []

            current_path = new_path
            current_lines.append(f"// {current_path}\n")
        else:
            current_lines.append(line)

if current_path and current_lines:
    flush_current_file(current_path, current_lines)

print(f"[INFO] Done. Output written to: {output_base_dir.resolve()}")
