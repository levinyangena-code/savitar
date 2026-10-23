#!/usr/bin/env bash
# Usage: save this dump as savitar-dump.txt, then:
#   bash extract.sh savitar-dump.txt
set -euo pipefail
infile="${1:?usage: extract.sh <dumpfile>}"

python3 - "$infile" <<'PY'
import re, sys, pathlib

text = pathlib.Path(sys.argv[1]).read_text()
parts = re.split(r'^={10,}\n=== (.+?)\n={10,}\n', text, flags=re.M)

i = 1
while i + 1 < len(parts):
    path, body = parts[i], parts[i + 1]
    if path == "extract.sh":
        i += 2
        continue
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.rstrip("\n") + "\n")
    print(f"wrote {p}")
    i += 2
PY

echo "Done. Now run:"
echo "  python -m venv .venv && source .venv/bin/activate"
echo "  pip install -e '.[dev]'"
echo "  pytest -q"
