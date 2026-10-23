import re, sys, pathlib

text = pathlib.Path(sys.argv[1]).read_text()
parts = re.split(r"^={10,}\n=== (.+?)\n={10,}\n", text, flags=re.M)
for i in range(1, len(parts) - 1, 2):
    p = pathlib.Path(parts[i])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(parts[i + 1])
    print("wrote", p)
