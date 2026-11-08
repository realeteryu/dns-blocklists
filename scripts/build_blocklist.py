import re
import msgpack
from pathlib import Path

raw_file = "combined_raw.txt"
allowlist_file = "allowlist.txt"
output_txt = "output/doh_combined.txt"
output_bin = "output/doh_combined.msgpack"

MAX_DOMAIN_LENGTH = 253

# allowlista
allowlist = set()
try:
    with open(allowlist_file, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                allowlist.add(line)
except FileNotFoundError:
    pass

def is_allowlisted(domain, allowlist):
    if domain in allowlist:
        return True
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        parent = '.'.join(parts[i:])
        if parent in allowlist:
            return True
    return False

# parsowanie
domains = set()
raw_line_count = 0
domain_pattern = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
)
ignored = {
    'localhost', 'local', 'broadcasthost', 'ip6-localhost',
    'ip6-loopback', 'example.com', 'example.org', 'example.net'
}

with open(raw_file, "r", encoding="utf-8-sig", errors="ignore") as f:
    for line in f:
        raw_line_count += 1
        line = line.split('#')[0].split('!')[0].strip().lower()
        if not line:
            continue

        if line.startswith("address=/") or line.startswith("server=/") or line.startswith("local=/"):
            parts = line.split('/')
            if len(parts) > 1:
                line = parts[1]
        else:
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1") or line.startswith("::1"):
                parts = line.split()
                if len(parts) > 1:
                    line = parts[1]

            if '$' in line: line = line.split('$')[0]
            if line.startswith('||'): line = line[2:]
            elif line.startswith('|'): line = line[1:]
            if '^' in line: line = line.split('^')[0]
            if line.startswith('*.'): line = line[2:]

        line = line.strip()

        if not line or line in ignored:
            continue
        if '<' in line or '>' in line:
            continue
        if len(line) > MAX_DOMAIN_LENGTH:
            continue

        if domain_pattern.match(line):
            if not is_allowlisted(line, allowlist):
                domains.add(line)

print(f"Surowych linii: {raw_line_count}")
print(f"Po deduplikacji: {len(domains)}")

raw_count = len(domains)

# aglomeracja
sorted_domains = sorted(domains, key=len)
optimized_domains = set()

for d in sorted_domains:
    parts = d.split('.')
    is_redundant = False
    for i in range(1, len(parts) - 1):
        parent = '.'.join(parts[i:])
        if parent in optimized_domains:
            is_redundant = True
            break
    if not is_redundant:
        optimized_domains.add(d)

optimized_count = len(optimized_domains)
removed_count = raw_count - optimized_count
print(f"Po aglomeracji: {optimized_count} (usunięto {removed_count} redundantnych)")

# zapis
Path("output").mkdir(exist_ok=True)
with open(output_txt, "w", encoding="utf-8") as f:
    for d in sorted(optimized_domains):
        f.write(d + "\n")
print(f"Zapisano do {output_txt}")

with open(output_bin, "wb") as f:
    msgpack.packb(list(optimized_domains), use_bin_type=True)
print(f"Zapisano do {output_bin}")
