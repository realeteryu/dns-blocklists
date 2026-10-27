import re

raw_file = "combined_raw.txt"
allowlist_file = "allowlist.txt"
output_file = "output/doh_combined.txt"

MAX_DOMAIN_LENGTH = 253

# 1. Wczytaj allowlistę
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
    """Sprawdza, czy domena lub któryś z jej rodziców jest na allowliście."""
    if domain in allowlist:
        return True
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        parent = '.'.join(parts[i:])
        if parent in allowlist:
            return True
    return False

# 2. Parsuj surowe domeny z list
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
        # Usuń komentarze i zamień na małe litery
        line = line.split('#')[0].split('!')[0].strip().lower()
        if not line:
            continue

        # --- Obsługa formatów dnsmasq (address=/, server=/ i local=/) ---
        if line.startswith("address=/") or line.startswith("server=/") or line.startswith("local=/"):
            parts = line.split('/')
            if len(parts) > 1:
                line = parts[1]
        
        # --- Optymalizacja: szybsze czyszczenie stringów ---
        else:
            # Format hosts (używamy split, aby uniknąć problemów z wieloma spacjami)
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1") or line.startswith("::1"):
                parts = line.split()
                if len(parts) > 1:
                    line = parts[1]
            
            # Format Adblock (opcje $, prefiksy ||, sufiksy ^)
            if '$' in line: line = line.split('$')[0]
            if line.startswith('||'): line = line[2:]
            elif line.startswith('|'): line = line[1:]
            if '^' in line: line = line.split('^')[0]
            if line.startswith('*.'): line = line[2:]

        line = line.strip()

        if not line or line in ignored:
            continue

        # Defensywnie: odrzuć pozostałości HTML/XML
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

# 3. Aglomeracja subdomen
# Sortujemy od najkrótszych, żeby rodzice trafiali do zbioru przed dziećmi
sorted_domains = sorted(domains, key=len)
optimized_domains = set()

for d in sorted_domains:
    parts = d.split('.')
    is_redundant = False
    # Sprawdzaj tylko rodziców, nie TLD (range kończy się przed ostatnim elementem)
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

# 4. Zapisz wynik
with open(output_file, "w", encoding="utf-8") as f:
    for d in sorted(optimized_domains):
        f.write(d + "\n")

print(f"Zapisano do {output_file}")
