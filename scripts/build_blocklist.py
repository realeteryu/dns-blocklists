import ipaddress
import re
import sys
import msgpack

from pathlib import Path


RAW_FILE = Path("combined_raw.txt")
ALLOWLIST_FILE = Path("allowlist.txt")
CUSTOM_BLOCKLIST_FILE = Path("custom-blocklist.txt")

OUTPUT_DIR = Path("output")
OUTPUT_TXT = OUTPUT_DIR / "doh_combined.txt"
OUTPUT_BIN = OUTPUT_DIR / "doh_combined.msgpack"
OUTPUT_ALLOWLIST_BIN = OUTPUT_DIR / "doh_allowlist.msgpack"

MAX_DOMAIN_LENGTH = 253

DOMAIN_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

DNSMASQ_PATTERN = re.compile(
    r"^(address|server|local)=/([^/]+)/([^/]*)$"
)

ADBLOCK_DOMAIN_PATTERN = re.compile(
    r"^\|\|([a-z0-9.-]+)\^(?:\$[a-z0-9_.,=~-]+)?$"
)

ADBLOCK_ANCHORED_PATTERN = re.compile(
    r"^\|([a-z0-9.-]+)\|$"
)

IGNORED_DOMAINS = {
    "localhost",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "example.com",
    "example.org",
    "example.net",
}


def normalize_domain(value):
    """Normalizuje i waliduje pojedynczą nazwę domenową."""

    if not isinstance(value, str):
        return None

    domain = value.strip().lower().rstrip(".")

    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return None

    if any(char in domain for char in "/\\:@?#[]"):
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None

    if len(domain) > MAX_DOMAIN_LENGTH:
        return None

    labels = domain.split(".")

    if len(labels) < 2:
        return None

    if any(
        not label
        or len(label) > 63
        or not DOMAIN_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        return None

    if domain in IGNORED_DOMAINS:
        return None

    return domain


def load_domain_file(path, required=True):
    """Wczytuje plik zawierający po jednej domenie w wierszu."""

    if not path.exists():
        if required:
            raise FileNotFoundError(
                f"Brak wymaganego pliku: {path}"
            )

        print(
            f"UWAGA: Nie znaleziono {path}. "
            "Własne blokady nie zostaną dodane."
        )
        return set()

    domains = set()

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:

        for line_number, line in enumerate(file, 1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            domain = normalize_domain(line)

            if domain is None:
                raise ValueError(
                    f"Nieprawidłowa domena w {path} "
                    f"(linia {line_number}): {line}"
                )

            domains.add(domain)

    return domains


def load_allowlist():
    """Wczytuje wyjątki użytkownika."""

    return load_domain_file(ALLOWLIST_FILE)


def load_custom_blocklist():
    """Wczytuje ręczne blokady użytkownika."""

    return load_domain_file(
        CUSTOM_BLOCKLIST_FILE,
        required=False,
    )


def remove_inline_comment(line):
    """Usuwa komentarz rozpoczynający się po białym znaku."""

    match = re.search(r"\s+#", line)

    if match:
        return line[:match.start()].strip()

    return line.strip()


def parse_hosts_line(line):
    """Rozpoznaje wpis hosts i zwraca aliasy domenowe."""

    parts = line.split()

    if len(parts) < 2:
        return None

    try:
        ipaddress.ip_address(parts[0])
    except ValueError:
        return None

    aliases = []

    for item in parts[1:]:
        if item.startswith("#"):
            break

        aliases.append(item)

    return aliases


def parse_dnsmasq_line(line):
    """Rozpoznaje obsługiwane wpisy dnsmasq."""

    match = DNSMASQ_PATTERN.fullmatch(line)

    if not match:
        return None

    record_type, domain, target = match.groups()

    if not domain:
        return []

    if record_type == "address" and target:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return []

    return [domain]


def parse_adblock_line(line):
    """Rozpoznaje jednoznaczne reguły domenowe AdBlock."""

    if line.startswith("@@"):
        return []

    match = ADBLOCK_DOMAIN_PATTERN.fullmatch(line)

    if match:
        return [match.group(1)]

    match = ADBLOCK_ANCHORED_PATTERN.fullmatch(line)

    if match:
        return [match.group(1)]

    if line.startswith(("||", "|")):
        return []

    return None


def parse_source_line(line):
    """Rozpoznaje obsługiwane formaty źródeł."""

    line = line.strip().lower()

    if not line or line.startswith("#") or line.startswith("!"):
        return []

    line = remove_inline_comment(line)

    if not line:
        return []

    hosts = parse_hosts_line(line)

    if hosts is not None:
        return hosts

    dnsmasq = parse_dnsmasq_line(line)

    if dnsmasq is not None:
        return dnsmasq

    adblock = parse_adblock_line(line)

    if adblock is not None:
        return adblock

    if line.startswith("*."):
        return [line[2:]]

    return [line]


def load_block_domains():
    """Parsuje źródła i zbiera poprawne domeny."""

    if not RAW_FILE.exists():
        raise FileNotFoundError(
            f"Brak pliku źródłowego: {RAW_FILE}"
        )

    domains = set()

    stats = {
        "raw_lines": 0,
        "accepted": 0,
        "invalid": 0,
        "ignored": 0,
    }

    with RAW_FILE.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as file:

        for line in file:
            stats["raw_lines"] += 1
            line = line.strip()

            if not line or line.startswith("#") or line.startswith("!"):
                stats["ignored"] += 1
                continue

            candidates = parse_source_line(line)

            if not candidates:
                stats["ignored"] += 1
                continue

            for candidate in candidates:
                domain = normalize_domain(candidate)

                if domain is None:
                    stats["invalid"] += 1
                    continue

                if domain not in domains:
                    domains.add(domain)
                    stats["accepted"] += 1

    if not domains:
        raise ValueError(
            "Parser nie znalazł żadnej poprawnej domeny."
        )

    return domains, stats


def optimize_blocklist(
    block_domains,
    allowlist,
    custom_blocklist=None,
):
    """
    Redukuje redundantne reguły.

    Zasady:
    - najbardziej szczegółowa domena wygrywa;
    - przy identycznej domenie ręczna reguła wygrywa
      z regułą zewnętrzną;
    - ręczna blokada i ręczny wyjątek tej samej domeny
      są konfliktem;
    - redundantne reguły o tej samej akcji są usuwane.
    """

    if custom_blocklist is None:
        custom_blocklist = set()

    conflict = allowlist & custom_blocklist

    if conflict:
        domains = ", ".join(sorted(conflict))

        raise ValueError(
            "Konflikt: te same domeny znajdują się "
            f"w ręcznej blokadzie i allowliście: {domains}"
        )

    rules = {}

    for domain in block_domains:
        rules[domain] = ("block", 1)

    for domain in allowlist:
        rules[domain] = ("allow", 2)

    for domain in custom_blocklist:
        rules[domain] = ("block", 3)

    optimized_blocks = set()
    optimized_allows = set()

    effective_rules = {}

    sorted_rules = sorted(
        rules.items(),
        key=lambda item: (
            item[0].count("."),
            len(item[0]),
            item[0],
        ),
    )

    for domain, (action, priority) in sorted_rules:

        parts = domain.split(".")
        inherited_action = None

        for index in range(1, len(parts)):
            parent = ".".join(parts[index:])

            if parent in effective_rules:
                inherited_action = effective_rules[parent]
                break

        if inherited_action == action:
            effective_rules[domain] = action
            continue

        effective_rules[domain] = action

        if action == "block":
            optimized_blocks.add(domain)
        else:
            optimized_allows.add(domain)

    return optimized_blocks


def write_atomic(path, data):
    """Zapisuje plik tymczasowo, a następnie podmienia wynik."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:
        temporary_path.write_bytes(data)
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def validate_outputs(
    blocklist,
    allowlist,
    txt_data,
    blocklist_data,
    allowlist_data,
):
    """Sprawdza zgodność wyników przed zapisem."""

    decoded_txt = txt_data.decode("utf-8").splitlines()

    decoded_blocklist = msgpack.unpackb(
        blocklist_data,
        raw=False,
    )

    decoded_allowlist = msgpack.unpackb(
        allowlist_data,
        raw=False,
    )

    if decoded_txt != sorted(blocklist):
        raise ValueError(
            "TXT nie odpowiada wygenerowanej liście domen."
        )

    if decoded_blocklist != sorted(blocklist):
        raise ValueError(
            "MessagePack bloklisty nie odpowiada TXT."
        )

    if decoded_allowlist != sorted(allowlist):
        raise ValueError(
            "MessagePack allowlisty zawiera niezgodne dane."
        )

    if set(decoded_blocklist) & set(decoded_allowlist):
        raise ValueError(
            "Ta sama domena znajduje się w obu wynikach."
        )

    for domain in decoded_blocklist + decoded_allowlist:
        if normalize_domain(domain) != domain:
            raise ValueError(
                f"Nieprawidłowa domena w wyniku: {domain}"
            )


def main():
    print("=== DNS Blocklist Builder ===")

    allowlist = load_allowlist()
    custom_blocklist = load_custom_blocklist()

    block_domains, stats = load_block_domains()

    print(f"Źródłowe domeny: {len(block_domains)}")
    print(f"Własne blokady: {len(custom_blocklist)}")
    print(f"Wyjątki użytkownika: {len(allowlist)}")
    print(f"Surowych linii: {stats['raw_lines']}")
    print(f"Odrzuconych wpisów: {stats['invalid']}")
    print(f"Pominiętych linii: {stats['ignored']}")

    all_block_domains = block_domains | custom_blocklist

    optimized = optimize_blocklist(
        block_domains,
        allowlist,
        custom_blocklist,
    )

    if not optimized:
        raise ValueError(
            "Końcowa lista blokad jest pusta."
        )

    sorted_blocklist = sorted(optimized)
    sorted_allowlist = sorted(allowlist)

    txt_data = (
        "\n".join(sorted_blocklist) + "\n"
    ).encode("utf-8")

    blocklist_data = msgpack.packb(
        sorted_blocklist,
        use_bin_type=True,
    )

    allowlist_data = msgpack.packb(
        sorted_allowlist,
        use_bin_type=True,
    )

    validate_outputs(
        optimized,
        allowlist,
        txt_data,
        blocklist_data,
        allowlist_data,
    )

    write_atomic(OUTPUT_TXT, txt_data)
    write_atomic(OUTPUT_BIN, blocklist_data)
    write_atomic(OUTPUT_ALLOWLIST_BIN, allowlist_data)

    print()
    print("=== Podsumowanie ===")
    print(f"Przed optymalizacją: {len(all_block_domains)}")
    print(f"Po optymalizacji: {len(optimized)}")
    print(
        "Usunięte redundantne blokady: "
        f"{len(all_block_domains) - len(optimized)}"
    )
    print(f"Wyjątki: {len(allowlist)}")
    print()
    print(f"TXT: {OUTPUT_TXT}")
    print(f"MessagePack: {OUTPUT_BIN}")
    print(f"Allowlist MessagePack: {OUTPUT_ALLOWLIST_BIN}")
    print()
    print("Budowanie zakończone.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"BŁĄD: {error}", file=sys.stderr)
        sys.exit(1)
