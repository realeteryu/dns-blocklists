import ipaddress
import re
import sys
import msgpack

from pathlib import Path


RAW_FILE = Path("combined_raw.txt")
ALLOWLIST_FILE = Path("allowlist.txt")

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


def load_allowlist():
    """Wczytuje i waliduje wyjątki użytkownika."""

    if not ALLOWLIST_FILE.exists():
        raise FileNotFoundError(
            f"Brak pliku {ALLOWLIST_FILE}. "
            "Nie można bezpiecznie zbudować listy bez allowlisty."
        )

    allowlist = set()

    with ALLOWLIST_FILE.open(
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
                    f"Nieprawidłowy wpis allowlisty "
                    f"(linia {line_number}): {line}"
                )

            allowlist.add(domain)

    return allowlist


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
    """
    Obsługuje wyłącznie jednoznaczne reguły domenowe AdBlock.

    Wyjątki @@ nie są automatycznie przenoszone
    do allowlisty użytkownika.
    """

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


def optimize_blocklist(block_domains, allowlist):
    """
    Usuwa redundantne blokady, zachowując semantykę
    najbardziej szczegółowej reguły.

    Reguła allow lub block o największej szczegółowości
    decyduje o wyniku dla danej domeny.
    """

    effective_rules = {
        domain: "allow"
        for domain in allowlist
    }

    optimized = set()

    sorted_domains = sorted(
        block_domains,
        key=lambda domain: (
            domain.count("."),
            len(domain),
            domain,
        ),
    )

    for domain in sorted_domains:

        if domain in allowlist:
            continue

        parts = domain.split(".")
        nearest_rule = None

        for index in range(1, len(parts)):
            parent = ".".join(parts[index:])

            if parent in effective_rules:
                nearest_rule = effective_rules[parent]
                break

        if nearest_rule == "block":
            continue

        optimized.add(domain)
        effective_rules[domain] = "block"

    return optimized


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


def validate_outputs(blocklist, allowlist, txt_data, blocklist_data, allowlist_data):
    """Sprawdza zgodność danych przed zapisaniem wyników."""

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
            "Ta sama domena znajduje się na blokliście i allowliście."
        )

    for domain in decoded_blocklist:
        if normalize_domain(domain) != domain:
            raise ValueError(
                f"Nieprawidłowa domena w wyniku: {domain}"
            )


def main():
    print("=== DNS Blocklist Builder ===")

    allowlist = load_allowlist()

    print(f"Wyjątki użytkownika: {len(allowlist)}")

    block_domains, stats = load_block_domains()

    print(f"Surowych linii: {stats['raw_lines']}")
    print(f"Poprawnych domen: {len(block_domains)}")
    print(f"Odrzuconych wpisów: {stats['invalid']}")
    print(f"Pominiętych linii: {stats['ignored']}")

    optimized = optimize_blocklist(
        block_domains,
        allowlist,
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
    print(f"Przed optymalizacją: {len(block_domains)}")
    print(f"Po optymalizacji: {len(optimized)}")
    print(
        "Usunięte redundantne blokady: "
        f"{len(block_domains) - len(optimized)}"
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
