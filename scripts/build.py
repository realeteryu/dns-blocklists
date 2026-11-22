from __future__ import annotations

import io
import ipaddress
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import dns.name
import dns.rdatatype
import dns.zone
import yaml
from abp.filters import parse_filterlist
from publicsuffix2 import PublicSuffixList


ROOT = Path(__file__).resolve().parent.parent

CONFIG_FILE = ROOT / "sources.yaml"
ALLOWLIST_FILE = ROOT / "custom" / "allowlist.txt"
CUSTOM_BLOCKLIST_FILE = ROOT / "custom" / "blocklist.txt"
OUTPUT_FILE = ROOT / "output" / "blocklist.txt"

USER_AGENT = "dns-blocklists-generator/1.0"
REQUEST_TIMEOUT = 30
MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3

BLOCKING_RPZ_TARGETS = {
    "",
    "rpz-drop",
    "rpz-nxdomain",
    "rpz-nodata",
    "rpz-tcp-only",
}

ADBLOCK_DOMAIN_PATTERN = re.compile(
    r"^\|\|([a-zA-Z0-9.-]+)\^(\$badfilter)?$",
    re.IGNORECASE,
)

DOMAIN_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class BuildError(Exception):
    """Błąd uniemożliwiający bezpieczne zbudowanie listy."""


def download_text(url: str) -> str:
    """Pobiera tekst z adresu HTTPS z ponawianiem prób."""

    if not isinstance(url, str) or not url.startswith("https://"):
        raise BuildError(f"Nieprawidłowy adres źródła: {url}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT,
            ) as response:
                data = response.read(MAX_DOWNLOAD_SIZE + 1)

                if len(data) > MAX_DOWNLOAD_SIZE:
                    raise BuildError(
                        f"Źródło przekracza limit 100 MB: {url}"
                    )

                text = data.decode("utf-8-sig")

                if not text.strip():
                    raise BuildError(
                        f"Pobrane źródło jest puste: {url}"
                    )

                beginning = text.lstrip().lower()

                if (
                    beginning.startswith("<!doctype html")
                    or beginning.startswith("<html")
                    or "<html" in beginning[:500]
                ):
                    raise BuildError(
                        f"Źródło zwróciło stronę HTML zamiast listy: {url}"
                    )

                return text

        except BuildError:
            raise

        except (
            urllib.error.URLError,
            TimeoutError,
            UnicodeDecodeError,
            OSError,
        ) as error:
            if attempt == DOWNLOAD_ATTEMPTS:
                raise BuildError(
                    f"Nie udało się pobrać źródła {url}: {error}"
                ) from error

            time.sleep(attempt * 2)

    raise BuildError(f"Nie udało się pobrać źródła: {url}")


def normalize_domain(
    value: str,
    *,
    allow_single_label: bool = False,
) -> str | None:
    """Normalizuje i sprawdza pojedynczą domenę."""

    if not isinstance(value, str):
        return None

    domain = value.strip().lower()

    if not domain:
        return None

    if domain.startswith("*."):
        domain = domain[2:]

    domain = domain.rstrip(".")

    if not domain or len(domain) > 253:
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(domain) > 253:
        return None

    # Adresy IP nie są nazwami domen i nie mogą trafiać
    # do wynikowej listy DNS.
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return None

    labels = domain.split(".")

    if len(labels) < 2 and not allow_single_label:
        return None

    if any(
        not DOMAIN_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        return None

    return domain


def parse_domain_lines(
    text: str,
    *,
    allow_single_label: bool = False,
) -> set[str]:
    """Odczytuje zwykłą listę domen."""

    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "!", "//", ";")):
            continue

        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]

        if line.startswith("*."):
            line = line[2:]

        parts = line.split()

        if len(parts) >= 2:
            try:
                ipaddress.ip_address(parts[0])
                candidates = parts[1:]
            except ValueError:
                candidates = [parts[0]]
        else:
            candidates = [parts[0]]

        for candidate in candidates:
            domain = normalize_domain(
                candidate,
                allow_single_label=allow_single_label,
            )

            if domain:
                domains.add(domain)

    return domains


def parse_hosts(text: str) -> set[str]:
    """Odczytuje plik hosts z adresami IPv4 lub IPv6."""

    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "!")):
            continue

        line = line.split("#", 1)[0].strip()
        parts = line.split()

        if len(parts) < 2:
            continue

        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue

        for candidate in parts[1:]:
            domain = normalize_domain(candidate)

            if domain:
                domains.add(domain)

    return domains


def parse_rpz(text: str) -> set[str]:
    """Odczytuje domeny blokujące z pliku DNS RPZ."""

    # Najpierw ustalamy origin strefy. Nie można zakładać dns.name.root:
    # rekord SOA musi znajdować się na wierzchołku właściwej strefy.
    origin_match = re.search(
        r"(?im)^\s*\$ORIGIN\s+(\S+)",
        text,
    )

    if origin_match:
        origin_text = origin_match.group(1)
    else:
        # W plikach bez $ORIGIN nazwa właściciela rekordu SOA
        # może wskazać wierzchołek strefy.
        soa_match = re.search(
            r"(?im)^\s*(\S+)\s+(?:(?:\d+)\s+)?"
            r"(?:(?:IN|CH|HS)\s+)?SOA\b",
            text,
        )

        if not soa_match:
            raise BuildError(
                "Nie można ustalić origin strefy RPZ: "
                "brakuje dyrektywy $ORIGIN i rekordu SOA."
            )

        soa_owner = soa_match.group(1)

        if soa_owner == "@":
            # W części poprawnych plików RPZ wierzchołek strefy
            # jest zapisany jako @, bez jawnego $ORIGIN. Ponieważ
            # do wyniku potrzebujemy wyłącznie względnych nazw
            # właścicieli rekordów, używamy technicznego origin.
            # Nie próbujemy wyprowadzać origin z MNAME lub RNAME SOA.
            origin_text = "rpz.invalid."
        else:
            origin_text = soa_owner

    try:
        origin = dns.name.from_text(
            origin_text,
            origin=dns.name.root,
        )
    except Exception as error:
        raise BuildError(
            f"Nieprawidłowy origin strefy RPZ: {origin_text}"
        ) from error

    try:
        zone = dns.zone.from_text(
            text,
            origin=origin,
            relativize=True,
            check_origin=False,
            allow_include=False,
        )
    except Exception as error:
        raise BuildError(
            f"Nie udało się odczytać strefy RPZ: {error}"
        ) from error

    if zone.origin is None:
        raise BuildError("Nie można ustalić origin strefy RPZ.")

    has_soa = any(
        rdataset.rdtype == dns.rdatatype.SOA
        for _, rdataset in zone.iterate_rdatasets()
    )

    if not has_soa:
        raise BuildError("Plik RPZ nie zawiera rekordu SOA.")

    domains = set()

    for name, rdataset in zone.iterate_rdatasets():
        if rdataset.rdtype != dns.rdatatype.CNAME:
            continue

        if name.is_absolute():
            if not name.is_subdomain(zone.origin):
                continue

            relative_name = name.relativize(zone.origin)
        else:
            relative_name = name

        owner = relative_name.to_text().rstrip(".")

        if not owner or owner == "@":
            continue

        labels = owner.split(".")

        if any(label.startswith("rpz-") for label in labels):
            continue

        # Reguły wildcard pomijamy, ponieważ nie oznaczają
        # bezpiecznie blokady całej domeny nadrzędnej.
        if owner.startswith("*."):
            continue

        blocked = any(
            record.target.to_text().lower().rstrip(".")
            in BLOCKING_RPZ_TARGETS
            for record in rdataset
        )

        if not blocked:
            continue

        domain = normalize_domain(owner)

        if domain:
            domains.add(domain)

    return domains


def parse_adblock(text: str) -> set[str]:
    """
    Odczytuje proste reguły blokowania całej domeny.

    Obsługuje $badfilter, który wyłącza odpowiadającą mu
    prostą regułę blokującą.

    Pomija wyjątki, reguły kosmetyczne, wyrażenia regularne,
    reguły URL i inne konstrukcje, których nie da się
    bezpiecznie przekształcić w blokadę DNS.
    """

    blocked_domains = set()
    disabled_domains = set()

    try:
        filters = parse_filterlist(io.StringIO(text))

        for item in filters:
            if not hasattr(item, "action"):
                continue

            if item.action != "block":
                continue

            match = ADBLOCK_DOMAIN_PATTERN.fullmatch(
                item.text.strip()
            )

            if not match:
                continue

            domain = normalize_domain(match.group(1))

            if not domain:
                continue

            if match.group(2):
                disabled_domains.add(domain)
            else:
                blocked_domains.add(domain)

    except Exception as error:
        raise BuildError(
            f"Nie udało się odczytać listy AdBlock: {error}"
        ) from error

    return blocked_domains - disabled_domains


def load_public_suffix_list(url: str) -> PublicSuffixList:
    """Pobiera i ładuje aktualną Public Suffix List."""

    text = download_text(url)

    try:
        psl = PublicSuffixList(
            io.StringIO(text),
            idna=True,
        )
    except Exception as error:
        raise BuildError(
            f"Nie udało się odczytać Public Suffix List: {error}"
        ) from error

    if not psl.tlds:
        raise BuildError(
            "Public Suffix List jest pusta lub nieprawidłowa."
        )

    return psl


def is_public_suffix(
    domain: str,
    psl: PublicSuffixList,
) -> bool:
    """Sprawdza, czy domena sama jest publicznym sufiksem."""

    try:
        suffix = psl.get_tld(domain, strict=True)
    except Exception as error:
        raise BuildError(
            f"Błąd sprawdzania Public Suffix List dla {domain}: {error}"
        ) from error

    return suffix is not None and suffix.lower() == domain.lower()


def load_custom_domains(path: Path) -> set[str]:
    """Odczytuje lokalny plik własnych domen."""

    if not path.is_file():
        raise BuildError(f"Brakuje pliku: {path.relative_to(ROOT)}")

    return parse_domain_lines(
        path.read_text(encoding="utf-8-sig"),
        allow_single_label=True,
    )


def apply_allowlist(
    domains: set[str],
    allowlist: set[str],
) -> set[str]:
    """Usuwa domeny z allowlisty oraz ich subdomeny."""

    return {
        domain
        for domain in domains
        if not any(
            domain == allowed
            or domain.endswith("." + allowed)
            for allowed in allowlist
        )
    }


def optimize_domains(domains: set[str]) -> set[str]:
    """Usuwa subdomeny, jeśli ich domena nadrzędna jest na liście."""

    optimized = set()

    for domain in sorted(
        domains,
        key=lambda item: (item.count("."), item),
    ):
        labels = domain.split(".")

        has_parent = any(
            ".".join(labels[index:]) in optimized
            for index in range(1, len(labels))
        )

        if not has_parent:
            optimized.add(domain)

    return optimized


def load_configuration() -> dict:
    """Wczytuje i sprawdza konfigurację YAML."""

    if not CONFIG_FILE.is_file():
        raise BuildError("Brakuje pliku sources.yaml.")

    try:
        config = yaml.safe_load(
            CONFIG_FILE.read_text(encoding="utf-8")
        )
    except yaml.YAMLError as error:
        raise BuildError(
            f"Nieprawidłowy plik sources.yaml: {error}"
        ) from error

    if not isinstance(config, dict):
        raise BuildError("Nieprawidłowa struktura sources.yaml.")

    suffix_url = config.get("public_suffix_list")
    sources = config.get("sources")

    if not isinstance(suffix_url, str):
        raise BuildError(
            "Brakuje adresu public_suffix_list w sources.yaml."
        )

    if not isinstance(sources, dict):
        raise BuildError(
            "Brakuje sekcji sources w sources.yaml."
        )

    if not suffix_url.startswith("https://"):
        raise BuildError(
            "Adres Public Suffix List musi używać HTTPS."
        )

    for source_type in ("rpz", "hosts", "domains", "adblock"):
        entries = sources.get(source_type, [])

        if not isinstance(entries, list):
            raise BuildError(
                f"Sekcja {source_type} musi być listą adresów URL."
            )

        for url in entries:
            if not isinstance(url, str) or not url.startswith("https://"):
                raise BuildError(
                    f"Nieprawidłowy adres URL w sekcji {source_type}."
                )

    return config


def build_blocklist() -> None:
    """Pobiera, przetwarza i zapisuje gotową listę."""

    config = load_configuration()

    print("Pobieranie Public Suffix List...")

    psl = load_public_suffix_list(
        config["public_suffix_list"]
    )

    sources = config["sources"]
    collected_domains = set()
    source_count = 0

    parsers = {
        "rpz": parse_rpz,
        "hosts": parse_hosts,
        "domains": parse_domain_lines,
        "adblock": parse_adblock,
    }

    for source_type, parser in parsers.items():
        for url in sources.get(source_type, []):
            source_count += 1
            print(f"Pobieranie [{source_type}]: {url}")

            text = download_text(url)
            parsed = parser(text)

            if not parsed:
                raise BuildError(
                    f"Źródło nie zawiera rozpoznanych domen: {url}"
                )

            collected_domains.update(parsed)

            print(f"  Rozpoznano domen: {len(parsed):,}")

    if source_count == 0:
        raise BuildError("Nie skonfigurowano żadnych źródeł.")

    print("Wczytywanie własnych list...")

    allowlist = load_custom_domains(ALLOWLIST_FILE)
    custom_blocklist = load_custom_domains(CUSTOM_BLOCKLIST_FILE)

    print(f"Allowlista: {len(allowlist):,}")
    print(f"Własne blokady: {len(custom_blocklist):,}")

    print("Sprawdzanie domen względem Public Suffix List...")

    # Własna lista jest kontrolowana rygorystycznie: błędny wpis
    # lub publiczny sufiks powinien zatrzymać budowanie.
    for domain in custom_blocklist:
        if "." not in domain and not is_public_suffix(domain, psl):
            raise BuildError(
                f"Nieprawidłowa domena na własnej liście blokującej: {domain}"
            )

        if is_public_suffix(domain, psl):
            raise BuildError(
                f"Wykryto publiczny sufiks na liście blokującej: {domain}"
            )

    # Zewnętrzne listy mogą zawierać publiczne sufiksy. Pomijamy je,
    # zamiast przerywać cały build; do wyniku trafiają tylko domeny.
    external_public_suffixes = {
        domain
        for domain in collected_domains
        if is_public_suffix(domain, psl)
    }

    if external_public_suffixes:
        collected_domains.difference_update(external_public_suffixes)
        print(
            "  Pominięto publiczne sufiksy ze źródeł zewnętrznych: "
            f"{len(external_public_suffixes):,}"
        )

    print("Stosowanie allowlisty...")

    # Łączymy domeny ze źródeł z własnymi blokadami.
    # Następnie stosujemy allowlistę, aby miała najwyższy priorytet.
    domains = collected_domains | custom_blocklist
    domains = apply_allowlist(domains, allowlist)

    print("Optymalizacja listy...")

    domains = optimize_domains(domains)

    if not domains:
        raise BuildError(
            "Wynikowa lista jest pusta. Przerwano zapis."
        )

    output = "\n".join(sorted(domains)) + "\n"

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=OUTPUT_FILE.parent,
            prefix=".blocklist-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(output)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(temporary_path, OUTPUT_FILE)

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    print()
    print("Budowanie zakończone pomyślnie.")
    print(f"Liczba domen: {len(domains):,}")
    print(f"Plik wynikowy: {OUTPUT_FILE.relative_to(ROOT)}")


def main() -> int:
    try:
        build_blocklist()
        return 0

    except BuildError as error:
        print(f"BŁĄD: {error}", file=sys.stderr)
        return 1

    except Exception as error:
        print(f"NIEOCZEKIWANY BŁĄD: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
