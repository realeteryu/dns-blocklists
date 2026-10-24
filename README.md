# dns-blocklists 🛡️

Moja osobista, automatycznie aktualizowana i zoptymalizowana lista blokad DNS.

Pipeline na **GitHub Actions** cyklicznie pobiera źródła, czyści reguły z niepotrzebnych nakładek, usuwa redundantne poddomeny i generuje czysty plik gotowy dla resolvera DNS.

---

## Jak to działa?

* **Agregacja:** Pobiera listy ze `sources.txt` z walidacją pobierania.
* **Sanityzacja i normalizacja:** Wyodrębnia czyste domeny z popularnych formatów, odrzuca komentarze, puste linie, adresy IP oraz niepoprawne domeny.
* **Wyjątki:** Przepuszcza domeny zdefiniowane w `allowlist.txt` (ignoruje je podczas blokowania).
* **Deduplikacja (Python):** Automatycznie usuwa subdomeny, jeśli blokowana jest cała domena nadrzędna (np. usuwa `sub.bad.com`, gdy istnieje `bad.com`).
* **Deploy:** Generuje zoptymalizowany plik, automatycznie commituje zmiany do repozytorium oraz **wysyła plik bezpośrednio do Cloudflare KV** (zapewniając błyskawiczny dostęp dla `doh-worker`).

---

## Obsługiwane formaty wejściowe

Skrypt potrafi sparsować i znormalizować listy w następujących formatach:

* **Czyste domeny:** `domena.com`
* **Wildcard:** `*.domena.com`
* **Format hosts:** `0.0.0.0 domena.com`, `127.0.0.1 domena.com`
* **Format dnsmasq:** `address=/domena.com/0.0.0.0`, `server=/domena.com/`
* **Format Adblock/uBlock:** `||domena.com^` (modyfikatory po znaku `$` są ignorowane)

---

## Plik wyjściowy

Gotowa lista do wdrożenia na poziomie resolvera (np. Cloudflare Worker `doh-worker`, Pi-hole, AdGuard Home):

* **Plik w repo:** `output/doh_combined.txt`
* **Raw URL:** `https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt`
