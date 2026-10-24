# dns-blocklists 🛡️

Moja osobista, automatycznie aktualizowana i zoptymalizowana lista blokad DNS.

Pipeline na **GitHub Actions** cyklicznie pobiera źródła, czyści reguły z niepotrzebnych nakładek, usuwa redundantne poddomeny i generuje czysty plik gotowy dla resolvera DNS.

---

## Jak to działa?

* **Agregacja:** Pobiera listy z pliku `sources.txt` z weryfikacją poprawności pobierania (odrzuca błędy HTTP i strony HTML).
* **Normalizacja i czyszczenie:** Wyodrębnia czyste domeny z popularnych formatów. Odrzuca komentarze, puste linie, adresy IP oraz niepoprawne ciągi znaków.
* **Aglomeracja i deduplikacja (Python):** Automatycznie usuwa subdomeny, jeśli blokowana jest cała domena nadrzędna (np. usuwa `sub.bad.com`, gdy na liście znajduje się już `bad.com`). Znacząco zmniejsza to rozmiar pliku i przyspiesza wyszukiwanie.
* **Wyjątki:** Przepuszcza domeny zdefiniowane w `allowlist.txt` (całkowicie ignoruje je podczas blokowania).
* **Deploy:** Generuje zoptymalizowany plik, automatycznie commituje zmiany do repozytorium oraz **wysyła plik bezpośrednio do Cloudflare KV** (zapewniając błyskawiczny dostęp dla `doh-worker`).

---

## Obsługiwane formaty wejściowe

Skrypt został napisany tak, aby bezproblemowo przetwarzać najpopularniejsze formaty list dostępne w sieci. Parser potrafi wyodrębnić domenę z następujących zapisów:

* **`domains` (czyste domeny):** `domena.com`
* **`domainswild` / `wildcards`:** `*.domena.com`
* **`hosts`:** `0.0.0.0 domena.com`, `127.0.0.1 domena.com`, `::1 domena.com`
* **`dnsmasq`:** `address=/domena.com/0.0.0.0`, `server=/domena.com/`
* **`adblock` / `abp`:** `||domena.com^` (modyfikatory i opcje po znaku `$` są ignorowane)

---

## Plik wyjściowy

Gotowa lista w formacie czystych domen (jedna domena na linię), gotowa do wdrożenia na poziomie resolvera (np. Cloudflare Worker `doh-worker`, Pi-hole, AdGuard Home):

* **Plik w repo:** `output/doh_combined.txt`
* **Raw URL:** `https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt`
