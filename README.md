# dns-blocklists

Automatycznie aktualizowana lista blokad DNS dla resolvera [doh-worker](https://github.com/realeteryu/doh-worker). Pipeline na GitHub Actions pobiera źródła, normalizuje je, usuwa redundantne poddomeny i generuje gotowe pliki.

## Działanie

1. **Pobieranie:** Odczyt z `sources.txt`. Odrzucanie błędów HTTP i odpowiedzi HTML.
2. **Normalizacja:** Ekstrakcja czystych domen z formatów hosts, dnsmasq, adblock itp. Odrzucanie adresów IP i komentarzy.
3. **Aglomeracja:** Usuwanie poddomen, jeśli domena nadrzędna znajduje się na liście (np. `sub.domena.com` zostaje usunięte, jeśli `domena.com` jest blokowana).
4. **Wyjątki:** Filtrowanie przez `allowlist.txt`.
5. **Deploy:** Commit do repozytorium i wgranie plików bezpośrednio do Cloudflare KV.

## Obsługiwane formaty

Parser wyodrębnia domeny z następujących zapisów:
*   `domains`: `domena.com`
*   `wildcards`: `*.domena.com`
*   `hosts`: `0.0.0.0 domena.com`, `127.0.0.1 domena.com`
*   `dnsmasq`: `address=/domena.com/0.0.0.0`
*   `adblock`: `||domena.com^`

## Pliki wyjściowe

*   `output/doh_combined.txt` – lista czystych domen (jedna na linię).
*   `output/doh_combined.msgpack` – lista w formacie binarnym, zoptymalizowana pod kątem niskiego zużycia CPU w Workerze.

Lista tekstowa jest dostępna publicznie: [Raw URL](https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt).
