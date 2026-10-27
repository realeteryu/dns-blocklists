#!/bin/bash
set -eo pipefail

mkdir -p output
> combined_raw.txt

# Inicjalizacja allowlisty z nagłówkiem, jeśli nie istnieje
if [ ! -f allowlist.txt ]; then
  echo "# Dodaj domeny do wyjątków (jedna na linię)" > allowlist.txt
fi

# Sprawdź, czy plik źródeł istnieje
if [ ! -f sources.txt ]; then
  echo "BŁĄD: Brak pliku sources.txt"
  exit 1
fi

while IFS= read -r url; do
  [[ -z "$url" || "$url" =~ ^# ]] && continue
  echo "Pobieranie: $url"

  HTTP_STATUS=$(curl -sL \
    --retry 3 --retry-delay 5 --retry-connrefused \
    --connect-timeout 10 --max-time 120 \
    -w "%{http_code}" -o temp_list.txt "$url" 2>/dev/null)
  [ -z "$HTTP_STATUS" ] && HTTP_STATUS="000"

  if [ "$HTTP_STATUS" = "200" ] && [ -s temp_list.txt ]; then
    # Odrzuć odpowiedzi HTML (np. strony błędów zwracające 200)
    if head -c 512 temp_list.txt | grep -qiE '<!doctype|<html|<head|<body'; then
      echo "Ostrzeżenie: $url zwrócił HTML - pomijam."
    else
      cat temp_list.txt >> combined_raw.txt
      echo "" >> combined_raw.txt
    fi
  else
    echo "Ostrzeżenie: Błąd pobierania ($HTTP_STATUS) dla $url - pomijam."
  fi
  rm -f temp_list.txt
done < sources.txt

if [ ! -s combined_raw.txt ]; then
  echo "BŁĄD: Pobrane listy są puste!"
  exit 1
fi

echo "Pobieranie zakończone. Plik combined_raw.txt jest gotowy."
