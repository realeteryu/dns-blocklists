#!/bin/bash
set -Eeuo pipefail

SOURCES_FILE="sources.txt"
OUTPUT_FILE="combined_raw.txt"

if [ ! -f "$SOURCES_FILE" ]; then
    echo "BŁĄD: Brak pliku $SOURCES_FILE"
    exit 1
fi

mkdir -p output

TEMP_DIR=$(mktemp -d ".download_sources.XXXXXX")

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

TEMP_OUTPUT="$TEMP_DIR/combined_raw.txt"

: > "$TEMP_OUTPUT"

SOURCE_COUNT=0
SUCCESS_COUNT=0
FAILED_COUNT=0

while IFS= read -r url || [ -n "$url" ]; do
    url="${url%$'\r'}"

    [[ -z "$url" || "$url" =~ ^[[:space:]]*# ]] && continue

    SOURCE_COUNT=$((SOURCE_COUNT + 1))
done < "$SOURCES_FILE"

if [ "$SOURCE_COUNT" -eq 0 ]; then
    echo "BŁĄD: Brak aktywnych źródeł w $SOURCES_FILE"
    exit 1
fi

MIN_SUCCESS=$(( (SOURCE_COUNT * 70 + 99) / 100 ))

echo "=== Pobieranie źródeł DNS ==="
echo "Skonfigurowane źródła: $SOURCE_COUNT"
echo "Wymagane udane pobrania: $MIN_SUCCESS"
echo

while IFS= read -r url || [ -n "$url" ]; do
    url="${url%$'\r'}"

    [[ -z "$url" || "$url" =~ ^[[:space:]]*# ]] && continue

    SOURCE_FILE="$TEMP_DIR/source_$((SUCCESS_COUNT + FAILED_COUNT + 1)).txt"

    echo "Pobieranie: $url"

    HTTP_STATUS="000"

    if HTTP_STATUS=$(curl -sSL \
        --retry 3 \
        --retry-delay 5 \
        --retry-connrefused \
        --connect-timeout 10 \
        --max-time 120 \
        -w "%{http_code}" \
        -o "$SOURCE_FILE" \
        "$url" 2>/dev/null); then
        :
    else
        HTTP_STATUS="${HTTP_STATUS:-000}"
    fi

    if [ "$HTTP_STATUS" = "200" ] && [ -s "$SOURCE_FILE" ]; then
        if head -c 512 "$SOURCE_FILE" |
            grep -qiE '<!doctype|<html|<head|<body'; then

            echo "BŁĄD ŹRÓDŁA: Odpowiedź HTML — pomijam."
            FAILED_COUNT=$((FAILED_COUNT + 1))

        else
            cat "$SOURCE_FILE" >> "$TEMP_OUTPUT"
            printf '\n' >> "$TEMP_OUTPUT"

            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            echo "OK: Źródło pobrane."
        fi
    else
        echo "BŁĄD ŹRÓDŁA: HTTP $HTTP_STATUS — pomijam."
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi

    rm -f "$SOURCE_FILE"

    echo
done < "$SOURCES_FILE"

echo "=== Podsumowanie pobierania ==="
echo "Wszystkie źródła: $SOURCE_COUNT"
echo "Pobrane poprawnie: $SUCCESS_COUNT"
echo "Nieudane: $FAILED_COUNT"
echo "Wymagane minimum: $MIN_SUCCESS"

if [ "$SUCCESS_COUNT" -lt "$MIN_SUCCESS" ]; then
    echo
    echo "BŁĄD: Za mało poprawnie pobranych źródeł."
    echo "Poprzedni plik $OUTPUT_FILE pozostaje bez zmian."
    exit 1
fi

if [ ! -s "$TEMP_OUTPUT" ]; then
    echo "BŁĄD: Zebrane dane są puste."
    exit 1
fi

mv -f "$TEMP_OUTPUT" "$OUTPUT_FILE"

echo
echo "Pobieranie zakończone pomyślnie."
echo "Gotowy plik: $OUTPUT_FILE"
