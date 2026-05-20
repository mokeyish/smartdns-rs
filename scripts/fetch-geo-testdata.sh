#!/usr/bin/env bash
#
# Fetch MetaCubeX geo data files into tests/test_data/ for the geodata
# feature tests. Tests gracefully skip when these files are absent, so
# running this script is optional — useful when you want to exercise the
# real protobuf/mmdb decoders.
#
# Source: https://github.com/MetaCubeX/meta-rules-dat (release: latest)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$REPO_ROOT/tests/test_data"
RELEASE="https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download"

mkdir -p "$DEST"

fetch() {
    local file="$1"
    local url="$RELEASE/$file"
    echo "==> $file"
    curl -sSfL --retry 3 -o "$DEST/$file.tmp" "$url"
    mv "$DEST/$file.tmp" "$DEST/$file"
}

fetch geosite.dat
fetch geoip.dat
fetch country.mmdb

echo ""
echo "Done. Files in $DEST:"
ls -lh "$DEST"/*.dat "$DEST"/*.mmdb 2>/dev/null || true
