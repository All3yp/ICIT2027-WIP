#!/bin/sh
# Download the pinned RNS 1.5.7 source distribution from PyPI and verify its SHA-256.
set -e
cd "$(dirname "$0")/.."

EXPECTED_SHA256="2bb48232e0a10b59b2b21b60e76592362210cdabd343d7b97a3bf1aba22dd879"
ARCHIVE="artifacts/rns-1.5.7.tar.gz"

mkdir -p artifacts

python - <<'PY'
import json
import pathlib
import urllib.request

meta = json.load(urllib.request.urlopen("https://pypi.org/pypi/rns/1.5.7/json"))
url = next(item["url"] for item in meta["urls"] if item["packagetype"] == "sdist")
pathlib.Path("artifacts").mkdir(exist_ok=True)
urllib.request.urlretrieve(url, "artifacts/rns-1.5.7.tar.gz")
print("downloaded:", url)
PY

OBSERVED_SHA256=$(python - "$ARCHIVE" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for block in iter(lambda: handle.read(1 << 20), b""):
        digest.update(block)
print(digest.hexdigest())
PY
)

if [ "$OBSERVED_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "SHA-256 mismatch for $ARCHIVE" >&2
    echo "  expected: $EXPECTED_SHA256" >&2
    echo "  observed: $OBSERVED_SHA256" >&2
    exit 1
fi

echo "verified: $ARCHIVE"
echo "  sha256: $OBSERVED_SHA256"
