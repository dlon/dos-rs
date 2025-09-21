#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

TEMP_README=$(mktemp)
cargo readme > "$TEMP_README"

function diff_cmd {
    git diff --quiet --ignore-space-at-eol --no-index "$1" "$2"
}

if ! diff_cmd README.md "$TEMP_README" > /dev/null; then
    echo "❌ README.md is out of sync with lib.rs documentation"
    echo ""
    diff_cmd README.md "$TEMP_README" || true
    echo ""
    echo "To fix this, run: cargo readme > README.md"
    rm -f "$TEMP_README"
    exit 1
else
    rm -f "$TEMP_README"
    echo "README.md is up to date"
fi
