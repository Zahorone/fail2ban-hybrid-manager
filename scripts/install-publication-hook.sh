#!/bin/sh
# Explicit local opt-in. Refuse to replace any existing user hook.
set -eu
repo=$(git rev-parse --show-toplevel)
hook=$(git rev-parse --git-path hooks/pre-commit)
if [ -e "$hook" ] || [ -L "$hook" ]; then
    echo "Existing pre-commit hook preserved; integrate the staged scanner manually." >&2
    exit 1
fi
# This small installer creates only the requested Git hook, no server files.
cp "$repo/scripts/publication-pre-commit.sh" "$hook"
chmod 755 "$hook"
echo "Installed staged publication-safety gate. CI still verifies the full tree."
