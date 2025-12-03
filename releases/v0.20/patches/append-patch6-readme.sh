#!/bin/bash
# macOS-safe append to README-PATCHES.md

TARGET="README-PATCHES.md"

{
echo ""
echo "### ❌ CHYBA 6: Wrapper používa zlý názov docker-block setu"
echo "**Lokácia:** /usr/local/bin/f2b (functions: block-port, unblock-port, list-blocked-ports)"
echo "**Problém:** Wrapper používa \`docker-blocked-ports\`, ale skutočný názov je \`blocked_ports\`"
echo "**Oprava:** sed replace v wrapperi"
echo ""
echo "**Testovanie:**"
echo '```
echo "sudo f2b manage block-port 8081"
echo "sudo f2b manage list-blocked-ports"
echo "sudo f2b manage unblock-port 8081"
echo '```'
echo ""
echo "**Patch:**"
echo '```
echo "bash patches/05-fix-wrapper-docker-set-name.sh"
echo '```'
} >> "$TARGET"

echo "✅ $TARGET updated"
