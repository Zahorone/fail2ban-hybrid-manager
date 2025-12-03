#!/bin/bash
# Fix f2b-wrapper-v019.sh and repackage tar.gz
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER="$SCRIPT_DIR/f2b-wrapper-v019.sh"
BACKUP_DIR="$SCRIPT_DIR/backup-$(date +%Y%m%d-%H%M)"

echo "════════════════════════════════════════════════════"
echo " Fix f2b-wrapper-v019.sh & Repackage v0.19 → v0.20"
echo " Date: $(date)"
echo "════════════════════════════════════════════════════"
echo ""

# 1) Kontrola
if [ ! -f "$WRAPPER" ]; then
  echo "[ERROR] Nenájdený skript: $WRAPPER"
  exit 1
fi

# 2) Backup
mkdir -p "$BACKUP_DIR"
cp "$WRAPPER" "$BACKUP_DIR/"
cp "$SCRIPT_DIR/f2b-wrapper-v0.19-production-ready.tar.gz" "$BACKUP_DIR/" 2>/dev/null || true
echo "[OK] Backup: $BACKUP_DIR"
echo ""

# 3) Fix F2BTABLE
echo "[INFO] Fixujem F2BTABLE..."
sed -i 's/F2BTABLE="inet fail2ban-filter"/F2BTABLE="inet f2b-table"/' "$WRAPPER"
grep '^F2BTABLE=' "$WRAPPER"
echo ""

# 4) Fix SETMAP
echo "[INFO] Fixujem SETMAP..."
sed -i '/declare -A SETMAP=/,/)/{
s|"sshd"]="f2b-sshd"|"sshd"]="addr-set-sshd"|
s|"manualblock"]="f2b-manualblock"|"manualblock"]="addr-set-manualblock"|
s|"nginx-recon-bonus"]="f2b-nginx-recon-bonus"|"nginx-recon-bonus"]="addr-set-nginx-recon-bonus"|
s|"recidive"]="f2b-recidive"|"recidive"]="addr-set-recidive"|
s|"f2b-exploit-critical"]="f2b-exploit-critical"|"f2b-exploit-critical"]="addr-set-f2b-exploit-critical"|
s|"f2b-dos-high"]="f2b-dos-high"|"f2b-dos-high"]="addr-set-f2b-dos-high"|
s|"f2b-web-medium"]="f2b-web-medium"|"f2b-web-medium"]="addr-set-f2b-web-medium"|
s|"f2b-fuzzing-payloads"]="f2b-fuzzing-payloads"|"f2b-fuzzing-payloads"]="addr-set-f2b-fuzzing-payloads"|
s|"f2b-botnet-signatures"]="f2b-botnet-signatures"|"f2b-botnet-signatures"]="addr-set-f2b-botnet-signatures"|
s|"f2b-anomaly-detection"]="f2b-anomaly-detection"|"f2b-anomaly-detection"]="addr-set-f2b-anomaly-detection"|
}' "$WRAPPER"

sed -n '/declare -A SETMAP=/,/)/p' "$WRAPPER" | head -12
echo ""

# 5) Fix grep -qE → grep -qF
echo "[INFO] Fixujem grep pattern..."
sed -i 's/grep -qE "\$IP"/grep -qF "\$IP"/g' "$WRAPPER"
grep 'grep -qF "$IP"' "$WRAPPER" || echo "[WARN] Nenašiel som grep -qF (možno už bolo opravené)"
echo ""

# 6) Bump verzia wrappera v0.19 → v0.20
echo "[INFO] Bump verzie na v0.20..."
sed -i 's/v0\.19/v0.20/g' "$WRAPPER"
grep -m1 'v0.20' "$WRAPPER" || echo "[WARN] Nenašiel som string v0.20, skontroluj manuálne"
echo ""

# 7) Syntax check
echo "[INFO] Syntax check..."
bash -n "$WRAPPER" && echo "[OK] Syntax OK" || { echo "[ERROR] Syntax ERROR"; exit 1; }
echo ""

# 8) Repackage tar.gz
echo "[INFO] Repackujem tar.gz..."
cd "$SCRIPT_DIR"
NEW_TAR="f2b-wrapper-v0.20-production-ready.tar.gz"

tar -czf "$NEW_TAR" f2b-wrapper-v019.sh
sha256sum "$NEW_TAR" > "$NEW_TAR.sha256"

echo "[OK] New package: $NEW_TAR"
echo "[OK] SHA256: $(cat "$NEW_TAR.sha256")"
echo ""
echo "Hotovo. Nový balík môžeš použiť namiesto v0.19."
