# fail2ban-hybrid-manager

**Hybridný manažment pre Fail2Ban, nftables, UFW a automatizované opravy/migrácie**  
Verzia: **0.7.3**  
Autor: Peter Bakic ([zahor@tuta.io](mailto:zahor@tuta.io))

## Funkcie:

- Plná automatizácia synchronizácie Fail2Ban ↔️ nftables/UFW
- Jedným príkazom audit, repair, forced orphaned unban
- Skripty na repair databázy, firewall sets, incremental bany
- Podporuje cron, notifikácie a repair kit pre administrátorov

## Základné skripty

- `fail2ban_hybrid-v0.7.3-COMPLETE.sh` — hlavný audoit/repair tool
- `fail2ban_hybrid-ULTIMATE-setup-v0.7.3.sh` — setup/auto-install
- `repair-all-v0.7.3.sh`, `repair-failban-v0.7.3.sh`, `repair-nftables-v0.7.3.sh` — špecifické opravy

## Rýchla inštalácia (do `/usr/local/bin/f2b`)

## Rýchla inštalácia (do `/usr/local/bin/f2b`)

curl -sSL https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main/fail2ban_hybrid-v0.7.3-COMPLETE.sh > /usr/local/bin/f2b
chmod +x /usr/local/bin/f2b
source /usr/local/bin/f2b

text

## Viac info a detailné návody doplníme do `/docs` sekcie
