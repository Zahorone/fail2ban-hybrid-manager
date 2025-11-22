
# fail2ban-hybrid-manager

**Hybridná správa Fail2Ban, nftables/UFW a automatizované filtre, plne automatizované pre moderné server infraštruktúry.**

---

## 🚀 Rýchla inštalácia

Nainštaluješ všetko jedným príkazom (tool aj voliteľne custom filtre):
```bash
curl -sSL https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main/install.sh | bash
```

- Skript automaticky stiahne hlavný tool do `/usr/local/bin/f2b`
- Pridá alias do tvojho shellu (`source /usr/local/bin/f2b`)
- Po inštalácii si môžeš zvoliť či chceš zároveň nainštalovať všetky custom regex filter .conf súbory do `/etc/fail2ban/filter.d/`  
  (odporúčané pre komplet funkčnú konfiguráciu)

---

## 🔄 Upgrade na najnovšiu verziu

Ako admin stačí spustiť:
```bash
curl -sSL https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main/upgrade.sh | bash
```

- Skript automaticky uloží backup starého toolu
- Stiahne najnovšiu verziu podľa repa
- Voliteľne synchronizuje/zaktualizuje všetky custom fail2ban filtre z GitHubu

---

## 🔧 Obnoviteľné filtre

Všetky pokročilé filtre máš pod adresárom `filters/`.  
Pre ručnú inštaláciu (ak by bolo treba len jeden filter):
```bash
sudo cp filters/nginx-npm-4xx.conf /etc/fail2ban/filter.d/
sudo cp filters/recidive.conf /etc/fail2ban/filter.d/
```
...atď pre každý filter

# Fail2Ban – Custom NGINX Proxy Manager Recon Filter (EasyAppointments Edition)

Tento filter je optimalizovaný pre log formát generovaný Nginx Proxy Managerom (Docker proxy-host logy).
Všetky legitímne cesty EasyAppointments (login, calendar, booking, assets, špeciálne endpointy) sú whitelisted v `.local` súbore – jednoducho upraviteľné podľa potreby.

## Použitie

- **nginx-recon.conf** – obsahuje failregex detekujúci skutočné recon/scanner útoky (.env, .git, shell.php, admin cesty...)
- **nginx-recon.local** – obsahuje ignoreregex pre whitelisting všetkých legitímnych requestov EasyAppointments (stačí upraviť tu, nie v .conf!)
- Log formát: `[Date] - Code - METHOD SCHEME DOMAIN "PATH" [Client IP] ...`

**Ak chceš whitelistiť ďalšie cesty, urob to priamo v `nginx-recon.local`.**
---

## 📁 Hlavné skripty v repozitári

- `fail2ban_hybrid-v0.7.3-COMPLETE.sh` – hlavný tool (audit, repair, sync, hybrid management)
- `fail2ban_hybrid-ULTIMATE-setup-v0.7.3.sh` – setup/inicializácia systémov
- `repair-all-v0.7.3.sh`, `repair-failban-v0.7.3.sh`, `repair-nftables-v0.7.3.sh` – opravné utility
- `install.sh` – inštalácia toolu a filtrov
- `upgrade.sh` – upgrade toolu a filtrov
- `filters/` – kompletná knižnica tvojich produktívnych custom fail2ban filtrov

---

## ❗ Odporúčanie pre adminov

Aktualizuj repo vždy keď meníš regex, logiku, alebo prichádzajú nové typy útokov.  
Každý server obnovíš najnovším toolom + všetky filtry do pár sekúnd = žiadny human error v pravidlách.

---

**Správca repa:**  
Peter Bakic (Zahorone)  
Contact: zahor@tuta.io

---

## ✨ Changelog, detailná dokumentácia a príklad použitia nájdeš v sekcii /docs (pridávame priebežne).
#### f2b_ufw_banned – ukáž aktuálnych UFW/Fail2Ban banov

