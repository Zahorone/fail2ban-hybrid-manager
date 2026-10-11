# Optional Easy!Appointments Apache hardening

This module is opt-in. The main Fail2Ban installer never changes arbitrary
websites or Apache virtual hosts. Use it only after confirming that the given
path is an Easy!Appointments installation served by the local Apache backend.

It protects the private Composer `vendor` tree and the private storage
directories, plus case-insensitive `config.php` and dot/tilde backup variants
in the selected application filesystem Directory. In `storage/uploads`, it disables indexes and CGI execution and
denies a deliberately bounded set of script-like filename suffixes:
`php[0-9]*`, `phtml`, `phar`, `cgi`, `pl`, `py`, and `sh`, including double
extensions such as `.php.jpg`. This list must be compared with the handlers
enabled on the target server; it is not a universal ban on every executable
file type. Public `/assets/vendor` is not affected.

## Preflight

The default command makes no changes and prints exact rendered snippets and
the three files/symlinks that apply would own. It requires an absolute safe
app root with `config.php` and the vendor/storage layout:

```bash
cd releases/v0.34
sudo python3 scripts/easyappointments-apache-hardening.py \
  --app-root /var/www/html/easyappointments \
  --backend-url http://127.0.0.1:8080
```

It refuses to proceed if a managed Apache snippet contains unknown content, a
conf-enabled entry points elsewhere, or `storage/uploads/.htaccess` exists.
The latter requires manual review because disabling overrides could silently
replace an application-specific upload policy.

Do not test port 80 when a reverse proxy such as Nginx Proxy Manager owns it.
Use the actual loopback Apache backend address.

## Apply and verification

```bash
sudo python3 scripts/easyappointments-apache-hardening.py \
  --app-root /var/www/html/easyappointments \
  --backend-url http://127.0.0.1:8080 \
  --apply
```

Before installation, the tool backs up the three target files and the exact
state of their enabled symlinks under `/var/backups/`. It runs
`apache2ctl configtest`, reloads Apache, and verifies private vendor paths,
query variants, storage, upload suffixes, the home page, login, and public
jQuery asset. Test files contain only harmless random text and are removed in
a `finally` block. Failure triggers automatic rollback.

The third file is `easyappointments-private-config.conf`; its enabled entry is
a symlink to that file. The rule is `FilesMatch (?i)^config\.php(?:[.~].*)?$`
with `Require all denied` scoped to the application Directory. A response of
200 with zero length alone is not proof that configuration source was leaked.
Existing unknown scan-review Apache snippets require review rather than silent
replacement. The universal Fail2Ban upgrade neither applies nor removes this
module. Application choice, webserver/proxy and Docker remain separate axes;
see `MODULE-ARCHITECTURE.md`.

Unit tests model HTTP responses and rollback files. They do not establish a real
Apache deployment, external IPv6 or reboot behavior; verify on a representative
backend before enabling this optional module.

The storage directories may already be protected by their shipped `.htaccess`;
a successful 403 test is therefore not evidence that storage was previously
exposed. Likewise, this module is not evidence that every application security
issue has been fixed.

## Manual rollback

Use the exact backup path printed during apply:

```bash
sudo python3 scripts/easyappointments-apache-hardening.py \
  --rollback /var/backups/easyappointments-apache-XXXXXXXX
```
