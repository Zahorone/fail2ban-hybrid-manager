# Critical RCE request detection

`f2b-exploit-critical` bans on the first unambiguous match for 31,536,000
seconds (365 days). The standard family-aware nftables action applies the same
policy to IPv4 and IPv6.

The v0.34 rules add two deliberately narrow request-target signatures:

- `/cgi-bin/` followed by at least two traversal components and a final
  `/bin/sh` or `/bin/bash`; supported dot representations are literal `.`,
  `%2e`, `%252e`, and the observed `%%32%65` scanner form;
- a target containing both `allow_url_include=1` and
  `auto_prepend_file=php://input`, in either order, with common percent-encoded
  forms of `=`, `:` and `/`.

The filter also covers three high-confidence groups in NPM access logs:

- direct reads of SSH, GnuPG, Google Cloud and Azure credential files listed
  in the filter, under any directory prefix;
- the exact known webshell basenames `wso.php`, `b374k.php`, `alfa.php`,
  `filemanager.php`, `priv8.php`, and `mini_shell.php`, plus only the observed
  `wp-content/plugins/hellopress/wp_filemanager.php` plugin path;
- `POST`, `PUT`, or `PATCH` of a final `.php`, `.phpN`, `.phtml`, or `.phar`
  filename below an `upload(s)`, `file(s)`, or `image(s)` path segment.

Ordinary image/PDF uploads, names such as `logo.php.png` or `.php.txt`, normal
application POSTs, and merely similar filenames are outside these signatures.

Matching is limited to the quoted request target in NPM access logs or the
quoted `request:` field in nginx warning/error logs. Payload text occurring
only in User-Agent or Referer is not a ban reason. Existing assets and
booking/reschedule exclusions remain, but they cannot suppress either complete
RCE signature.

The managed `config/exploit-critical-rce.local` override adds
`/opt/rustnpm/data/logs/*_error.log tail` alongside the access logs. `tail`
means historical error-log content is not replayed when the path is first
registered. The upgrade workflow installs the override without replacing the
site's main `jail.local`.

Regression coverage is in `tests/fixtures/exploit-critical-attacks.log` and
the related `exploit-critical-*.log` fixtures; CI executes all fixtures through
`fail2ban-regex` as well as the parser-level assertions. The high-risk fixture
adds 24 malicious and 13 benign access-log cases, including dangerous text only
in a Referer.
