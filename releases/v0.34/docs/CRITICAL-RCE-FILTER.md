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
`tests/fixtures/exploit-critical-benign.log`; CI executes the fixtures through
`fail2ban-regex` as well as the parser-level assertions.
