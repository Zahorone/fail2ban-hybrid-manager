# WordPress-safe webshell sweep jail

`f2b-webshell-sweep` detects a rapid enumeration of missing executable files;
it is not a one-shot ban on PHP requests. An address is banned for 365 days
only after three matching final access responses within 30 seconds.

A matching event must be:

- an NPM access-log record whose final HTTP status is exactly `404`;
- a `GET` or `HEAD` request;
- a missing path ending in `.php`, `.phpN`, `.phtml`, or `.phar`, optionally
  followed by a query string.

The jail tails proxy-host, fallback, fallback HTTP and dead-host access logs.
It does not read error logs, so a parallel nginx error record cannot count as a
second attempt. A HTTP-to-HTTPS `301` is not a match; only the final HTTPS `404`
access record counts.

This design is safe for legitimate WordPress installations: successful or
redirected core and plugin PHP endpoints have 2xx/3xx statuses and do not
match. The core entry points `/index.php`, `/wp-login.php`,
`/wp-admin/admin-ajax.php`, and `/wp-cron.php` are also explicitly ignored if a
broken deployment returns 404. There is no general one-shot rule for
`/wp-admin`, `/wp-content`, `/plugins`, or arbitrary PHP requests.

The critical jail separately contains two exact one-shot indicators:

- `/this_is_a_new_hello_world.php`, with an optional query string;
- the known malicious
  `/wp-content/plugins/hellopress/wp_filemanager.php` basename through the
  precise high-risk webshell list.

The legitimate `wp-file-manager` plugin path is different and is not a
critical one-shot match.

The v0.33-to-v0.34 transaction installs both the filter and jail override. Its
existing full Fail2Ban backup captures the prior files and bans; rollback
removes newly introduced mapped files, restores previous configuration and
active bans, and never flushes the global nftables ruleset.
