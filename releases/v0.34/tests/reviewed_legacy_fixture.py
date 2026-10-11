"""Minimal reviewed prior variants; no full server snapshot, domains or secrets."""
import hashlib


def variants(root):
    legacy = root.parent / "v0.33"
    wrapper = (legacy / "scripts/f2b-wrapper-v033.sh").read_text()
    wrapper = wrapper.replace('}\n\ncanonical_ips()', '}\ncanonical_ips()')
    for verb in ('list set', 'delete element', 'add element'):
        for variable in ('$F2BTABLE', '${F2BTABLE}'):
            wrapper = wrapper.replace('nft ' + verb + ' ' + variable + ' ', 'nft ' + verb + '  ' + variable + '  ')
    wrapper = wrapper.replace('nft list set  $F2BTABLE  "$set_to_check"', 'nft list set $F2BTABLE "$set_to_check"')
    wrapper = wrapper.replace('nft -j list set $F2BTABLE "$set"', 'nft -j list set  $F2BTABLE  "$set"')
    wrapper = wrapper.replace('sudo /usr/bin/python3 /usr/local/sbin/f2b-ipv6-sync.py || {\n'
        '    log_error "IPv6 sync failed; existing bans preserved where possible"\n    return 1\n  }',
        'sudo /usr/bin/python3 /usr/local/sbin/f2b-ipv6-sync.py || { log_error "IPv6 sync failed; existing bans preserved where possible"; return 1; }')
    wrapper = wrapper.replace("grep -E '(^| )444( |$)' \\\n        | awk", "grep -E '(^| )404( |$)' \\\n        | awk")
    wrapper = wrapper.replace("grep -E '(^| )(404|444)( |$)'", "grep -E '\\b(404|444)\\b'")
    hook = (legacy / "scripts/f2b-docker-hook.sh").read_text().replace(
        '# Keep a shared IPv6 ban until the runtime union has been checked.\n'
        '    # Do not query Fail2Ban here: this hook runs inside its action worker.',
        '# IPv6 union is reconciled by f2b-ipv6-sync; another jail may still ban it.') + '\n'
    action = (root / 'actions/docker-sync-hook.conf').read_text()
    action = action[action.index('[Definition]'):].rstrip() + '\n'
    mail = (root / 'config/php-errors-mail.local').read_text()
    mail = '# Treat nginx error logs as text even if they contain binary bytes.\n' + mail[mail.index('[nginx-php-errors]'):]
    multiport = ('# Fail2Ban configuration file\n#\n# Author: Cyril Jaquier\n'
        '# Modified: Yaroslav O. Halchenko <debian@onerussian.com>\n'
        '# \t\t\tmade active on all ports from original iptables.conf\n'
        '# Modified: Alexander Belykh <albel727@ngs.ru>\n'
        '#                       adapted for nftables\n#\n'
        '# Obsolete: superseded by nftables[type=multiport]\n\n'
        '[INCLUDES]\n\nbefore = nftables.conf\n\n[Definition]\n\ntype = multiport')
    result = {'/usr/local/bin/f2b': wrapper.encode(), '/usr/local/sbin/f2b-docker-hook': hook.encode(),
            '/etc/fail2ban/action.d/docker-sync-hook.conf': action.encode(),
            '/etc/fail2ban/action.d/nftables-multiport.conf': multiport.encode(),
            '/etc/fail2ban/jail.d/99-php-errors-mail.local': mail.encode()}
    filters = {
        'f2b-botnet-signatures': r'''[Definition]
# NPM proxy/fallback log format. Match only explicit offensive tools, never the
# generic words bot/crawler/spider (which caught OAI-SearchBot previously).
failregex = (?i)^.* (?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (?:http|https) [^ ]+ "[^"]*" \[Client <HOST>\].* "[^"]*(?:sqlmap|nikto|masscan|nmap|zgrab|gobuster|dirbuster|nuclei|ffuf|feroxbuster|wpscan|acunetix|nessus)[^"]*".*$
ignoreregex =
''',
        'f2b-fuzzing-payloads': r'''[Definition]
# Encoded traversal/NUL/backslash fuzzing only. Ordinary words such as test,
# admin, hello or random are intentionally not attack indicators.
failregex = (?i)^.* (?:GET|POST|PUT|DELETE) (?:http|https) [^ ]+ "[^"]*(?:%%00|%%2e%%2e(?:%%2f|/)|\.\./\.\./|%%5c%%5c|%%%%2[ef])[^"]*" \[Client <HOST>\].*$
ignoreregex = ^.*booking/reschedule/.*$
              ^.*/assets/.*$
              ^.*index\.php.*$
              ^.*/static/.*$
''',
        'f2b-web-medium': r'''[Definition]
# This jail reads fallback_access.log only. Repeated malformed/unknown-host
# requests are useful here; normal application 404/429 responses are excluded.
failregex = ^.* (?:400|403|404|444) .* \[Client <HOST>\].*$
            ^.* (?:GET|POST) (?:http|https) [^ ]+ "/[^\"]*(?:\.git(?:/|$)|\.env(?:\.|$)|wp-config\.php|phpinfo\.php|shell\.php|cmd\.php|backdoor\.php)[^\"]*" \[Client <HOST>\].*$
ignoreregex = ^.*booking/reschedule/.*$
              ^.*/assets/.*$
''',
        'nginx-recon-optimized': r'''[Definition]
# Reconnaissance against the unknown-host fallback server. Avoid generic HEAD,
# all-404, and /.well-known matches that can include legitimate monitoring/ACME.
failregex = (?i)^.* (?:GET|POST) (?:http|https) [^ ]+ "/[^\"]*(?:\.git(?:/|$)|\.svn(?:/|$)|\.env(?:\.|$)|\.npmrc|composer\.lock|package-lock\.json|yarn\.lock|wp-config\.php|phpinfo\.php|shell\.php|cmd\.php|backdoor\.php|wp-admin(?:/|$)|wp-login\.php)[^\"]*" \[Client <HOST>\].*$
ignoreregex = ^.*?/\.well-known/acme-challenge/.*$
''',
    }
    result.update({'/etc/fail2ban/filter.d/' + name + '.conf': text.encode() for name, text in filters.items()})
    return result


def verify_variants(root, approved):
    result = variants(root)
    for target, content in result.items():
        digest = hashlib.sha256(content).hexdigest()
        assert digest in approved[target], (target, digest)
    return result
