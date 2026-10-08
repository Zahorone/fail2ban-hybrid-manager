import pathlib
import re
import subprocess

source = (pathlib.Path(__file__).resolve().parents[1] / 'scripts/f2b-wrapper-v033.sh').read_text()
# Exercise actual patched functions with mocked read-only service commands.
functions = []
for name in ('validate_ip', 'canonical_ips', 'get_f2b_ips', 'ipv6_set_for_jail'):
    functions.append(re.search(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)[0])
test = 'set -e\n[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo "Bash 4+ required"; exit 1; }\n' + '\n'.join(functions) + r'''
log_error() { :; }
declare -A SETMAP=([web]=f2b-web [recidive]=f2b-recidive)
sudo() {
 if [[ "$1" == fail2ban-client ]]; then printf '%s\n' '2001:0db8:0:0::1 192.0.2.10'; return; fi
 [[ "${@: -1}" == addr6-set-web ]]
}
validate_ip 2001:db8::1 || exit 1
validate_ip 192.0.2.1 || exit 2
if validate_ip 999.1.1.1; then exit 3; fi
if validate_ip garbage; then exit 4; fi
[[ "$(ipv6_set_for_jail web)" == addr6-set-web ]] || exit 5
[[ "$(ipv6_set_for_jail recidive)" == f2b-recidive-v6 ]] || exit 6
get_f2b_ips web | grep -Fxq 2001:db8::1 || exit 7
get_f2b_ips web | grep -Fxq 192.0.2.10 || exit 8
'''
subprocess.run(['bash', '-c', test], check=True)
assert 'N6="$(get_nft_ips "$nftset6"' in source
print('PASS: wrapper IPv6 regression tests')
