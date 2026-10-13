#!/usr/bin/env python3
"""Transactional v0.34-dev canary update to changeset 227c393."""
from __future__ import annotations

import argparse, ast, datetime as dt, hashlib, importlib.util, ipaddress, json, os, re, shutil, sqlite3, subprocess, sys, tarfile, tempfile
from pathlib import Path

RELEASE = "0.34-dev"
TARGET_CHANGESET = "227c393"
BACKUP_LABEL = "v034dev-to-227c393"
JAIL = "f2b-webshell-sweep"
HTTP_JAILS = {'f2b-exploit-critical', 'f2b-webshell-sweep', 'f2b-dos-high',
              'f2b-web-medium', 'nginx-recon-bonus', 'f2b-fuzzing-payloads',
              'f2b-botnet-signatures', 'nginx-php-errors', 'f2b-anomaly-detection'}

class UpgradeError(RuntimeError): pass

def npm_log_kind(name):
    """Known HTTP logs only: never streams, backend logs or rotations."""
    match = re.fullmatch(r'(?:fallback(?:_http)?|dead-host|(?:proxy|redirection|dead)-host-[0-9]+)_(access|error)\.log', name)
    return match[1] if match else None

def npm_logs(directory):
    result = {'access': [], 'error': []}
    for file in sorted(Path(directory).glob('*.log')):
        kind = npm_log_kind(file.name)
        if kind and file.is_file() and not file.is_symlink(): result[kind].append(str(file))
    return result

def npm_required(jail):
    if jail == 'f2b-exploit-critical': return {'access', 'error'}
    return {'error'} if jail == 'nginx-php-errors' else {'access'}

def load_sync():
    script = Path('/usr/local/sbin/f2b-ipv6-sync.py')
    if not script.is_file(): script = package_root() / 'scripts/f2b-ipv6-sync.py'
    spec = importlib.util.spec_from_file_location('diagnostic_sync', script)
    sync = importlib.util.module_from_spec(spec); spec.loader.exec_module(sync)
    return sync

def verify_npm_coverage(jails, sync=None):
    selected = set(jails) & HTTP_JAILS
    if not selected: return
    sync = sync or load_sync()
    for jail in sorted(selected):
        files = sync.call(['get', jail, 'logpath'])
        if not isinstance(files, list) or not files or not all(isinstance(f, str) for f in files):
            raise UpgradeError('Invalid runtime log paths: ' + jail)
        kinds = {npm_log_kind(Path(f).name) for f in files}
        if None in kinds or not npm_required(jail) <= kinds:
            raise UpgradeError('Incomplete HTTP access/error coverage: ' + jail)
        if any(not Path(f).is_file() or Path(f).is_symlink() for f in files):
            raise UpgradeError('Missing/unsafe runtime HTTP log: ' + jail)

def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise UpgradeError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}\n{result.stderr}")
    return result

def package_root(): return Path(__file__).resolve().parents[1]

def sources(root):
    payload = root / "payload"
    if payload.is_dir():
        return {"critical": payload/"f2b-exploit-critical.conf", "sweep": payload/"f2b-webshell-sweep.conf",
                "jail": payload/"99-webshell-sweep.local", "wrapper": payload/"f2b",
                "sync": payload/"f2b-ipv6-sync.py", "hook": payload/"f2b-docker-hook"}
    return {"critical": root/"filters/f2b-exploit-critical.conf", "sweep": root/"filters/f2b-webshell-sweep.conf",
            "jail": root/"config/webshell-sweep.local", "wrapper": root/"scripts/f2b-wrapper-v034.sh",
            "sync": root/"scripts/f2b-ipv6-sync.py", "hook": root/"scripts/f2b-docker-hook.sh"}

def install_map(root, system_root=Path("/")):
    src = sources(root)
    dst = {"critical": "etc/fail2ban/filter.d/f2b-exploit-critical.conf",
           "sweep": "etc/fail2ban/filter.d/f2b-webshell-sweep.conf",
           "jail": "etc/fail2ban/jail.d/99-webshell-sweep.local", "wrapper": "usr/local/bin/f2b",
           "sync": "usr/local/sbin/f2b-ipv6-sync.py", "hook": "usr/local/sbin/f2b-docker-hook"}
    mapping={system_root/path: src[name] for name, path in dst.items()}
    mapping[system_root/"usr/local/libexec/f2b-runtime-verify.py"]=Path(__file__).resolve()
    return mapping

def validate_payload(root):
    src = sources(root)
    missing = [str(p) for p in src.values() if not p.is_file()]
    if missing: raise UpgradeError("Missing payload: " + ", ".join(missing))
    if "/this_is_a_new_hello_world\\.php" not in src["critical"].read_text():
        raise UpgradeError("Missing hello-world IOC")
    jail = src["jail"].read_text()
    for item in ("findtime = 30", "maxretry = 3", "bantime = 31536000"):
        if item not in jail: raise UpgradeError(f"Missing jail policy: {item}")
    if JAIL not in src["wrapper"].read_text(): raise UpgradeError("Wrapper lacks canary jail")
    for path in src.values():
        if re.search(r"^\s*flush\s+ruleset(?:\s|$)", path.read_text(errors="replace"), re.M):
            raise UpgradeError(f"Unsafe global flush: {path}")
    run("bash", "-n", str(src["wrapper"]))
    run("bash", "-n", str(src["hook"]))
    compile(src["sync"].read_text(), str(src["sync"]), "exec")

def parse_jails(text):
    for line in text.splitlines():
        if "Jail list:" in line: return [x.strip() for x in line.split("Jail list:",1)[1].split(",") if x.strip()]
    return []

def validate_dbfile(output):
    """Accept a plain value or Fail2Ban 1.0.2's labelled tree output."""
    value = output.strip()
    formatted = re.fullmatch(r"Current database file is:\n[ \t]*[`|]-[ \t]+([^\r\n]+)", value)
    if formatted: value = formatted[1].strip()
    if value == "None": return None
    if not re.fullmatch(r"/[^\r\n]+", value):
        raise UpgradeError("Unrecognized Fail2Ban dbfile response")
    if value != "/var/lib/fail2ban/fail2ban.sqlite3":
        raise UpgradeError("Custom dbfile requires an explicit backup plan: " + value)
    return value

def valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except ValueError: return False

def snapshot_bans():
    jails = parse_jails(run("fail2ban-client", "status").stdout)
    if not jails: raise UpgradeError("Fail2Ban returned no jails")
    result = {}
    for jail in jails:
        addresses = run("fail2ban-client", "get", jail, "banip").stdout.split()
        if not all(valid_ip(x) for x in addresses):
            raise UpgradeError("Malformed ban response: " + jail)
        result[jail] = sorted({str(ipaddress.ip_address(x)) for x in addresses})
    return result

def diagnostic_socket(command):
    # This deliberately has no dependency on the installed reconciler.
    if not command or command[0] not in {'status', 'get'}:
        raise UpgradeError('Diagnostic socket operation is not read-only')
    from fail2ban.client.csocket import CSocket
    socket = CSocket('/var/run/fail2ban/fail2ban.sock', timeout=15)
    try: response = socket.send(command)
    finally: socket.close()
    if not isinstance(response, (list, tuple)) or len(response) != 2 or response[0] != 0:
        raise UpgradeError('Fail2Ban read failed')
    return response[1]


def diagnostic_bans():
    status = dict(diagnostic_socket(['status']))
    names = status.get('Jail list')
    if isinstance(names, str): names = [x.strip() for x in names.split(',') if x.strip()]
    if not isinstance(names, (list, tuple)) or not names:
        raise UpgradeError('No usable active jail list')
    result = {}
    for jail in names:
        if not isinstance(jail, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', jail):
            raise UpgradeError('Malformed active jail name')
        values = diagnostic_socket(['get', jail, 'banip'])
        if not isinstance(values, (list, tuple)) or not all(isinstance(x, str) for x in values):
            raise UpgradeError('Malformed runtime ban list: ' + jail)
        try: result[jail] = {str(ipaddress.ip_address(x)) for x in values}
        except ValueError as error: raise UpgradeError('Malformed runtime address: ' + jail) from error
    return result


def diagnostic_action_sets(jail):
    # Resolve LOADED properties, not SETMAP or a possibly unreloaded disk dump.
    names = diagnostic_socket(['get', jail, 'actions'])
    if not isinstance(names, (list, tuple)) or not all(isinstance(x, str) for x in names):
        raise UpgradeError('Malformed runtime action list: ' + jail)
    references = {}
    for action in names:
        keys = diagnostic_socket(['get', jail, 'actionproperties', action])
        if not isinstance(keys, (list, tuple)) or not all(isinstance(x, str) for x in keys):
            raise UpgradeError('Malformed action property list: ' + jail)
        if 'actionban' not in keys: continue
        command = diagnostic_socket(['get', jail, 'action', action, 'actionban'])
        if not isinstance(command, str) or 'nft add element' not in command:
            continue
        props = {key: diagnostic_socket(['get', jail, 'action', action, key]) for key in keys if key != 'actionban'}
        props['actionban'] = command
        for version, family in ((4, 'inet4'), (6, 'inet6')):
            values = {k: v for k, v in props.items() if '?' not in k}
            values.update({k.split('?', 1)[0]: v for k, v in props.items() if k.endswith('?family=' + family)})
            values.setdefault('family', family)
            def expand(text):
                for _ in range(16):
                    updated = re.sub(r'<([A-Za-z0-9_]+)>', lambda m: str(values.get(m[1], m[0])), text)
                    if updated == text: return text
                    text = updated
                raise UpgradeError('Recursive runtime action property')
            ban = expand(values.get('actionban', ''))
            start = expand(values.get('actionstart', ''))
            matches = re.findall(r'\bnft\s+add\s+element\s+(inet|ip|ip6)\s+([A-Za-z0-9_.:-]+)\s+([A-Za-z0-9_.:-]+)(?=\s)', ban)
            if not matches: raise UpgradeError('Unresolved runtime nft action: ' + jail)
            for table_family, table, name in matches:
                if (table_family == 'ip' and version != 4) or (table_family == 'ip6' and version != 6):
                    raise UpgradeError('Runtime action family mismatch: ' + jail)
                lazy = ('nft add set ' + table_family + ' ' + table + ' ' + name in start and
                        ('ipv4_addr' if version == 4 else 'ipv6_addr') in start)
                reference = (version, table_family, table, name)
                references[reference] = references.get(reference, False) or lazy
    if {ref[0] for ref in references} != {4, 6}:
        raise UpgradeError('Cannot resolve both runtime nft families: ' + jail)
    return references


def diagnostic_merge(ranges):
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else: merged.append((first, last))
    return merged


def diagnostic_ranges(elements, version):
    ranges = []
    for element in elements:
        if isinstance(element, dict) and 'elem' in element:
            element = element['elem']['val']
        if isinstance(element, str):
            first = last = ipaddress.ip_address(element)
        elif isinstance(element, dict) and set(element) == {'prefix'}:
            prefix = element['prefix']
            network = ipaddress.ip_network(str(prefix['addr']) + '/' + str(prefix['len']), strict=False)
            first, last = network.network_address, network.broadcast_address
        elif isinstance(element, dict) and set(element) == {'range'}:
            first, last = map(ipaddress.ip_address, element['range'])
        else: raise UpgradeError('Unsupported nft address element; no repair attempted')
        if first.version != version or last.version != version or int(first) > int(last):
            raise UpgradeError('Invalid nft address family/range')
        ranges.append((int(first), int(last)))
    return diagnostic_merge(ranges)


def diagnostic_nft():
    result = subprocess.run(['nft', '-j', 'list', 'ruleset'], text=True, capture_output=True)
    if result.returncode: raise UpgradeError('nft ruleset read failed')
    try:
        document = json.loads(result.stdout)
        if not isinstance(document.get('nftables'), list): raise ValueError()
        return document
    except (ValueError, TypeError, AttributeError) as error:
        raise UpgradeError('Malformed nft ruleset response') from error


def diagnostic_compare(label, expected, actual):
    if expected != actual:
        count = lambda ranges: sum(last - first + 1 for first, last in ranges)
        raise UpgradeError('Membership mismatch: ' + label + '; expected=' + str(count(expected)) +
                           ', actual=' + str(count(actual)) + ' (equal counts do not prove equal members)')


def diagnose_sync(docker=False):
    """Read-only active-jail membership; stale unreferenced sets are ignored."""
    bans = diagnostic_bans()
    document = diagnostic_nft()
    sets = {}
    tables = set()
    for entry in document['nftables']:
        if 'table' in entry:
            table = entry['table']; tables.add((table['family'], table['name']))
        if 'set' in entry:
            item = entry['set']; key = (item['family'], item['table'], item['name'])
            if key in sets: raise UpgradeError('Ambiguous nft set response')
            sets[key] = item
    expected_sets = {}
    lazy_sets = {}
    for jail, addresses in bans.items():
        for reference, lazy in diagnostic_action_sets(jail).items():
            version, family, table, name = reference
            expected_sets.setdefault(reference, set()).update(
                x for x in addresses if ipaddress.ip_address(x).version == version)
            lazy_sets[reference] = lazy_sets.get(reference, True) and lazy
    for reference, addresses in expected_sets.items():
        version, family, table, name = reference
        if (family, table) not in tables: raise UpgradeError('Referenced runtime table missing')
        item = sets.get((family, table, name))
        expected = diagnostic_ranges(list(addresses), version)
        if item is None:
            if expected or not lazy_sets[reference]: raise UpgradeError('Referenced runtime set missing: ' + name)
            actual = []
        else:
            if item.get('type') != ('ipv4_addr' if version == 4 else 'ipv6_addr'):
                raise UpgradeError('Referenced set has wrong address type: ' + name)
            actual = diagnostic_ranges(item.get('elem', []), version)
        diagnostic_compare(table + '/' + name, expected, actual)
    if docker:
        for version in (4, 6):
            name = 'docker-banned-ipv' + str(version)
            item = sets.get(('inet', 'docker-block', name))
            if item is None or item.get('type') != ('ipv4_addr' if version == 4 else 'ipv6_addr'):
                raise UpgradeError('Docker family set missing/wrong type')
            expected = diagnostic_ranges([x for ips in bans.values() for x in ips
                                          if ipaddress.ip_address(x).version == version], version)
            diagnostic_compare('docker-block/' + name, expected, diagnostic_ranges(item.get('elem', []), version))
    if diagnostic_bans() != bans:
        raise UpgradeError('Runtime bans changed during diagnostic; retry without forcing synchronization')
    print('PASS: ' + str(len(bans)) + ' active jails; exact IPv4/IPv6 membership' +
          (' and Docker union' if docker else '') + '; sets unused by loaded jail actions ignored; no changes made')

def restore_bans(saved):
    live = set(parse_jails(run("fail2ban-client","status").stdout))
    if set(saved)-live: raise UpgradeError("Jails disappeared: " + ", ".join(sorted(set(saved)-live)))
    for jail, old in saved.items():
        current = {x for x in run("fail2ban-client","get",jail,"banip").stdout.split() if valid_ip(x)}
        for ip in sorted(set(old)-current): run("fail2ban-client","set",jail,"banip",ip)
        final = {x for x in run("fail2ban-client","get",jail,"banip").stdout.split() if valid_ip(x)}
        if set(old)-final: raise UpgradeError(f"Bans not preserved: {jail}")

def nft_json():
    try: return json.loads(run("nft","-j","list","ruleset").stdout)
    except json.JSONDecodeError as e: raise UpgradeError(f"Bad nft JSON: {e}") from e

def nft_digest(doc):
    def stable(v):
        if isinstance(v,dict): return {k:stable(x) for k,x in v.items() if k not in {"handle","packets","bytes","expires"}}
        if isinstance(v,list): return [stable(x) for x in v]
        return v
    kept=[]
    for item in doc.get("nftables",[]):
        data=next((v for k,v in item.items() if k!="metainfo"),None)
        owner = (data.get("name") if "table" in item else data.get("table")) if isinstance(data,dict) else None
        if isinstance(data,dict) and data.get("family")=="inet" and owner in {"fail2ban-filter","docker-block"}: continue
        if "metainfo" not in item: kept.append(stable(item))
    return hashlib.sha256(json.dumps(kept,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def production_preflight(root):
    if os.geteuid()!=0: raise UpgradeError("Run with sudo; no changes made")
    missing=[x for x in ("bash","fail2ban-client","nft","systemctl") if not shutil.which(x)]
    if missing: raise UpgradeError("Missing commands: "+", ".join(missing))
    if not Path("/etc/fail2ban/jail.local").is_file(): raise UpgradeError("Missing jail.local")
    if run("fail2ban-client","ping").stdout.strip()!="Server replied: pong": raise UpgradeError("Fail2Ban unavailable")
    validate_dbfile(run("fail2ban-client","get","dbfile").stdout)
    if run("/usr/local/bin/f2b","version","--short").stdout.strip()!=RELEASE: raise UpgradeError("Not a v0.34-dev host")
    validate_payload(root)
    with tempfile.TemporaryDirectory(prefix="f2b-canary-") as tmp:
        candidate=Path(tmp)/"fail2ban"; shutil.copytree("/etc/fail2ban",candidate,symlinks=True)
        for target,source in install_map(root).items():
            try: relative=target.relative_to("/etc/fail2ban")
            except ValueError: continue
            dest=candidate/relative; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,dest)
        run("fail2ban-client","-c",str(candidate),"-t")
    return snapshot_bans(),nft_json()

def backup_paths(root):
    return [root/"etc/fail2ban",root/"var/lib/fail2ban",root/"usr/local/bin/f2b",
            root/"usr/local/sbin/f2b-docker-hook",root/"usr/local/sbin/f2b-ipv6-sync.py",
            root/"usr/local/libexec/f2b-runtime-verify.py"]

def create_backup(base,root,bans,nft):
    out=base/f"{BACKUP_LABEL}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"; out.mkdir(parents=True,mode=0o700)
    existing=[p for p in backup_paths(root) if p.exists()]
    with tarfile.open(out/"system-files.tar","w") as archive:
        def exclude_sidecars(info):
            return None if info.name.endswith((".sqlite3-wal", ".sqlite3-shm")) else info
        for path in existing: archive.add(path,arcname=path.relative_to(root),recursive=True,filter=exclude_sidecars)
        if root == Path("/"):
            with tempfile.TemporaryDirectory(prefix="f2b-canary-db-") as temporary:
                for database in (root/"var/lib/fail2ban").glob("*.sqlite3"):
                    destination=Path(temporary)/database.name
                    with sqlite3.connect(f"file:{database}?mode=ro",uri=True) as source:
                        with sqlite3.connect(destination) as target: source.backup(target)
                    archive.add(destination,arcname=database.relative_to(root))
    (out/"manifest.json").write_text(json.dumps({"paths":[str(p.relative_to(root)) for p in existing]},indent=2)+"\n")
    (out/"fail2ban-bans.json").write_text(json.dumps(bans,indent=2)+"\n")
    (out/"nft-ruleset.json").write_text(json.dumps(nft,indent=2)+"\n")
    sums=[]
    for path in sorted(out.iterdir()): sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (out/"SHA256SUMS").write_text("\n".join(sums)+"\n"); return out

def verify_backup(backup):
    for line in (backup/"SHA256SUMS").read_text().splitlines():
        digest,name=line.split("  ",1); path=backup/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise UpgradeError(f"Bad backup: {path}")

def atomic_install(source,target):
    target.parent.mkdir(parents=True,exist_ok=True); fd,name=tempfile.mkstemp(prefix=".canary-",dir=target.parent); staged=Path(name)
    try:
        with os.fdopen(fd,"wb") as out,source.open("rb") as inp: shutil.copyfileobj(inp,out); out.flush(); os.fsync(out.fileno())
        os.chmod(staged,0o755 if any(p in str(target) for p in ("/usr/local/bin/","/usr/local/sbin/","/usr/local/libexec/")) else 0o644); os.replace(staged,target)
    finally: staged.unlink(missing_ok=True)

def deploy(mapping):
    for target,source in mapping.items(): atomic_install(source,target)

def restore_files(backup,mapping,root):
    json.loads((backup/"manifest.json").read_text())
    # Remove all managed targets first. The full archive restores every
    # target that existed before apply; targets introduced by the canary stay
    # absent, which is required for an exact rollback.
    for target in mapping: target.unlink(missing_ok=True)
    # The archive is created locally by this process from a fixed path list;
    # avoid Python 3.12's filter argument so the updater also works on 3.9/3.10.
    with tarfile.open(backup/"system-files.tar") as archive: archive.extractall(root)

def scalar(jail,setting):
    found=re.search(r"(-?\d+)\s*$",run("fail2ban-client","get",jail,setting).stdout.strip())
    if not found: raise UpgradeError(f"Cannot read {jail}.{setting}")
    return found.group(1)

def action_names(jail):
    output=run("fail2ban-client","get",jail,"actions").stdout
    names=[]
    for line in output.splitlines()[1:]:
        for item in line.strip().lstrip("|`- ").split(","):
            name=item.strip()
            if re.fullmatch(r"[A-Za-z0-9_.:-]+",name): names.append(name)
    return names

def effective_nft_actions(jail):
    """Resolve family properties from Fail2Ban's effective configuration dump."""
    rendered={}
    live=set(action_names(jail))
    for line in run("fail2ban-client","-d").stdout.splitlines():
        if not line.startswith("["): continue
        try: command=ast.literal_eval(line)
        except (ValueError,SyntaxError): continue
        if not isinstance(command,list) or len(command)!=5 or command[:3]!=["multi-set",jail,"action"]: continue
        action=command[3]
        if action not in live: continue
        props=dict(command[4])
        if "nft add element" not in props.get("actionban",""): continue
        # Confirm the loaded runtime action uses the same command template.
        runtime=run("fail2ban-client","get",jail,"action",action,"actionban").stdout.strip()
        if runtime!=props["actionban"].strip(): raise UpgradeError("Runtime/config nft action mismatch")
        for version,family in ((4,"inet4"),(6,"inet6")):
            values={k:v for k,v in props.items() if "?" not in k}
            values.update({k.split("?",1)[0]:v for k,v in props.items() if k.endswith("?family="+family)})
            def expand(text):
                for _ in range(12):
                    updated=re.sub(r"<([A-Za-z0-9_]+)>",lambda m:str(values.get(m[1],m[0])),text)
                    if updated==text: return text
                    text=updated
                raise UpgradeError("Recursive nft action property")
            name=expand(str(values.get("addr_set","")))
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+",name): raise UpgradeError("Unresolved nft set name")
            start=expand(props.get("actionstart","")); ban=expand(props["actionban"])
            address_family="ip" if version==4 else "ip6"
            address_type="ipv4_addr" if version==4 else "ipv6_addr"
            if (f"nft add set inet fail2ban-filter {name}" not in start or
                address_type not in start or f"{address_family} saddr @{name}" not in start or
                f"nft add element inet fail2ban-filter {name}" not in ban):
                raise UpgradeError(f"Invalid IPv{version} nft action")
            rendered[version]=(name,start)
    return rendered

def verify_nft_lifecycle(jail):
    rendered=effective_nft_actions(jail)
    if set(rendered)!={4,6} or rendered[4][0]==rendered[6][0]:
        raise UpgradeError(f"Cannot resolve both effective nft set names: {sorted(rendered)}")
    active_bans=[x for x in run("fail2ban-client","get",jail,"banip").stdout.split() if valid_ip(x)]
    # A clean daemon can defer the entire action, including the input chain.
    # A live set below still requires a reference in an existing chain.
    chain=run("nft","list","chain","inet","fail2ban-filter","f2b-input",check=False).stdout
    for version,(name,start) in rendered.items():
        family_bans=[ip for ip in active_bans if ipaddress.ip_address(ip).version==version]
        live=run("nft","list","set","inet","fail2ban-filter",name,check=False)
        if live.returncode:
            # Fail2Ban starts nft actions on demand. A clean jail after reload
            # legitimately has no set until its first real ban.
            if family_bans: raise UpgradeError(f"Active jail is missing nft set {name}")
            if name not in start or "nft add set" not in start:
                raise UpgradeError(f"Lazy nft action cannot create {name}")
        elif f"@{name}" not in chain:
            raise UpgradeError(f"Live nft set {name} is not referenced by f2b-input")
        for ip in family_bans:
            run("nft","get","element","inet","fail2ban-filter",name,"{",ip,"}")
    return rendered

def verify_docker_hook(jail):
    if "docker-sync-hook" not in action_names(jail): raise UpgradeError("Docker hook inactive")
    hook=run("fail2ban-client","get",jail,"action","docker-sync-hook","actionban").stdout.strip()
    if hook!=f"/usr/local/sbin/f2b-docker-hook ban <ip> {jail} <bantime>":
        raise UpgradeError("Unexpected Docker hook ban command")

def verify_runtime():
    """Read-only checks shared by canary, standard upgrade and diagnostics."""
    if JAIL not in parse_jails(run("fail2ban-client","status").stdout): raise UpgradeError("Canary jail inactive")
    for key,value in {"findtime":"30","maxretry":"3","bantime":"31536000"}.items():
        if scalar(JAIL,key)!=value: raise UpgradeError(f"Bad {key}")
    if "this_is_a_new_hello_world" not in run("fail2ban-client","get","f2b-exploit-critical","failregex").stdout: raise UpgradeError("IOC inactive")
    verify_docker_hook(JAIL)
    verify_nft_lifecycle(JAIL)

def verify_docker_membership(reconcile=False):
    """Check actual active bans; optional repair is used only inside apply."""
    for jail,addresses in snapshot_bans().items():
        if "docker-sync-hook" not in action_names(jail): continue
        for ip in addresses:
            name="docker-banned-ipv4" if ipaddress.ip_address(ip).version==4 else "docker-banned-ipv6"
            query=("nft","get","element","inet","docker-block",name,"{",ip,"}")
            if reconcile and run(*query,check=False).returncode:
                run("/usr/local/sbin/f2b-docker-hook","ban",ip,jail,scalar(jail,"bantime"))
            run(*query)

def verify_live(root,bans,before):
    run("fail2ban-client","-t"); run("fail2ban-client","ping"); restore_bans(bans)
    if nft_digest(nft_json())!=nft_digest(before): raise UpgradeError("External nftables table changed")
    verify_runtime()
    run("/usr/local/bin/f2b","sync","docker")
    # Reconcile only genuine live bans. The hook handles either address family
    # independently of the wrapper's historical nft set naming conventions.
    verify_docker_membership(reconcile=True)
    if nft_digest(nft_json())!=nft_digest(before): raise UpgradeError("External nftables table changed during sync")
    validate_payload(root)

def rollback(backup,mapping,root,fixture=False):
    verify_backup(backup); bans=json.loads((backup/"fail2ban-bans.json").read_text())
    if not fixture:
        try: fresh=snapshot_bans()
        except UpgradeError: fresh={}
        fallback="manualblock" if "manualblock" in bans else "recidive" if "recidive" in bans else None
        for jail,addresses in fresh.items():
            destination=jail if jail in bans else fallback
            if destination is not None: bans[destination]=sorted(set(bans[destination])|set(addresses))
    if not fixture: run("systemctl","stop","fail2ban")
    restore_files(backup,mapping,root)
    if not fixture:
        for suffix in ("-wal","-shm"):
            for sidecar in (root/"var/lib/fail2ban").glob("*.sqlite3"+suffix): sidecar.unlink(missing_ok=True)
        run("fail2ban-client","-t"); run("systemctl","start","fail2ban")
        restore_bans(bans)

def fixture_state(root):
    state=root/"run/f2b-canary"
    return json.loads((state/"bans.json").read_text()),json.loads((state/"nft.json").read_text())

def main():
    parser=argparse.ArgumentParser(description=__doc__); mode=parser.add_mutually_exclusive_group()
    mode.add_argument("--apply",action="store_true"); mode.add_argument("--rollback",type=Path)
    mode.add_argument("--verify-only",action="store_true",help="read-only runtime and Docker membership checks")
    mode.add_argument("--set-name",nargs=2,metavar=("JAIL","FAMILY"),help="resolve the effective nft set for wrapper diagnostics")
    mode.add_argument("--sync-check", action="store_true", help="strict read-only active-profile sync check")
    mode.add_argument("--docker-check", action="store_true", help="strict read-only active-profile and Docker union check")
    mode.add_argument("--npm-coverage", action="store_true", help="read-only HTTP access/error coverage for active web jails")
    parser.add_argument("--backup-dir",type=Path,default=Path("/var/backups/f2b-v034-canary"))
    parser.add_argument("--fixture-root",type=Path,help=argparse.SUPPRESS); args=parser.parse_args()
    root=package_root(); fixture=args.fixture_root is not None; system_root=args.fixture_root.resolve() if fixture else Path("/")
    mapping=install_map(root,system_root)
    try:
        if args.npm_coverage:
            jails = snapshot_bans()
            verify_npm_coverage(jails)
            print('PASS: runtime HTTP log coverage; active web jails: ' + str(len(set(jails) & HTTP_JAILS)))
            return 0
        if args.sync_check or args.docker_check:
            # Keep the source workflow's separate HTTP-coverage guard. The
            # standalone diagnostic hotfix intentionally checks membership only.
            verify_npm_coverage(snapshot_bans())
            diagnose_sync(docker=args.docker_check)
            return 0
        if args.set_name:
            jail,family=args.set_name
            if family not in {"4","6"}: raise UpgradeError("Family must be 4 or 6")
            if jail=="recidive": print("f2b-recidive"+("-v6" if family=="6" else ""))
            else:
                resolved=effective_nft_actions(jail)
                if int(family) not in resolved: raise UpgradeError("No effective nft action for jail")
                print(resolved[int(family)][0])
            return 0
        if args.verify_only:
            if fixture: raise UpgradeError("--verify-only requires the live system")
            if os.geteuid()!=0: raise UpgradeError("Run with sudo")
            verify_runtime(); verify_docker_membership()
            print("PASS: read-only runtime actions, family sets and Docker membership")
            return 0
        validate_payload(root)
        if args.rollback: rollback(args.rollback,mapping,system_root,fixture); print(f"PASS: rollback restored {args.rollback}"); return 0
        bans,before=fixture_state(system_root) if fixture else production_preflight(root)
        print(f"PASS: read-only preflight; {len(bans)} jails and {sum(map(len,bans.values()))} bans captured")
        if not args.apply: print("No changes made. Re-run with --apply only in the approved canary window."); return 0
        backup=create_backup(system_root/"backups" if fixture else args.backup_dir,system_root,bans,before); print(f"Backup complete: {backup}")
        try:
            deploy(mapping)
            if fixture:
                for target,source in mapping.items():
                    if target.read_bytes()!=source.read_bytes(): raise UpgradeError(f"Bad fixture install: {target}")
                if fixture_state(system_root)[0]!=bans: raise UpgradeError("Fixture bans changed")
            else:
                run("fail2ban-client","-t"); run("fail2ban-client","reload"); verify_live(root,bans,before)
        except Exception as error: rollback(backup,mapping,system_root,fixture); raise UpgradeError(f"Update failed and rolled back: {error}") from error
        print(f"PASS: canary updated through {TARGET_CHANGESET}; backup: {backup}")
        print("Docker and nftables were not restarted; no ruleset was loaded or flushed."); return 0
    except (OSError,UpgradeError,json.JSONDecodeError,tarfile.TarError) as error: print(f"ERROR: {error}",file=sys.stderr); return 1

if __name__=="__main__": raise SystemExit(main())
