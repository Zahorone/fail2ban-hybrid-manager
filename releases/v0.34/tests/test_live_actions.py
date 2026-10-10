"""Real Fail2Ban/nft actions in CI's private mount and network namespaces."""
import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)

def client(*args):
    return run("fail2ban-client", *args)

def wait_for(predicate):
    for _ in range(100):
        if predicate(): return
        time.sleep(.1)
    raise AssertionError("Timed out waiting for real action")

# This script is invoked only by unshare --mount --net. Private /run keeps
# sockets, pid files and locks separate from any runner's existing daemon.
run("mount", "--make-rprivate", "/")
run("mount", "-t", "tmpfs", "tmpfs", "/run")
pathlib.Path("/run/lock").mkdir()
pathlib.Path("/usr/local/sbin").mkdir(parents=True, exist_ok=True)
for source, target in (("f2b-ipv6-sync.py", "f2b-ipv6-sync.py"), ("f2b-docker-hook.sh", "f2b-docker-hook")):
    shutil.copy2(ROOT / "scripts" / source, pathlib.Path("/usr/local/sbin") / target)

with tempfile.TemporaryDirectory() as temporary:
    temporary = pathlib.Path(temporary)
    config = temporary / "config"
    shutil.copytree("/etc/fail2ban", config)
    for source in (ROOT / "actions").iterdir():
        shutil.copy2(source, config / "action.d" / source.name)
    shutil.copy2(ROOT / "filters/f2b-webshell-sweep.conf", config / "filter.d/f2b-webshell-sweep.conf")
    log = temporary / "access.log"
    log.touch()
    (config / "fail2ban.local").write_text(
        "[Definition]\nlogtarget = " + str(temporary / "daemon.log") +
        "\ndbfile = " + str(temporary / "bans.sqlite3") + "\n")
    (config / "jail.local").write_text(
        "[DEFAULT]\nbackend = polling\nbantime = 7200\nfindtime = 30\nmaxretry = 3\n"
        "action = nftables-multiport\n         docker-sync-hook\n"
        "[sshd]\nenabled = false\n"
        "[f2b-webshell-sweep]\nenabled = true\nfilter = f2b-webshell-sweep\nlogpath = " + str(log) + "\n"
        "[f2b-testsecond]\nenabled = true\nfilter = f2b-webshell-sweep\nbantime = 60\nlogpath = " + str(log) + "\n")
    run("nft", "add", "table", "inet", "foreign-sentinel")
    run("nft", "add", "chain", "inet", "foreign-sentinel", "keep")
    foreign = run("nft", "-s", "list", "table", "inet", "foreign-sentinel").stdout
    for table, names in (("docker-block", ("docker-banned-ipv4", "docker-banned-ipv6")),
                         ("fail2ban-filter", ("f2b-recidive", "f2b-recidive-v6"))):
        run("nft", "add", "table", "inet", table)
        for name in names:
            kind = "ipv6_addr" if name.endswith(("ipv6", "-v6")) else "ipv4_addr"
            run("nft", "add", "set", "inet", table, name, "{ type " + kind + "; flags timeout; timeout 7d; }")
    started = False
    try:
        run("fail2ban-client", "-c", str(config), "-x", "start")
        started = True
        wait_for(lambda: client("ping").returncode == 0)
        spec = importlib.util.spec_from_file_location("runtime", ROOT / "scripts/upgrade-v034dev-canary-227c393.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        def verifier_run(*args, check=True):
            if args == ("fail2ban-client", "-d"):
                args = ("fail2ban-client", "-c", str(config), "-d")
            return run(*args, check=check)
        verifier.run = verifier_run
        # Actual zero-ban action and both family templates, before any set exists.
        verifier.verify_docker_hook("f2b-webshell-sweep")
        resolved = verifier.verify_nft_lifecycle("f2b-webshell-sweep")
        for ip, family in (("192.0.2.8", 4), ("2001:db8::8", 6)):
            query = ("nft", "get", "element", "inet", "docker-block", "docker-banned-ipv%d" % family, "{", ip, "}")
            client("set", "f2b-webshell-sweep", "banip", ip)
            wait_for(lambda: run(*query, check=False).returncode == 0)
            client("set", "f2b-testsecond", "banip", ip)
            client("set", "f2b-testsecond", "unbanip", ip)
            run("/usr/bin/python3", "/usr/local/sbin/f2b-ipv6-sync.py")
            run(*query)
            verifier.verify_nft_lifecycle("f2b-webshell-sweep")
            client("set", "f2b-webshell-sweep", "unbanip", ip)
            run("/usr/bin/python3", "/usr/local/sbin/f2b-ipv6-sync.py")
            assert run(*query, check=False).returncode != 0
        client("set", "f2b-webshell-sweep", "bantime", "-1")
        client("set", "f2b-webshell-sweep", "banip", "2001:db8::9")
        wait_for(lambda: run("nft", "get", "element", "inet", "docker-block", "docker-banned-ipv6", "{ 2001:db8::9 }", check=False).returncode == 0)
        run("/usr/bin/python3", "/usr/local/sbin/f2b-ipv6-sync.py")
        assert foreign == run("nft", "-s", "list", "table", "inet", "foreign-sentinel").stdout
        print("PASS: real Fail2Ban two-family lazy actions, shared hook/unban, permanent ban and foreign table preservation")
    finally:
        if started: client("stop")
