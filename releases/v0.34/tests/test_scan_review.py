"""2026-10-11 probes: narrow targets, real ConfigParser and Fail2Ban regressions."""
import configparser
import itertools
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOSTS = ("192.0.2.17", "2001:db8::17")


def log(target, host, status=404, method="GET", scheme="https"):
    return (f'[11/Oct/2026:10:00:00 +0000] - {status} {status} - '
            f'{method} {scheme} app.example.test "{target}" [Client {host}]')


def check(name, attacks, benign):
    path = ROOT / "filters" / (name + ".conf")
    parser = configparser.ConfigParser()
    parser.read(path)
    definition = parser["Definition"]
    def patterns(key):
        return [re.compile(value.replace("<HOST>", r"(?:[0-9.]+|[0-9A-Fa-f:]+)"))
                for value in definition[key].splitlines() if value.strip()]
    fail, ignore = patterns("failregex"), patterns("ignoreregex")
    def matches(line):
        return any(p.search(line) for p in fail) and not any(p.search(line) for p in ignore)
    assert all(matches(line) for line in attacks), [line for line in attacks if not matches(line)]
    assert not any(matches(line) for line in benign), [line for line in benign if matches(line)]
    executable = shutil.which("fail2ban-regex")
    if "--require-fail2ban" in sys.argv:
        assert executable, "Real fail2ban-regex is required in CI"
    if executable:
        with tempfile.TemporaryDirectory(prefix="f2b-scan-review-") as directory:
            for label, lines, expected in (("attacks", attacks, len(attacks)), ("benign", benign, 0)):
                fixture = pathlib.Path(directory) / (label + ".log")
                fixture.write_text("\n".join(lines) + "\n")
                result = subprocess.run([executable, str(fixture), str(path)],
                                        capture_output=True, text=True, check=True)
                summary = re.search(r"Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched", result.stdout)
                assert summary and int(summary[1]) == expected, result.stdout + result.stderr
    print(f"PASS: {name}: {len(attacks)} attacks, {len(benign)} benign; "
          f"real fail2ban-regex={'yes' if executable else 'not available locally'}")


credentials = [f"/.aws/{name}{suffix}" for name, suffix in itertools.product(
    ("credentials", "config"), ("", ".bak", ".old", ".save", ".orig", "~"))]
credentials += ["/.boto", "/.s3cfg", "/.codeium/auth.json", "/.tabnine/credentials", "/rclone.conf"]
credentials += [f"/{prefix}{name}.json" for prefix, name in itertools.product(
    ("", "config/", "keys/"), ("gcp-credentials", "google-credentials", "firebase-credentials",
                                "google-service-account", "service-account", "firebase-admin"))]
traversals = ["/userfiles/x?path=../../../../proc/self/environ",
              "/userfiles/x?path=../../.env", "/userfiles?path=../../../../proc/self/environ"]
traversals += [f"/userfiles/x?x=1&{param}={dots}{sep}{dots}{sep}{target}&raw=1"
               for param, dots, sep, target in itertools.product(
                   ("path", "file", "filename", "download"),
                   ("..", "%2e%2e", ".%2e", "%2e.", "%2E%2E"),
                   ("/", "%2f", "%2F"),
                   (".env", ".env.local", "proc/self/environ", "proc%2fself%2fcmdline"))]
iocs = ["/wp-content/plugins/hellopress/wp_filemanager.php", "/this_is_a_new_hello_world.php"]
critical_attacks = [log(target, host) for target, host in itertools.product(credentials + traversals, HOSTS)]
critical_attacks += [log(target, host, status, scheme=scheme)
                     for target, host, status, scheme in itertools.product(iocs, HOSTS, (301, 404, 444), ("http", "https"))]
# Broad legacy application ignores must not suppress a precise request target.
critical_attacks += [log("/.aws/credentials.bak?next=/assets/a", host) for host in HOSTS]
critical_attacks += [log("/assets/x?path=../../.env", host) for host in HOSTS]
benign_targets = ["/search?q=../../.env", "/userfiles?path=../../images/a.jpg",
                  "/userfiles?path=.env", "/userfiles?path=proc/self/environ",
                  "/userfiles?other=../../.env", "/userfiles?filepath=../../.env",
                  "/userfiles?path=../../.env.local.txt", "/userfiles?path=../../proc/self/environ.txt",
                  "/firebase.json", "/google-services.json", "/push_config.json", "/graphql",
                  "/.claude/settings.json", "/config/example.json", "/docs/service-account.json",
                  "/.aws/credentials.txt", "/.boto.txt", "/rclone.conf.example",
                  "/config.php", "/solr/admin/cores"]
critical_benign = [log(target, host) for target, host in itertools.product(benign_targets, HOSTS)]
critical_benign += [log("/news", host) + ' "browser" "https://ref.example/.aws/credentials.bak"'
                    for host in HOSTS]
critical_benign += [f'2026/10/11 [warn] trust_forwarded_proto client: {host}, request: "GET / HTTP/1.1"'
                    for host in HOSTS]
check("f2b-exploit-critical", critical_attacks, critical_benign)

core = [f"/{prefix}{name}{query}" for prefix, name, query in itertools.product(
    ("", "blog/", "wordpress/", "wp/", "cms/", "site/", "main/", "new/", "tenant/a/blog/"),
    ("index.php", "wp-login.php", "wp-admin/admin-ajax.php", "wp-cron.php"), ("", "?x=1"))]
sweep_benign = [log(target, host, method=method) for target, host, method in itertools.product(core, HOSTS, ("GET", "HEAD"))]
check("f2b-exploit-critical", [], [log(target, host) for target, host in itertools.product(core, HOSTS)])
sweep_targets = ("/blog/not-wp-login.php", "/wp-content/plugins/evil/payload.phtml", "/tenant/a/payload.php")
sweep_attacks = [log(target, host, method=method) for target, host, method in itertools.product(sweep_targets, HOSTS, ("GET", "HEAD"))]
sweep_benign += [log(target, host, status) for target, host, status in itertools.product(sweep_targets, HOSTS, (200, 301, 444))]
check("f2b-webshell-sweep", sweep_attacks, sweep_benign)
