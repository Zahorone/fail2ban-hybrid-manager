"""Representative server override structure; not an authenticated server export."""
import configparser


def overrides(root):
    parser = configparser.RawConfigParser()
    parser.read(root / "filters/f2b-exploit-critical.conf")
    probe = parser["Definition"]["scan_review"]
    ioc = (r'^.* (?:GET|POST|HEAD) (?:http|https) [^ ]+ "/(?:wp-content/plugins/hellopress/wp_filemanager|this_is_a_new_hello_world)\.php(?:\?[^"\s]*)?" \[Client <HOST>\]')
    critical = ('[Definition]\n# scan-review-20261011\n'
                'failregex = %(known/failregex)s\n            ' + probe + '\n            ' + ioc + '\n')
    parser.read(root / "filters/f2b-webshell-sweep.conf")
    sweep = ('[Definition]\n# scan-review-20261011\n'
             'ignoreregex = %(known/ignoreregex)s\n              ' + parser["Definition"]["ignoreregex"] + '\n')
    return {"f2b-exploit-critical.local": critical, "f2b-webshell-sweep.local": sweep}
