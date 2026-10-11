# Publication boundary

Commit only generic installers, policies, tests and minimal synthetic examples.
Use documentation address ranges and example.invalid/example.test. Whitelists
are operator-managed; shipped defaults contain loopback only. Production
exports, snapshots, logs, endpoint identifiers, review hashes and deployment
records stay in a private directory outside the checkout and package.

Before committing/pushing:

```sh
python3 scripts/test-publication-safety.py
python3 scripts/check-publication-safety.py
python3 scripts/check-publication-safety.py --staged
```

`sh scripts/install-publication-hook.sh` explicitly installs the staged gate
without replacing an existing user hook. CI checks the full tracked tree and
the built archive, including its manifest. The package builder checks the tree
and payload before writing an archive; known historical target hashes are
derived only from canonical source-controlled installer components. Historical
source text is not included: these compatibility digests must still recognize
legacy components whose old examples did not follow the current policy.
No deployment hash list is shipped. Local-only v0.40 code paths are refused.

The generic rules flag public non-documentation IP literals, non-example
deployment domains, private home/backup paths, private keys, common credential
tokens and literal deployment hash dictionaries. Matches are never echoed:
only location/type diagnostics are printed. Provider domains are a generic
public software/documentation list, not a list of private server literals.

This heuristic gate supplements human review. It cannot establish absence of
every secret, identify an arbitrary opaque hash or inspect encrypted/binary
content. A zero result is not a historical purge or a security certification.

Read-only audit modes support `--history`, `--archive PATH` and
`--stdin-label LABEL` for PR/API/log text. History findings are separate from
the current-tree CI gate: removing data from HEAD does not remove earlier
commits, PR revisions, caches, clones, forks or existing logs. History rewriting,
remote-ref replacement and deleting runs/artifacts require separate approval
and coordination. Never publish actual finding values in PRs/issues/logs.

RC/final promotion still requires the release validation gates. Deployment,
external packet testing and reboot validation are separate from publication.
