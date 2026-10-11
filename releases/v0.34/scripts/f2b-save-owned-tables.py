#!/usr/bin/python3
"""Persist only the two managed tables. Never load or flush a firewall."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile


def save(directory=Path('/etc/nftables.d')):
    with open('/run/lock/f2b-runtime-sync.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Read both before replacing either. A failed read changes no file.
        snapshots = {name: subprocess.run(['nft', '-s', 'list', 'table', 'inet', name],
                     check=True, text=True, capture_output=True).stdout
                     for name in ('fail2ban-filter', 'docker-block')}
        directory.mkdir(parents=True, exist_ok=True)
        for name, contents in snapshots.items():
            target = directory / (name + '.nft')
            descriptor, filename = tempfile.mkstemp(prefix='.' + name, dir=directory)
            try:
                with os.fdopen(descriptor, 'w') as output:
                    output.write(contents)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(filename, 0o600)
                os.replace(filename, target)
            finally:
                Path(filename).unlink(missing_ok=True)


if __name__ == '__main__':
    save()
