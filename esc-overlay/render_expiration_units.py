#!/usr/bin/python3 -I
"""Render an explicit one-off expiration unit pair; never installs or schedules it."""
import argparse
from datetime import datetime
from pathlib import Path
import re


def render(script, receipt, backup, deadline):
    paths = [str(path) for path in (script, receipt, backup)]
    if any(not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or '/..' in path for path in paths):
        raise ValueError('Explicit simple absolute owned paths required')
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", deadline):
        raise ValueError("Explicit canonical UTC deadline required")
    when = datetime.fromisoformat(deadline)
    if when.tzinfo is None or when.utcoffset().total_seconds() != 0:
        raise ValueError('Approved UTC deadline required')
    service = ('[Unit]\nDescription=Expire one positively owned retained LLDAP archive\n'
               '[Service]\nType=oneshot\nUser=root\nUMask=0077\nExecStart=/usr/bin/python3 -I '
               + paths[0] + ' --receipt ' + paths[1] + ' --backup ' + paths[2]
               + ' --retain-until ' + deadline + '\n')
    timer = ('[Unit]\nDescription=One-off approved LLDAP archive expiration\n[Timer]\n'
             'OnCalendar=' + when.strftime('%Y-%m-%d %H:%M:%S UTC')
             + '\nPersistent=true\nUnit=lldap-owned-backup-expire.service\n'
             '[Install]\nWantedBy=timers.target\n')
    return service, timer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('script', 'receipt', 'backup', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    parser.add_argument('--retain-until', required=True)
    args = parser.parse_args()
    service, timer = render(args.script, args.receipt, args.backup, args.retain_until)
    args.output.mkdir(mode=0o700)
    (args.output / 'lldap-owned-backup-expire.service').write_text(service)
    (args.output / 'lldap-owned-backup-expire.timer').write_text(timer)


if __name__ == '__main__':
    main()
