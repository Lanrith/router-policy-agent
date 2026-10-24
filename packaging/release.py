#!/usr/bin/env python3
"""Package freshly scanned, inert policy tools with their source identity."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', args.version):
        raise ValueError('Invalid component version')
    args.output.mkdir(parents=True)
    source = run('git', 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip()
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('Invalid source identity')
    packages = {'router-policy-helper': ['router-policy-helper', 'router-policy-check',
                                          'router-policy-status', 'router-policy-recover',
                                          'router-policy-profile'],
                'router-policy-reader': ['router-policy-reader'],
                'router-policy-collector': ['router-policy-collector']}
    scan = args.output/'security.txt'
    notices = args.output/'THIRD-PARTY-NOTICES'
    run('go', 'mod', 'download', 'all')
    run('go', 'mod', 'verify')
    run('python3', 'packaging/collect-notices.py', 'go', '--output', str(notices))
    with scan.open('w') as stream:
        stream.write('source_commit='+source+'\nversion='+args.version+'\n')
        stream.write('assessed_at='+datetime.datetime.now(datetime.timezone.utc).isoformat()+'\n')
        stream.flush()
        run('go', 'run', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0', '-version', stdout=stream)
        run('go', 'run', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0', './...', stdout=stream)
        for package, commands in packages.items():
            with tempfile.TemporaryDirectory(prefix='lanrith-policy-package.') as temporary:
                root = Path(temporary)
                (root/'DEBIAN').mkdir()
                (root/'usr/bin').mkdir(parents=True)
                (root/('usr/share/doc/'+package)).mkdir(parents=True)
                for command in commands:
                    binary = root/('usr/bin/'+command)
                    run('go', 'build', '-trimpath', '-buildvcs=true', '-ldflags',
                        '-X github.com/lanrith/router-policy-agent/internal/cli.Version='+args.version,
                        '-o', str(binary), './cmd/'+command, env={**os.environ, 'CGO_ENABLED': '0'})
                    binary.chmod(0o755)
                    run('go', 'run', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0', '-mode=binary', str(binary), stdout=stream)
                    observed = run(str(binary), '-version', capture_output=True, text=True).stdout.strip()
                    if observed != args.version:
                        raise ValueError('Binary version does not match release')
                shutil.copyfile('LICENSE', root/('usr/share/doc/'+package+'/copyright'))
                shutil.copyfile(notices, root/('usr/share/doc/'+package+'/THIRD-PARTY-NOTICES'))
                (root/'DEBIAN/control').write_text(
                    f'Package: {package}\nVersion: {args.version}\nArchitecture: amd64\n'
                    'Section: net\nPriority: optional\nMaintainer: Lanrith <maintainers@lanrith.org>\n'
                    'Description: Lanrith bounded router policy component\n')
                # No maintainer scripts, service activation or deployment configuration.
                run('dpkg-deb', '--build', '--root-owner-group', str(root),
                    str(args.output/(package+'_'+args.version+'_amd64.deb')))
    files = {path.name: {'sha256': digest(path), 'size': path.stat().st_size}
             for path in args.output.iterdir()}
    manifest = {'schema': 'lanrith-component-v1', 'version': args.version,
                'source_commit': source, 'architecture': 'amd64', 'files': files}
    (args.output/'component-release.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n')


if __name__ == '__main__':
    main()
