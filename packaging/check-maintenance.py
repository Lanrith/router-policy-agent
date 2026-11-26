#!/usr/bin/env python3
"""Reject incomplete controller pin transactions before expensive qualification."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
source = json.loads((root/'security/maintenance-source.json').read_text())
commit = source['source_commit']
assert source['schema'] == 2 and re.fullmatch(r'[0-9a-f]{40}', commit), 'Invalid reviewed controller identity'
references, collectors = [], []
for path in (root/'.github/workflows').glob('*.yml'):
    text = path.read_text()
    for name, pin in re.findall(r'Lanrith/lanrith/\.github/workflows/([a-z-]+\.yml)@([0-9a-f]{40})', text):
        assert pin == commit, f'{path.name}: controller pin differs from maintenance-source.json'
        references.append(name)
    for pin in re.findall(r'repository: Lanrith/lanrith\s+ref: ([0-9a-f]{40})', text):
        assert pin == commit, f'{path.name}: release collector differs from controller provenance'
        collectors.append(pin)
assert {'publish-release.yml','security-proposal.yml','security-review.yml','cleanup-artifacts.yml','request-human-review.yml'} <= set(references), 'Controller reference coverage is incomplete'
assert len(collectors) == 1, 'Expected exactly one release collector'
# GitHub resolves environment secrets only when each nested caller forwards
# them. The App key remains in the protected lanrith-updates environment; no
# compilation or attestation job binds that environment.
for filename, job in [('release.yml', 'release'), ('build-release.yml', 'publish')]:
    text = (root/'.github/workflows'/filename).read_text()
    block = re.search(r'(?ms)^  '+job+r':\n(?:(?!^  [A-Za-z0-9_-]+:).)*', text)
    assert block and re.search(r'(?m)^    secrets: inherit$', block[0]), f'{filename}: forward the environment secret through the complete release call chain'
print('Complete controller, collector and release credential routing verified.')
