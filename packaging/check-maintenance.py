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
print('Complete controller and collector references verified.')
