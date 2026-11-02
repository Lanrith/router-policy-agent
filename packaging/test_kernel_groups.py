"""Keep all tagged tests in exactly one required race qualification group."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]


class KernelGroupsTests(unittest.TestCase):
    def capture(self, failure=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'commands.jsonl'
            go = root / 'go'
            go.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
p=pathlib.Path(os.environ['KERNEL_GROUP_TEST_LOG'])
with p.open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
count=len(p.read_text().splitlines())
raise SystemExit(1 if count==int(os.environ['KERNEL_GROUP_TEST_FAILURE']) else 0)
''')
            go.chmod(0o755)
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                       KERNEL_GROUP_TEST_LOG=str(log), KERNEL_GROUP_TEST_FAILURE=str(failure))
            result = subprocess.run(['sh', str(SOURCE/'packaging/kernel-groups.sh')],
                                    env=env, capture_output=True, text=True, check=False)
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            return result, commands

    def test_every_test_or_fuzz_parent_runs_once_with_original_race_options(self):
        result, commands = self.capture()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(4, len(commands))
        parents = {'TestFutureNativeCase', 'TestKernelFutureCase',
                   'TestKernelNamedNAT46FutureCase', 'TestKernelNamedNAT64FutureCase',
                   'FuzzFutureCase', 'ExampleFutureCase'}
        for path in (SOURCE/'internal/firewall').glob('*_test.go'):
            parents.update(re.findall(r'^func ((?:Test|Fuzz|Example)\w*)\(', path.read_text(), re.M))
        for name in sorted(parents):
            matched = []
            for index, command in enumerate(commands):
                include = command[command.index('-run')+1] if '-run' in command else '.'
                exclude = command[command.index('-skip')+1] if '-skip' in command else '^$'
                if re.search(include, name) and not re.search(exclude, name):
                    matched.append(index)
            self.assertEqual(1, len(matched), (name, matched))
        for command in commands:
            self.assertEqual('test', command[0])
            for required in ['-race', '-shuffle=on', '-count=1', 'integration,kernel', './internal/firewall']:
                self.assertIn(required, command)
            self.assertNotIn('-timeout', ' '.join(command))

    def test_a_failed_group_stops_the_required_qualification(self):
        for index in range(1, 5):
            with self.subTest(group=index):
                result, commands = self.capture(index)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(index, len(commands))


if __name__ == '__main__':
    unittest.main()
