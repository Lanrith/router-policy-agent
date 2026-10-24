"""Check that aggregate qualification cannot omit or hide a failed fixture."""

import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('kernel_vm', Path(__file__).with_name('kernel-vm.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class QualificationTests(unittest.TestCase):
    def test_default_batches_retain_the_whole_previous_suite_and_new_owner(self):
        batches = runner.vm_batches(runner.EXPECTED_TESTS)
        self.assertEqual([13, 5, 10, 11], [len(batch) for batch in batches])
        executed = [name for batch in batches for name in batch]
        self.assertEqual(runner.EXPECTED_TESTS, executed)
        self.assertEqual(len(executed), len(set(executed)))
        translators = batches[2]
        self.assertIn('TestKernelNamedUplinkNATRetainsSourceAndGrants', translators)
        self.assertIn('TestKernelNamedNAT46TupleTransport', translators)
        self.assertEqual(['TestKernelNamedNAT46PublicationFences',
                          'TestKernelNamedNAT46GrantPublicationFences',
                          'TestKernelNamedNAT46JoinedTAYGA',
                          'TestKernelNamedNAT46JoinedTAYGAUID4',
                          'TestKernelNamedNAT46JoinedTAYGAConfiguration',
                          'TestKernelNamedNAT64AllocationIdentity',
                          'TestKernelNamedNAT64ProjectedOrderAndRevocation',
                          'TestKernelNamedNAT64JoinedTAYGAConfiguration',
                          'TestKernelNamedNAT64JoinedTAYGAOwner',
                          'TestKernelNamedNAT64JoinedTAYGADirectory',
                          'TestKernelNamedCombinedTranslationLayout'], batches[-1])

    def test_selected_fixtures_do_not_expand_into_an_unrequested_suite(self):
        selected = [runner.EXPECTED_TESTS[0]]
        self.assertEqual([selected], runner.vm_batches(selected))

    def test_every_fixture_must_run_once_and_pass_without_skips_or_failures(self):
        names = runner.EXPECTED_TESTS[:2]
        complete = ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)
        complete += 'ROUTER_POLICY_KERNEL_VM_PASS\n'
        runner.check_console(complete, names, 0)
        variants = [
            (complete, 1),
            (complete.replace('ROUTER_POLICY_KERNEL_VM_PASS', 'ROUTER_POLICY_KERNEL_VM_FAIL'), 0),
            (complete+'--- SKIP: hidden/subtest (0.01s)\n', 0),
            (complete+'--- FAIL: hidden/subtest (0.01s)\n', 0),
            (complete.replace('=== RUN   '+names[0]+'\n', ''), 0),
            (complete+'=== RUN   '+names[0]+'\n', 0),
            (complete.replace('--- PASS: '+names[1], 'missing: '+names[1]), 0),
        ]
        for console, status in variants:
            with self.subTest(console=console, status=status), self.assertRaises(AssertionError):
                runner.check_console(console, names, status)


if __name__ == '__main__':
    unittest.main()
