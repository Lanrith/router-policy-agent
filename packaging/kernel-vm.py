#!/usr/bin/env python3
"""Qualify a static kernel-test binary in an offline disposable initramfs VM.

The caller builds the test binary from the recorded source and supplies a
reviewed base archive. No host devices, disk images or external NICs are used.
This fixture does not qualify a signed router image or persistent migration.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile


EXPECTED_TESTS = [
    'TestKernelNativeGuardPermitAndRevoke', 'TestKernelNamedGuardPermitAndRevoke',
    'TestKernelGuardedObjectInspection', 'TestKernelNativeControllerBaseline',
    'TestKernelGuardClassificationRestoreAndSeal', 'TestKernelZeroGrantHistoryClosesReusedNativeAddresses',
    'TestKernelControllerTAYGARoundTrip', 'TestKernelControllerTAYGAICMP', 'TestKernelDeviceTAYGACallbacks',
    'TestKernelNamedOwnershipRefreshAndExpiry',
    'TestKernelNamedOwnershipUsesWriterAndFloorFences',
    'TestKernelNamedOwnershipEpochRejectsOldConnections',
    'TestKernelNamedNativePredicatesRetainEveryField',
    'TestKernelNamedNativeOwnerOrderAndReplies',
    'TestKernelNamedNativeDirectoryPhysicalRevocation',
    'TestKernelNamedCoreServicesWithoutDirectory',
    'TestKernelNamedCoreDependenciesThroughSourceNAT',
    'TestKernelNamedPhysicalFloorAndSourcePairing',
    'TestKernelNamedNAT46TupleTransport',
    'TestKernelNamedNAT46StaticSourceIdentity',
    'TestKernelNamedTranslationFacts',
    'TestKernelNamedNAT46OrderedWirePolicy',
    'TestKernelNamedNAT46TargetOwnership',
    'TestKernelNamedNAT46TargetGrants',
    'TestKernelNamedNAT46SourceGeometry',
    'TestKernelNamedNAT46MappedContext',
    'TestKernelNamedNAT46SharedValidation',
    'TestKernelNamedUplinkNATRetainsSourceAndGrants',
    'TestKernelNamedNAT46PublicationFences',
    'TestKernelNamedNAT46GrantPublicationFences',
    'TestKernelNamedNAT46JoinedTAYGA',
    'TestKernelNamedNAT46JoinedTAYGAUID4',
    'TestKernelNamedNAT46JoinedTAYGAConfiguration',
    'TestKernelNamedNAT64AllocationIdentity',
    'TestKernelNamedNAT64ProjectedOrderAndRevocation',
    'TestKernelNamedNAT64JoinedTAYGAConfiguration',
    'TestKernelNamedNAT64JoinedTAYGAOwner',
    'TestKernelNamedNAT64JoinedTAYGADirectory',
    'TestKernelNamedCombinedTranslationLayout',
]


INIT = b'''#!/usr/bin/python3
import ctypes,os,pathlib,subprocess,traceback
os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
try:
 for name in ('proc','sys','dev','run','tmp'):
  pathlib.Path('/'+name).mkdir(exist_ok=True)
 for kind in ('proc','sysfs','devtmpfs'):
  target={'proc':'proc','sysfs':'sys','devtmpfs':'dev'}[kind]
  subprocess.run(['mount','-t',kind,kind,'/'+target],check=True)
 for name in ('run','tmp'):
  subprocess.run(['mount','-t','tmpfs','tmpfs','/'+name],check=True)
 pathlib.Path('/dev/net').mkdir(exist_ok=True)
 if not pathlib.Path('/dev/net/tun').exists():os.mknod('/dev/net/tun',0o20666,os.makedev(10,200))
 os.chmod('/dev/net/tun',0o666)
 subprocess.run(['modprobe','tun'],check=True)
 subprocess.run(['modprobe','veth'],check=True)
 subprocess.run(['modprobe','dummy','numdummies=0'],check=True)
 pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
 pathlib.Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
 os.chdir('/work/internal/firewall')
 os.environ['ROUTER_POLICY_KERNEL_TEST']='isolated'
 os.environ['ROUTER_POLICY_REQUIRE_HEADER_TEST']='1'
 subprocess.run(['/kernel-tests','-test.v','-test.run=@TEST_PATTERN@'],check=True)
 print('ROUTER_POLICY_KERNEL_VM_PASS',flush=True)
except BaseException:
 traceback.print_exc()
 print('ROUTER_POLICY_KERNEL_VM_FAIL',flush=True)
os.sync()
ctypes.CDLL(None).reboot(0x4321fedc)
'''


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def record(stream, number, name, mode, data=b'', *, uid=0, gid=0, major=0, minor=0):
    name = name.encode()+b'\0'
    fields = [number, mode, uid, gid, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
    header = b'070701'+b''.join(f'{item:08x}'.encode() for item in fields)
    stream.write(header+name+b'\0'*((-(len(header)+len(name))) % 4))
    stream.write(data+b'\0'*((-len(data)) % 4))


def prepare(base, binary, destination, tests):
    entries = {}
    init = INIT.replace(b'@TEST_PATTERN@', ('^('+'|'.join(tests)+')$').encode())
    commands = {'python3', 'python3.13', 'bash', 'sh', 'env', 'mount', 'umount', 'ip', 'nft',
                'nsenter', 'sysctl', 'modprobe', 'kmod', 'tayga', 'stdbuf'}
    with tarfile.open(base) as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            path = PurePosixPath(name)
            assert not path.is_absolute() and '..' not in path.parts
            if name.startswith('boot/vmlinuz-') and member.isfile():
                (destination/'vmlinuz').write_bytes(archive.extractfile(member).read())
            wanted = (name in ('lib', 'lib64', 'bin', 'sbin', 'usr/lib64', 'etc/passwd', 'etc/group',
                               'etc/nsswitch.conf', 'etc/protocols', 'etc/services',
                               'usr/libexec/coreutils/libstdbuf.so') or
                      name.startswith(('usr/lib/modules/', 'usr/lib/x86_64-linux-gnu/', 'usr/lib/python3.13/', 'usr/lib64/')) or
                      str(path.parent) in ('usr/bin', 'usr/sbin') and path.name in commands)
            if not wanted or member.isdir():
                continue
            if member.isfile() or member.islnk():
                entries[name] = (stat.S_IFREG | member.mode, archive.extractfile(member).read(), member.uid, member.gid)
            elif member.issym():
                entries[name] = (stat.S_IFLNK | 0o777, member.linkname.encode(), member.uid, member.gid)
    source = Path(__file__).resolve().parents[1]
    for path in (source/'examples').glob('*.json'):
        entries['work/examples/'+path.name] = (stat.S_IFREG | 0o644, path.read_bytes(), 0, 0)
    translator = next(entries[name] for name in ('usr/sbin/tayga', 'usr/bin/tayga') if name in entries)
    assert stat.S_ISREG(translator[0]), 'The reviewed base must supply a native TAYGA binary.'
    entries['usr/local/sbin/tayga'] = translator
    entries['init'] = (stat.S_IFREG | 0o755, init, 0, 0)
    entries['kernel-tests'] = (stat.S_IFREG | 0o755, binary.read_bytes(), 0, 0)
    assert (destination/'vmlinuz').is_file()
    directories = {'dev', 'proc', 'sys', 'tmp', 'run', 'var', 'etc', 'work', 'work/internal', 'work/internal/firewall'}
    for name in entries:
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
    with gzip.open(destination/'initrd.cpio.gz', 'wb', compresslevel=1) as stream:
        number = 1
        for name in sorted(directories, key=lambda name: (name.count('/'), name)):
            if name not in entries:
                record(stream, number, name, stat.S_IFDIR | 0o755)
                number += 1
        record(stream, number, 'dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
        number += 1
        for name, (mode, data, uid, gid) in sorted(entries.items()):
            record(stream, number, name, mode, data, uid=uid, gid=gid)
            number += 1
        record(stream, number, 'TRAILER!!!', 0)
    source = Path(__file__).resolve().parents[1]
    paths = [source/'go.mod', source/'go.sum']+sorted((source/'packaging').glob('*.py'))
    paths += sorted((source/'examples').glob('*.json'))
    paths += sorted((source/'cmd').rglob('*.go'))+sorted((source/'internal').rglob('*.go'))
    return {'schema': 1, 'base_archive_sha256': digest(base), 'kernel_test_binary_sha256': digest(binary),
            'init_sha256': hashlib.sha256(init).hexdigest(), 'tests': tests,
            'sources': {str(path.relative_to(source)): digest(path) for path in paths},
            **{name+'_sha256': digest(destination/name) for name in ('vmlinuz', 'initrd.cpio.gz')}}


def run_vm(directory, tests):
    with (directory/'console.log').open('wb') as log:
        result = subprocess.run([
            'qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-no-reboot', '-kernel', str(directory/'vmlinuz'), '-initrd', str(directory/'initrd.cpio.gz'),
            '-append', 'console=ttyS0 rdinit=/init panic=1 loglevel=4'
        ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=360)
    console = (directory/'console.log').read_text(errors='replace')
    check_console(console, tests, result.returncode)
    return {'result': 'pass', 'tests': tests, 'inputs_sha256': digest(directory/'inputs.json'),
            'console_sha256': digest(directory/'console.log')}


def check_console(console, tests, status):
    assert status == 0 and 'ROUTER_POLICY_KERNEL_VM_PASS' in console and \
        'ROUTER_POLICY_KERNEL_VM_FAIL' not in console and '--- SKIP:' not in console and \
        '--- FAIL:' not in console, console[-12000:]
    for name in tests:
        assert console.count('=== RUN   '+name+'\n') == 1 and '--- PASS: '+name+' (' in console, name


def vm_batches(tests):
    # Keep the original thirteen-fixture group intact. Run the native core
    # separately, and keep uplink-NAT inspection with the translator fixtures
    # so their table cleanup remains covered. All VMs use the same timeout,
    # writer fences, binary and source inventory.
    # The aggregate can pass only after every selected fixture passes once.
    if tests == EXPECTED_TESTS:
        return [tests[:13], tests[13:18], tests[18:28], tests[28:]]
    return [tests]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--base-sha256', required=True)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--test', action='append', choices=EXPECTED_TESTS)
    args = parser.parse_args()
    tests = args.test or EXPECTED_TESTS
    assert len(tests) == len(set(tests)), 'Duplicate fixture selection.'
    assert not args.work.exists(), 'Choose a new disposable directory.'
    assert args.base.is_file() and digest(args.base) == args.base_sha256, 'Reviewed base digest differs.'
    assert args.test_binary.is_file() and shutil.which('qemu-system-x86_64')
    args.work.mkdir(mode=0o700, parents=True)
    batches = vm_batches(tests)
    prepared = []
    for index, selected in enumerate(batches):
        directory = args.work/('batch-'+str(index+1))
        directory.mkdir(mode=0o700)
        batch_inputs = prepare(args.base, args.test_binary, directory, selected)
        (directory/'inputs.json').write_text(json.dumps(batch_inputs, indent=2, sort_keys=True)+'\n')
        prepared.append((directory, batch_inputs))
    original = prepared[0][1]
    for _, batch_inputs in prepared:
        for field in ('sources', 'base_archive_sha256', 'kernel_test_binary_sha256', 'vmlinuz_sha256'):
            assert batch_inputs[field] == original[field], 'VM batches differ in admitted inputs.'
    inputs = {'schema': 2, 'sources': original['sources'], 'tests': tests,
              'base_archive_sha256': original['base_archive_sha256'],
              'kernel_test_binary_sha256': original['kernel_test_binary_sha256'],
              'vmlinuz_sha256': original['vmlinuz_sha256'],
              'vm_timeout_seconds': 360,
              'vm_batches': [{'directory': str(directory.relative_to(args.work)),
                              'inputs_sha256': digest(directory/'inputs.json'), 'tests': value['tests'],
                              'inputs': value}
                             for directory, value in prepared]}
    (args.work/'inputs.json').write_text(json.dumps(inputs, indent=2, sort_keys=True)+'\n')
    results = []
    with (args.work/'console.log').open('wb') as combined:
        for directory, value in prepared:
            try:
                results.append(run_vm(directory, value['tests']))
            finally:
                if (directory/'console.log').is_file():
                    combined.write((directory/'console.log').read_bytes())
                    combined.flush()
    executed = [name for result in results for name in result['tests']]
    assert len(executed) == len(tests) and set(executed) == set(tests), 'Incomplete fixture coverage.'
    assert all(digest(directory/'inputs.json') == result['inputs_sha256'] and
               digest(directory/'console.log') == result['console_sha256']
               for (directory, _), result in zip(prepared, results, strict=True)), 'VM evidence changed.'
    qualification = {'schema': 2, 'result': 'pass', 'external_network': False,
                     'vm_batches': results, 'vm_timeout_seconds': 360,
                     'inputs_sha256': digest(args.work/'inputs.json'),
                     'console_sha256': digest(args.work/'console.log'),
                     'private_image_qualified': False, 'signed_image_qualified': False,
                     'persistent_state_migration_qualified': False,
                     'tests': tests, 'full_guard_suite': tests == EXPECTED_TESTS,
                     'checks': [name+' passes' for name in tests]+['no skipped packet-header tests']}
    (args.work/'qualification.json').write_text(json.dumps(qualification, indent=2, sort_keys=True)+'\n')
    print('Offline policy guard VM passed; private image qualification remains separate.')


if __name__ == '__main__':
    main()
