import hashlib
from pathlib import Path
import shutil
import tempfile

import pytest

from qq_nt_replica.primary_qimei_fresh_identity import OwnFreshHardwareIdentity, source_cpu_string, source_digest
from test_primary_windows_qimei_fresh_identity import API, CPU
from qq_nt_replica.primary_windows_qimei_fresh_identity import WindowsFreshIdentityHardware

T = Path('G:/Hackergame/.codex-workflow/reports/pmhq-analysis-20261010/signature-audit-20261119/trusted-local-captures')


@pytest.fixture
def own_directory():
    directory = Path(tempfile.mkdtemp(prefix='qimei-fresh-impl-model-', dir=T))
    try:
        yield directory
    finally:
        assert directory.resolve().parent == T.resolve()
        assert directory.name.startswith('qimei-fresh-impl-model-')
        shutil.rmtree(directory)


def test_source_cpu_preserves_spaces_and_nul():
    raw = b'CPU  internal  space\0'.ljust(48, b'X')
    rows = tuple(tuple(int.from_bytes(raw[i+j:i+j+4], 'little') for j in range(0,16,4)) for i in range(0,48,16))
    assert source_cpu_string(rows) == b'CPU  internal  space'
    assert source_digest(b' ', b'CPU ', b'0011220000000000') == hashlib.md5(b' CPU 0011220000000000').digest()


def test_profile_once_restore_and_malformed(own_directory):
    path = own_directory / 'own.json'
    cpu, api = CPU(), API()
    owner = OwnFreshHardwareIdentity(path, own_directory / 'machine-info', WindowsFreshIdentityHardware(cpu, api=api))
    assert not path.exists()
    first = owner.application()
    from qq_nt_replica.primary_qimei_sdk import QimeiSdkContexts
    context = first.configure(QimeiSdkContexts())
    assert context.second == b'{"GUID":"' + first.guid.hex().encode('ascii') + b'"}'
    assert owner.application() is first
    owner.close()

    cpu2, api2 = CPU(), API()
    restored = OwnFreshHardwareIdentity(path, own_directory / 'machine-info', WindowsFreshIdentityHardware(cpu2, api=api2))
    assert restored.application().guid == first.guid
    assert not cpu2.calls and not api2.calls
    restored.close()
    path.write_bytes(b'{}')
    bad = OwnFreshHardwareIdentity(path, own_directory / 'machine-info', WindowsFreshIdentityHardware(CPU(), api=API()))
    with pytest.raises(Exception): bad.application()
    assert path.read_bytes() == b'{}'
    bad.close()


def test_persist_failure_no_resampling(own_directory, monkeypatch):
    cpu, api = CPU(), API()
    owner = OwnFreshHardwareIdentity(own_directory / 'own.json', own_directory / 'machine-info', WindowsFreshIdentityHardware(cpu, api=api))
    def failed_fsync(fd): raise OSError('MODEL first persistence failure')
    monkeypatch.setattr('os.fsync', failed_fsync)
    with pytest.raises(OSError): owner.application()
    assert owner.persisted_prefix
    count = len(cpu.calls)
    with pytest.raises(Exception): owner.application()
    assert len(cpu.calls) == count
    owner.close()


def test_existing_machine_info_refused_without_hardware(own_directory):
    machine = own_directory / 'machine-info'
    machine.write_bytes(b'MODEL existing file')
    cpu, api = CPU(), API()
    owner = OwnFreshHardwareIdentity(own_directory / 'own.json', machine, WindowsFreshIdentityHardware(cpu, api=api))
    with pytest.raises(Exception): owner.application()
    assert not cpu.calls and not api.calls
    owner.close()
