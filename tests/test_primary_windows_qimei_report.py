"""Injected ANSI API/CRT metadata only; no machine directory is collected."""
import ctypes as C
import struct
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from qq_nt_replica.primary_qimei_application import APPLICATION_OWNER
from qq_nt_replica.primary_qimei_report_sources import QimeiReportSources
from qq_nt_replica.primary_qimei_request import QimeiRequestBoundary
from qq_nt_replica.primary_windows_qimei_report import WindowsQimeiReportObservations


class Metadata:
    root = b'X:\\MODEL\\Tencent Files'

    def __init__(self, entries=(), existing=None, folder_ok=True):
        self.entries = list(entries)
        self.existing = {} if existing is None else existing
        self.folder_ok = folder_ok
        self.calls, self.times = [], []
        self.local_error, self.calendar_bad, self.close_ok, self.fail_next = 0, False, True, False
        names = ('SHGetSpecialFolderPathA', '_access', '_stat64', 'FindFirstFileA',
                 'FindNextFileA', 'FindClose', '_localtime64_s')
        self.api = NS(**{name: Mock(side_effect=lambda *args, n=name: self.call(n, *args)) for name in names})

    def entry(self, target, entry):
        name, attributes = entry
        raw = attributes.to_bytes(4, 'little') + bytes(40) + name + b'\0'
        C.memmove(target, raw, len(raw))

    def call(self, name, *args):
        self.calls.append((name, args[:1] if name != 'SHGetSpecialFolderPathA' else (args[2],)))
        if name == 'SHGetSpecialFolderPathA':
            hwnd, output, identifier, create = args
            assert hwnd == 0 and create == 1 and output.raw == bytes(260)
            assert identifier in (0x1A, 5)
            C.memmove(output, b'X:\\MODEL\0', 9)
            return int(self.folder_ok)
        if name == '_access':
            path, mode = args
            assert mode == 0
            return 0 if path in (self.root, b'\\Tencent Files') or path in self.existing else -1
        if name == '_stat64':
            path, output = args
            value = self.existing[path]
            if value is None:
                return -1
            C.memmove(C.addressof(output) + 0x28, (value & ((1 << 64) - 1)).to_bytes(8, 'little'), 8)
            return 0
        if name == 'FindFirstFileA':
            self.cursor = 0
            if not self.entries:
                return -1
            self.entry(args[1], self.entries[0])
            return 17
        if name == 'FindNextFileA':
            assert args[0] == 17
            if self.fail_next:
                raise OSError('controlled enumeration failure')
            self.cursor += 1
            if self.cursor == len(self.entries):
                return 0
            self.entry(args[1], self.entries[self.cursor])
            return 1
        if name == 'FindClose':
            assert args == (17,)
            return int(self.close_ok)
        assert name == '_localtime64_s'
        timestamp = C.cast(args[1], C.POINTER(C.c_int64))[0]
        self.times.append(timestamp)
        tm = (timestamp % 60, 0, 0, 1, 0, 126, 4, 0, 0)
        if self.calendar_bad:
            tm = (0, 0, 90, 1, 0, 126, 4, 0, 0)
        C.memmove(args[0], struct.pack('<9i', *tm), 36)
        return self.local_error

    def sources(self):
        self.port = WindowsQimeiReportObservations(api=self.api)
        return QimeiReportSources(self.port)

    def path(self, name, primary=True):
        return self.root + b'\\' + name + (b'\\nt_qq\\nt_db' if primary else b'\\QQGuild\\nt_db')


def test_priority_filter_tie_and_api_order():
    md = Metadata([(b'.', 16), (b'..', 16), (b'abc', 16), (b'12x', 16),
                   (b'2', 0), (b'01', 16), (b'3', 16), (b'4', 16), (b'5', 16), (b'6', 16)])
    md.existing = {md.path(b'01'): 11, md.path(b'01', False): 99,
                   md.path(b'3'): None, md.path(b'3', False): 88,
                   md.path(b'4', False): 12, md.path(b'6'): 11}
    report = md.sources().collect(APPLICATION_OWNER)
    assert report.available
    assert report.values == (b'', b'', b'4&2026-01-01 00:00:12#01&2026-01-01 00:00:11#3&2026-01-01 00:00:00', b'', b'', b'')
    accesses = [args[0] for name, args in md.calls if name == '_access']
    assert accesses == [md.root, md.path(b'01'), md.path(b'3'), md.path(b'4'),
                        md.path(b'4', False), md.path(b'5'), md.path(b'5', False), md.path(b'6')]
    assert md.calls[:4] == [('SHGetSpecialFolderPathA', (0x1A,)),
        ('SHGetSpecialFolderPathA', (5,)), ('_access', (md.root,)), ('FindFirstFileA', (md.root + b'/*',))]
    assert not md.port._handles
    assert md.api.FindFirstFileA.restype == C.c_void_p
    assert md.api._stat64.argtypes == (C.c_char_p, C.c_void_p)
    md.port.close()


def test_unsigned_sort_top10_before_u32_time_and_first_tie():
    md = Metadata([(str(i).encode(), 16) for i in range(13)])
    values = [(1 << 64) - 1, 1 << 32, 1 << 32, *range(3, 13)]
    md.existing = {md.path(str(i).encode()): value for i, value in enumerate(values)}
    value = md.sources().collect(APPLICATION_OWNER).values[2]
    assert [row.split(b'&')[0] for row in value.split(b'#')] == [b'0', b'1', b'12', b'11', b'10', b'9', b'8', b'7', b'6', b'5']
    assert md.times == [0xffffffff, 0, 12, 11, 10, 9, 8, 7, 6, 5]
    md.port.close()


@pytest.mark.parametrize('kind', ['root-missing', 'find-empty', 'no-numeric', 'folder-failed'])
def test_empty_and_failed_personal_path(kind):
    md = Metadata(folder_ok=kind != 'folder-failed')
    if kind == 'root-missing':
        md.root = b'absent'
    if kind == 'no-numeric':
        md.entries = [(b'abc', 16), (b'123', 0)]
    sources = md.sources()
    report = sources.collect(APPLICATION_OWNER)
    assert report.values == (b'',) * 6 and not report.available
    if kind == 'folder-failed':
        assert ('FindFirstFileA', (b'\\Tencent Files/*',)) in md.calls
    if kind == 'root-missing':
        assert not md.api.FindFirstFileA.called
    md.port.close()


@pytest.mark.parametrize('calendar', [False, True])
def test_formatter_abnormal_is_unsupported_after_findclose(calendar):
    md = Metadata([(b'1', 16)])
    md.local_error, md.calendar_bad = (0, True) if calendar else (22, False)
    with pytest.raises(QimeiRequestBoundary, match='source80588'):
        md.sources().collect(APPLICATION_OWNER)
    assert md.times == [0] and md.api.FindClose.call_count == 1 and not md.port._handles
    md.port.close()


def test_owner_unsupported_enumeration_exception_and_cleanup_debt():
    md = Metadata([(b'1', 16)])
    source = md.sources()
    with pytest.raises(QimeiRequestBoundary, match='fixed QQ owner'):
        source.collect(b'other')
    assert not md.calls
    md.fail_next = True
    with pytest.raises(OSError, match='enumeration'):
        source.collect(APPLICATION_OWNER)
    assert not md.port._handles
    md.port.close()
    md = Metadata([(b'1', 16)])
    md.close_ok = False
    assert md.sources().collect(APPLICATION_OWNER).available
    with pytest.raises(QimeiRequestBoundary, match='cleanup debt'):
        md.port.close()
    assert md.port._handles == {17} and not md.port._closed
    md.close_ok = True
    md.port.close()
    assert not md.port._handles


def test_port_construction_is_lazy():
    port = WindowsQimeiReportObservations()
    assert not port._libraries and not port._functions
    port.close()
