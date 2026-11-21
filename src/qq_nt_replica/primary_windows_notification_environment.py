import ctypes as C
import hashlib
import os
import secrets
import threading

from .errors import InputError
from .primary_vm import PrimarySemanticUnavailable
from .primary_windows_ownimage import GUEST_BASE, freeze_capability, freeze_w_capability
from .primary_windows_notification_process import APIS as _PROCESS_APIS, WindowsNotificationProcessService
from .primary_windows_notification_integrity import WindowsNotificationIntegrityService


_LIMIT = 1 << 20
_SIGNATURES = {
    'GetModuleFileNameW': ('kernel32', C.c_uint32, (C.c_void_p, C.c_void_p, C.c_uint32)),
    'PathRemoveFileSpecW': ('shlwapi', C.c_int32, (C.c_void_p,)),
    'GetFileVersionInfoSizeW': ('version', C.c_uint32, (C.c_void_p, C.c_void_p)),
    'GetFileVersionInfoW': ('version', C.c_int32, (C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p)),
    'VerQueryValueW': ('version', C.c_int32, (C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)),
    'GetUserDefaultLangID': ('kernel32', C.c_uint16, ()),
    'GetTimeZoneInformation': ('kernel32', C.c_uint32, (C.c_void_p,)),
}


class _TimeZoneInformation(C.Structure):
    _fields_ = [('Bias', C.c_int32), ('StandardName', C.c_uint16 * 32),
                ('StandardDate', C.c_uint16 * 8), ('StandardBias', C.c_int32),
                ('DaylightName', C.c_uint16 * 32), ('DaylightDate', C.c_uint16 * 8),
                ('DaylightBias', C.c_int32)]


class WindowsNotificationEnvironmentAPIBackend:
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('notification environment observations require Windows AMD64')
        libraries = {name: C.WinDLL(name, use_last_error=True) for name in ('kernel32', 'shlwapi', 'version')}
        self._functions = {}
        for name, (library, result, arguments) in _SIGNATURES.items():
            function = getattr(libraries[library], name)
            function.restype, function.argtypes = result, arguments
            self._functions[name] = function
        self.last_error = None

    def call(self, name, *arguments):
        result = self._functions[name](*arguments)
        self.last_error = C.get_last_error()
        return int(result) & (0xFFFF if name == 'GetUserDefaultLangID' else 0xFFFFFFFF)


def _path(raw):
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= 520 or len(raw) & 1 or raw[-2:] != b'\0\0':
        raise InputError('notification W path/query requires bounded terminated UTF16 bytes')
    if any(raw[index:index + 2] == b'\0\0' for index in range(0, len(raw) - 2, 2)):
        raise InputError('notification W path/query contains premature NUL')
    return C.create_string_buffer(raw, len(raw))


def _mask(before, after):
    return bytes(int(left != right) for left, right in zip(before, after))


class _ParentEnvironment:
    def __init__(self, parent, runtime, owner):
        self.parent, self._runtime, self.owner = parent, runtime, owner
        self._provider = parent._provider.notification_view(runtime, owner)
        self._capability = self._provider
        self._owner = os.getpid(), threading.get_native_id()
        self._session, self._binding = parent._session, parent._binding
        self._integrity = self._process = None
        self._resource = None
        self._raw_events, self.records, self._raw_bytes = [], [], 0
        self._closed = False

    def _check(self, runtime):
        self.parent._parent_check(runtime, self.owner)
        if self._closed or runtime is not self._runtime or self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('notification worker facade is stale')
        self._provider.check(runtime)

    def _source(self, runtime, function):
        import sys
        self._check(runtime)
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not function.__code__:
            frame = frame.f_back
        if frame is None or frame.f_locals.get('runtime') is not runtime:
            raise InputError('notification facade lacks its exact source API frame')
        return frame

    def begin_integrity(self, runtime, rva):
        from .primary_notification_integrity_files import produce
        frame = self._source(runtime, produce)
        if frame.f_locals.get('rva') != rva:
            raise InputError('notification manifest entry differs from its original role')
        if self._integrity is None:
            self._integrity = WindowsNotificationIntegrityService(self, self.parent._integrity_backend)
        self._integrity.begin(runtime, rva)

    def take_integrity(self, runtime, name, arguments):
        from .primary_notification_integrity_files import _observe
        frame = self._source(runtime, _observe)
        if frame.f_locals.get('name') != name or frame.f_locals.get('arguments') != arguments or self._integrity is None:
            raise InputError('notification manifest API differs from its exact source arguments')
        return self._integrity.module_api(runtime, name, arguments)

    def end_integrity(self, runtime, rva):
        self._check(runtime)
        if self._integrity is None:
            raise InputError('notification manifest exit lacks its original entry')
        self._integrity.end(runtime, rva)

    def take(self, runtime, name, arguments):
        from .primary_notification_process import _observe
        frame = self._source(runtime, _observe)
        if (name not in _PROCESS_APIS or frame.f_locals.get('name') != name or
                frame.f_locals.get('arguments') != arguments):
            raise InputError('notification process API differs from its finite original source')
        if self._process is None:
            self._process = WindowsNotificationProcessService(self, self.parent._process_backend)
        event, summary = self._event(runtime, name, arguments)
        return self._process.take(runtime, name, arguments, event, summary)

    def _event(self, runtime, name, arguments):
        return WindowsNotificationEnvironmentObservations._event(self, runtime, name, arguments)

    def _buffer(self, event, summary, role, before, after, defined, preknown=None):
        return WindowsNotificationEnvironmentObservations._buffer(self, event, summary, role, before, after,
                                                                 defined, preknown)

    def close(self):
        if self._closed:
            return
        failure = None
        for resource in (self._integrity, self._process, self._provider):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            raise failure
        self._closed = True


class WindowsNotificationEnvironmentObservations:
    def __init__(self, *, ownimage_module=None, capability=None, backend=None, process_backend=None, integrity_backend=None, mandatory_backend=None, parent_backend=None, module_capability=None, module_backend=None):
        if C.sizeof(C.c_void_p) != 8:
            raise PrimarySemanticUnavailable('notification environment requires pointer width8')
        self._owner = os.getpid(), threading.get_native_id()
        self._provider, self._backend = ownimage_module, backend
        self._process_backend, self._process = process_backend, None
        self._integrity_backend, self._integrity = integrity_backend, None
        self._mandatory_backend, self._mandatory_delegates = mandatory_backend, set()
        self._constructor_delegates = set()
        self._module_delegates = set()
        self._module_backend = module_backend
        self._module_capability = None if module_capability is None else freeze_capability(module_capability)
        if module_capability is not None and ownimage_module is None:
            raise InputError('notification A capability requires its owned live provider')
        self._parent_backend = parent_backend
        self._capability = None if capability is None else freeze_w_capability(capability)
        if capability is not None and ownimage_module is None:
            raise InputError('notification W capability requires its owned live provider')
        self._runtime = None
        self._session, self._binding = secrets.token_hex(16), None
        self._resource = None
        self._seen = set()
        self._raw_events, self.records = [], []
        self._closed = False
        self._close_failure = None
        self._size_observation = None
        self._raw_bytes = 0

    def bind(self, runtime):
        if self._runtime is not None or self._closed:
            raise InputError('notification observer requires one fresh runtime binding')
        self._check_owner()
        if runtime.image_base != GUEST_BASE:
            raise InputError('notification observer requires the fixed guest image')
        if self._capability is not None:
            if self._provider.capability_w_snapshot() != self._capability:
                raise InputError('notification W capability differs from its live provider')
            self._provider.filename_w_relocation(runtime, (runtime.image_base, 260), self._capability)
        if self._module_capability is not None:
            if self._provider.capability_snapshot() != self._module_capability:
                raise InputError('notification A capability differs from its live provider')
        self._runtime, self._binding = runtime, secrets.token_hex(16)

    def _check_owner(self):
        if self._owner != (os.getpid(), threading.get_native_id()):
            raise InputError('notification observer requires its creating process and native thread')

    def notification_mandatory_service(self, runtime, owner):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        from .primary_windows_notification_mandatory import WindowsNotificationMandatoryService
        if (type(owner) is not _NotificationWorkerOwner or not owner.valid() or owner.runtime is not runtime or
                self._owner[0] != os.getpid() or self._closed or self._close_failure is not None or
                self._runtime is not runtime or self._provider is None):
            raise PrimarySemanticUnavailable('mandatory delegation requires its genuine notification owner and bound parent')
        view = self._provider.notification_view(runtime, owner)
        try:
            service = WindowsNotificationMandatoryService(self, owner, view, self._mandatory_backend)
        except BaseException:
            view.close()
            raise
        self._mandatory_delegates.add(service)
        return service

    def release_notification_mandatory(self, service):
        if service not in self._mandatory_delegates:
            raise InputError('mandatory delegate is not owned by this notification parent')
        service.close()
        self._mandatory_delegates.remove(service)

    def module_collector_environment(self, runtime, owner):
        import sys
        from .primary_notification_modules import _module_environment, require_claim
        from .primary_windows_notification_modules import WindowsModuleCollectorObservations
        from .primary_windows_ownimage import WindowsOwnImageModule
        claim = require_claim(runtime)
        frame = sys._getframe(1)
        if (claim.owner is not owner or claim.facade is not None or self._module_delegates or
                self._runtime is not runtime or self._owner[0] != os.getpid() or self._closed or self._close_failure is not None or
                type(self._provider) is not WindowsOwnImageModule or self._module_capability is None or
                frame.f_code is not _module_environment.__wrapped__.__code__ or frame.f_locals.get('runtime') is not runtime or
                frame.f_locals.get('prior') is not self or frame.f_locals.get('environment') is not None):
            raise PrimarySemanticUnavailable('module collector delegate requires its original source factory and explicit A authority')
        environment = WindowsModuleCollectorObservations(self, runtime, owner, self._module_backend)
        self._module_delegates.add(environment)
        return environment

    def release_module_collector_environment(self, environment):
        if environment not in self._module_delegates:
            raise InputError('module collector delegate belongs to a different parent')
        environment.close()
        if not environment.closed:
            raise InputError('module collector delegate cleanup is unresolved')
        self._module_delegates.remove(environment)

    def notification_parent_service(self, runtime, owner):
        from .primary_windows_notification_parent import WindowsNotificationParentObservations
        self._parent_check(runtime, owner)
        return WindowsNotificationParentObservations(self, owner, runtime, backend=self._parent_backend)

    def environment_values_service(self, runtime, facade):
        from .primary_windows_notification_environment_values import WindowsEnvironmentValuesService
        from .primary_notification_environment_values import _window
        import sys
        frame=sys._getframe(1)
        if frame.f_code is not _window.__wrapped__.__code__ or frame.f_locals.get('runtime') is not runtime:
            raise InputError('environment values factory requires original helper window')
        return WindowsEnvironmentValuesService(self,runtime,facade)

    def _parent_check(self, runtime, owner):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        if (type(owner) is not _NotificationWorkerOwner or not owner.valid() or owner.runtime is not runtime or
                self._runtime is not runtime or self._owner[0] != os.getpid() or self._closed or
                self._close_failure is not None or self._provider is None or
                runtime._primary_direct_scope.require_parent_phase().owner is not owner):
            raise PrimarySemanticUnavailable('parent delegation requires its genuine live notification phase')

    def parent_environment(self, runtime, owner):
        self._parent_check(runtime, owner)
        return _ParentEnvironment(self, runtime, owner)

    def _constructor_check(self, runtime, owner):
        from .primary_sign_lifecycle import _NotificationWorkerOwner
        from .primary_windows_ownimage import WindowsOwnImageModule
        if (type(owner) is not _NotificationWorkerOwner or not owner.valid() or owner.runtime is not runtime or
                self._runtime is not runtime or self._owner[0] != os.getpid() or self._closed or
                self._close_failure is not None or type(self._provider) is not WindowsOwnImageModule or self._capability is None or
                runtime._primary_direct_scope.require_constructor_phase().owner is not owner):
            raise PrimarySemanticUnavailable('constructor delegation requires its genuine live notification phase')

    def constructor_environment(self, runtime, owner):
        import sys
        from .primary_notification_environment import _constructor_phase
        self._constructor_check(runtime, owner)
        frame = sys._getframe(1)
        if (frame.f_code is not _constructor_phase.__wrapped__.__code__ or
                frame.f_locals.get('runtime') is not runtime or frame.f_locals.get('prior') is not self or
                frame.f_locals.get('environment') is not None or self._constructor_delegates):
            raise InputError('constructor delegate requires its one original phase factory')
        environment = _ConstructorEnvironment(self, runtime, owner)
        self._constructor_delegates.add(environment)
        return environment

    def release_constructor_environment(self, environment):
        if environment not in self._constructor_delegates:
            raise InputError('constructor delegate is not owned by this notification parent')
        try:
            environment.close()
        finally:
            self._constructor_delegates.remove(environment)

    def begin_integrity(self, runtime, rva):
        self._check(runtime)
        if self._integrity is None:
            self._integrity = WindowsNotificationIntegrityService(self, self._integrity_backend)
        self._integrity.begin(runtime, rva)

    def take_integrity(self, runtime, name, arguments):
        self._check(runtime)
        if self._integrity is None:
            raise InputError('manifest API requires explicit producer role entry')
        return self._integrity.module_api(runtime, name, arguments)

    def end_integrity(self, runtime, rva):
        self._check(runtime)
        if self._integrity is None:
            raise InputError('manifest role exit lacks its producer entry')
        self._integrity.end(runtime, rva)

    def _check(self, runtime):
        self._check_owner()
        if self._closed or self._close_failure is not None or runtime is not self._runtime:
            raise InputError('notification observer requires its open bound runtime')
        if self._capability is not None:
            if self._provider.capability_w_snapshot() != self._capability:
                raise InputError('notification W provider session is stale')
            self._provider.filename_w_relocation(runtime, (runtime.image_base, 260), self._capability)

    def _allocation(self, runtime, base, size):
        if type(base) is not int or type(size) is not int or not 0 < size <= _LIMIT or runtime.allocations.get(base) != size:
            raise InputError('notification resource requires an exact live source allocation')
        region, offset = runtime.memory._span(base, size)
        if region.address != base or offset != 0 or len(region.data) != size:
            raise InputError('notification resource requires its exact allocation region')
        return region

    def register_version_resource(self, runtime, guestbase, size):
        self._check(runtime)
        region = self._allocation(runtime, guestbase, size)
        if self._resource is not None or guestbase in self._seen:
            raise InputError('notification resource registration is duplicate or reused')
        if runtime.memory.read(guestbase, size) != bytes(size):
            raise InputError('notification resource registration requires a known zero preimage')
        observed = self._size_observation
        if observed is None or observed['size'] != size or not observed['result']:
            raise InputError('notification resource lacks its matching size observation')
        backing = C.create_string_buffer(size)
        self._resource = dict(base=guestbase, size=size, region=region, backing=backing,
                              generation=secrets.token_hex(16), info=False, size_observation=observed)
        self._size_observation = None
        self._seen.add(guestbase)

    def _live(self, runtime, guestbase):
        record = self._resource
        if record is None or guestbase != record['base'] or self._allocation(runtime, guestbase, record['size']) is not record['region']:
            raise InputError('notification resource binding is missing or stale')
        return record

    def release_version_resource(self, runtime, guestbase):
        self._check(runtime)
        record = self._live(runtime, guestbase)
        C.memset(record['backing'], 0, record['size'])
        self._resource = None

    def _event(self, runtime, name, arguments):
        reserve = 6 * (self._resource['size'] if self._resource is not None else 520) + 256
        if len(self._raw_events) >= 64 or self._raw_bytes + reserve > 32 * _LIMIT:
            raise PrimarySemanticUnavailable('notification raw event retention bound reached')
        event = dict(sequence=len(self._raw_events), api=name, variant='W', phase='notification-environment',
                     logical_arguments=arguments, owner=self._owner, session=self._session, runtime_binding=self._binding,
                     status='started', native_arguments=None, result=None, last_error=None, buffers=[])
        summary = dict(sequence=event['sequence'], api=name, variant='W', phase=event['phase'], status='started', buffers=[])
        self._raw_events.append(event)
        self.records.append(summary)
        return event, summary

    def _buffer(self, event, summary, role, before, after, defined, preknown=None):
        self._raw_bytes += len(before) * 2 + len(after) + len(defined) + len(after)
        if self._raw_bytes > 40 * _LIMIT:
            raise PrimarySemanticUnavailable('notification raw event memory bound reached')
        event['buffers'].append(dict(role=role, preimage=before, postimage=after, defined_mask=defined,
                                     preknown_mask=b'\1' * len(before) if preknown is None else preknown,
                                     observed_change_mask=_mask(before, after)))
        summary['buffers'].append(dict(role=role, size=len(after), pre_sha256=hashlib.sha256(before).hexdigest(),
                                       post_sha256=hashlib.sha256(after).hexdigest(), defined_count=sum(defined),
                                       observed_changes=sum(_mask(before, after))))

    def _call(self, event, name, arguments):
        if self._backend is None:
            self._backend = WindowsNotificationEnvironmentAPIBackend()
        event['native_arguments'] = tuple(C.addressof(value) if isinstance(value, C.Array) else value for value in arguments)
        result = self._backend.call(name, *arguments)
        event['last_error'] = getattr(self._backend, 'last_error', None)
        if type(result) is not int or not 0 <= result <= (0xFFFF if name == 'GetUserDefaultLangID' else 0xFFFFFFFF):
            raise InputError('notification backend returned an invalid typed scalar')
        event['result'] = result
        return result

    def take(self, runtime, name, arguments):
        self._check(runtime)
        if (name not in _SIGNATURES and name not in _PROCESS_APIS) or not isinstance(arguments, tuple):
            raise InputError('notification observer supports only its finite named APIs')
        event, summary = self._event(runtime, name, arguments)
        try:
            result, effects = self._take(runtime, name, arguments, event, summary)
            event['status'] = summary['status'] = 'observed'
            summary['result'] = summary.pop('_safe_result', result)
            return result, effects
        except BaseException as error:
            event['status'] = summary['status'] = 'failed'
            summary['error_type'] = type(error).__name__
            summary['message_sha256'] = hashlib.sha256(str(error).encode('utf-8', 'replace')).hexdigest()
            raise

    def _take(self, runtime, name, arguments, event, summary):
        if name in _PROCESS_APIS:
            if self._process is None:
                self._process = WindowsNotificationProcessService(self, self._process_backend)
            return self._process.take(runtime, name, arguments, event, summary)
        if name == 'GetTimeZoneInformation':
            size = C.sizeof(_TimeZoneInformation)
            if len(arguments) != 1 or type(arguments[0]) is not int or arguments[0] != size:
                raise InputError('notification timezone requires its exact172-byte output role')
            buffer = C.create_string_buffer(b'\xA5' * size, size)
            before = buffer.raw
            result = self._call(event, name, (buffer,))
            successful = result != 0xFFFFFFFF
            self._buffer(event, summary, 'system-timezone', before, buffer.raw,
                         bytes([int(successful)]) * size, bytes(size))
            summary['role'] = 'system-timezone'
            summary['output_usable'] = successful
            return result, buffer.raw if successful else b''
        if name == 'GetModuleFileNameW':
            if len(arguments) != 2 or any(type(value) is not int for value in arguments) or arguments[1] != 260:
                raise InputError('notification filename requires capacity260 and a finite module role')
            module = arguments[0]
            if module == 0:
                native, role = 0, 'current-executable'
            elif module == runtime.image_base and self._capability is not None:
                native_args, capability = self._provider.filename_w_relocation(runtime, arguments, self._capability)
                native, role = native_args[0], 'wrapper-own-image'
                event['capability'] = capability
            else:
                raise InputError('notification filename module role lacks explicit W authority')
            buffer = C.create_string_buffer(520)
            before = buffer.raw
            result = self._call(event, name, (native, buffer, 260))
            self._buffer(event, summary, role, before, buffer.raw, b'\1' * 520)
            summary['role'] = role
            return result, buffer.raw
        if name == 'PathRemoveFileSpecW':
            if len(arguments) != 1 or not isinstance(arguments[0], bytes) or len(arguments[0]) != 520:
                raise InputError('notification directory requires a complete520-byte preimage')
            raw = arguments[0]
            if not any(raw[index:index + 2] == b'\0\0' for index in range(0, 520, 2)):
                raise InputError('notification directory native input is unterminated')
            buffer = C.create_string_buffer(raw, 520)
            result = self._call(event, name, (buffer,))
            self._buffer(event, summary, 'directory-in-place', raw, buffer.raw, b'\1' * 520)
            return result, buffer.raw
        if name == 'GetUserDefaultLangID':
            if arguments:
                raise InputError('notification LANGID requires no arguments')
            return self._call(event, name, ()), b''
        if name == 'GetFileVersionInfoSizeW':
            if len(arguments) != 1:
                raise InputError('notification version size requires one path')
            path = _path(arguments[0])
            handle = C.create_string_buffer(b'\xA5' * 4, 4)
            before = handle.raw
            result = self._call(event, name, (path, handle))
            self._buffer(event, summary, 'version-handle', before, handle.raw, (b'\1' if result else b'\0') * 4, bytes(4))
            self._size_observation = dict(path=arguments[0], size=result, result=result, handle=handle.raw) if result else None
            return result, handle.raw if result else b''
        if name == 'GetFileVersionInfoW':
            if len(arguments) != 4:
                raise InputError('notification version info requires exact source arguments')
            path, handle, size, zeroed = arguments
            if type(handle) is not int or not 0 <= handle <= 0xFFFFFFFF or type(size) is not int or zeroed is not True:
                raise InputError('notification version info arguments leave their ABI domain')
            record = self._resource
            if record is None:
                raise InputError('notification version info requires explicit resource registration')
            self._live(runtime, record['base'])
            observed = record['size_observation']
            if record.get('attempted') or size != record['size'] or path != observed['path'] or handle != int.from_bytes(observed['handle'], 'little'):
                raise InputError('notification version info does not match its size/handle provenance')
            native_path = _path(path)
            backing = record['backing']
            before = backing.raw
            if before != bytes(size) or runtime.memory.read(record['base'], size) != bytes(size):
                raise InputError('notification version info lost its zero preimage')
            result = self._call(event, name, (native_path, handle, size, backing))
            record['info'] = bool(result)
            record['attempted'] = True
            self._buffer(event, summary, 'version-resource', before, backing.raw, b'\1' * size)
            runtime.memory.write(record['base'], backing.raw, source='notification_native.version_info_mirror')
            return result, backing.raw
        if len(arguments) != 2:
            raise InputError('notification version query requires resource and query')
        guestbase, query = arguments
        record = self._live(runtime, guestbase)
        if not record['info']:
            raise InputError('notification version query requires successful version info')
        native_query = _path(query)
        backing, size = record['backing'], record['size']
        pointer = C.create_string_buffer(8)
        length = C.create_string_buffer(b'\xA5' * 4, 4)
        before = backing.raw
        result = self._call(event, name, (backing, native_query, pointer, length))
        native_pointer = int.from_bytes(pointer.raw, 'little')
        hostbase = C.addressof(backing)
        self._buffer(event, summary, 'query-pointer', bytes(8), pointer.raw, (b'\1' if result else b'\0') * 8)
        self._buffer(event, summary, 'query-length', b'\xA5' * 4, length.raw, (b'\1' if result else b'\0') * 4, bytes(4))
        self._buffer(event, summary, 'version-resource-query', before, backing.raw, b'\1' * size)
        if native_pointer and not hostbase <= native_pointer < hostbase + size:
            raise PrimarySemanticUnavailable('notification native query returned a foreign resource pointer')
        offset = native_pointer - hostbase if native_pointer else None
        event['resource_relocation'] = dict(guestbase=guestbase, nativebase=hostbase, offset=offset,
                                            generation=record['generation'])
        summary['resource_offset'] = offset
        guest_pointer = 0 if offset is None else guestbase + offset
        runtime.memory.write(guestbase, backing.raw, source='notification_native.query_resource_mirror')
        return result, (guest_pointer.to_bytes(8, 'little') if result else b'', length.raw if result else b'',
                        ((guestbase, backing.raw),))

    def close(self):
        self._check_owner()
        if self._closed:
            if self._close_failure is not None:
                raise self._close_failure
            return
        if self._mandatory_delegates or self._constructor_delegates or self._module_delegates:
            raise PrimarySemanticUnavailable('notification parent retains active mandatory delegates')
        if self._integrity is not None:
            try:
                self._integrity.close()
            except BaseException as error:
                self._close_failure = error
                raise
            self._integrity = None
            self._close_failure = None
        if self._process is not None:
            try:
                self._process.close()
            except BaseException as error:
                self._close_failure = error
                raise
            self._process = None
            self._close_failure = None
        outstanding = self._resource is not None
        if outstanding:
            C.memset(self._resource['backing'], 0, self._resource['size'])
            self._resource = None
        self._raw_events.clear()
        self._raw_bytes = 0
        self._size_observation = None
        self._module_capability = self._module_backend = None
        self._capability = self._provider = self._runtime = None
        self._mandatory_backend = None
        self._session = self._binding = None
        self._closed = True
        if outstanding:
            self._close_failure = PrimarySemanticUnavailable('notification observer closed with an unreleased source resource')
            raise self._close_failure


    @property
    def diagnostics(self):
        return dict(closed=self._closed, resource_count=int(self._resource is not None) +
                    len(self._module_delegates) + len(self._mandatory_delegates) + sum(len(item.files) for item in self._mandatory_delegates) +
                    (self._process.resource_count if self._process is not None else 0) +
                    (self._integrity.resource_count if self._integrity is not None else 0),
                    integrity_records=[] if self._integrity is None else [dict(item) for item in self._integrity.records],
                    mandatory_delegates=len(self._mandatory_delegates), module_delegates=len(self._module_delegates),
                    raw_events=len(self._raw_events), safe_events=len(self.records),
                    close_failed=self._close_failure is not None, runtime_bound=self._runtime is not None,
                    records=[dict(record, buffers=[dict(buffer) for buffer in record['buffers']]) for record in self.records])


class _ConstructorEnvironment:
    def __init__(self, parent, runtime, owner):
        self.parent, self._runtime, self.owner = parent, runtime, owner
        self.claim = runtime._primary_direct_scope.require_constructor_phase()
        self._provider = parent._provider.constructor_view(runtime, owner, parent._capability)
        self._capability = self._provider
        self._authority = parent._capability
        self._owner = os.getpid(), threading.get_native_id()
        self._session, self._binding = parent._session, parent._binding
        self._backend = parent._backend
        self._resource, self._size_observation = None, None
        self._resource_generation = None
        self._seen = set()
        self._raw_events, self.records, self._raw_bytes = [], [], 0
        self._closed = False

    def _check(self, runtime):
        self.parent._constructor_check(runtime, self.owner)
        if (self._closed or runtime is not self._runtime or self._owner != (os.getpid(), threading.get_native_id()) or
                runtime._primary_direct_scope.require_constructor_phase() is not self.claim or
                runtime.__dict__.get('notification_environment_observations') is not self or
                self.parent._session != self._session or self.parent._binding != self._binding or
                self.parent._capability is not self._authority or
                self not in self.parent._constructor_delegates):
            raise InputError('notification constructor facade is stale or substituted')
        self._provider.check(runtime)

    def _source(self, runtime, function):
        import sys
        self._check(runtime)
        frame = sys._getframe(1)
        while frame is not None and frame.f_code is not function.__code__:
            frame = frame.f_back
        if frame is None or frame.f_locals.get('runtime') is not runtime:
            raise InputError('notification constructor lacks its exact source API frame')
        return frame

    def take(self, runtime, name, arguments):
        from .primary_notification_environment import _IMPORTS, _observe
        frame = self._source(runtime, _observe)
        if (name not in _IMPORTS or type(arguments) is not tuple or frame.f_locals.get('name') != name or
                frame.f_locals.get('arguments') != arguments or runtime.worker_imports.get(name) is None or
                runtime.memory.load(runtime.image_base + _IMPORTS[name], 8) != runtime.worker_imports[name]):
            raise InputError('notification constructor API differs from its finite current source arguments')
        event, summary = self._event(runtime, name, arguments)
        event['phase'] = summary['phase'] = 'notification-constructor'
        try:
            result, effects = WindowsNotificationEnvironmentObservations._take(self, runtime, name, arguments, event, summary)
            event['status'] = summary['status'] = 'observed'
            summary['result'] = summary.pop('_safe_result', result)
            return result, effects
        except BaseException as error:
            event['status'] = summary['status'] = 'failed'
            summary['error_type'] = type(error).__name__
            summary['message_sha256'] = hashlib.sha256(str(error).encode('utf-8', 'replace')).hexdigest()
            raise

    def register_version_resource(self, runtime, guestbase, size):
        from .primary_notification_environment import metadata
        frame = self._source(runtime, metadata)
        if frame.f_locals.get('buffer') != guestbase or frame.f_locals.get('size') != size:
            raise InputError('constructor resource differs from its metadata source allocation')
        WindowsNotificationEnvironmentObservations.register_version_resource(self, runtime, guestbase, size)
        self._resource_generation = self._resource['generation']

    def _live(self, runtime, guestbase):
        self._check(runtime)
        record = WindowsNotificationEnvironmentObservations._live(self, runtime, guestbase)
        if self._resource_generation is None or record['generation'] != self._resource_generation:
            raise InputError('constructor version resource generation is stale')
        return record

    def release_version_resource(self, runtime, guestbase):
        from .primary_notification_environment import _free_resource
        frame = self._source(runtime, _free_resource)
        if frame.f_locals.get('buffer') != guestbase or frame.f_locals.get('registered') is not True:
            raise InputError('constructor resource release differs from its metadata cleanup')
        WindowsNotificationEnvironmentObservations.release_version_resource(self, runtime, guestbase)
        self._resource_generation = None

    _allocation = WindowsNotificationEnvironmentObservations._allocation
    _event = WindowsNotificationEnvironmentObservations._event
    _buffer = WindowsNotificationEnvironmentObservations._buffer
    _call = WindowsNotificationEnvironmentObservations._call

    def close(self):
        if self._closed:
            return
        outstanding = self._resource is not None
        if outstanding:
            C.memset(self._resource['backing'], 0, self._resource['size'])
            self._resource = None
        self._size_observation = None
        self._resource_generation = None
        self._provider.close()
        self._closed = True
        if outstanding:
            raise PrimarySemanticUnavailable('constructor closed with an unreleased source resource')

