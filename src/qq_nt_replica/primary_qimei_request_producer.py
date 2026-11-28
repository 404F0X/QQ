from dataclasses import dataclass, field

from .primary_qimei_context import classify
from .primary_qimei_observations import QimeiClassifierObservations
from .primary_qimei_request import QimeiRequestBoundary, QimeiRequestError, QimeiRequestState, _bytes, _integer
from .primary_qimei_sdk import QimeiSdkContext
from .primary_qimei_settings import QimeiSettings
from .primary_qimei_system_sources import QimeiSystemSources


@dataclass(frozen=True)
class RequestSourceReply:
    result: int
    values: tuple[bytes, ...] = field(repr=False)


class QimeiRequestProducer:
    def __init__(self, owner, settings, sdk_contexts, system, extras, extensions, *, classifier_observations=None, settings_dependencies=None):
        self.owner = _bytes(owner)
        if not isinstance(settings, QimeiSettings) or not isinstance(system, QimeiSystemSources):
            raise QimeiRequestError('source settings and system producer required')
        self.settings, self.sdk_contexts, self.system, self.extras, self.extensions = settings, sdk_contexts, system, extras, extensions
        self.classifier_observations = classifier_observations
        self.settings_dependencies = {} if settings_dependencies is None else settings_dependencies

    def _flag(self, number, io=None):
        return self.settings.flag(number, **(self.settings_dependencies if io is None else io.settings_dependencies)) != 0

    def _extension(self, name, io=None):
        if name == 'identity_3fafa' and io is not None:
            return self.extensions.identity_3fafa(observations=io.request_observations, write_main=io.write_main)
        method = getattr(self.extensions if io is None else io.extension, name, None)
        if not callable(method):
            raise QimeiRequestBoundary('unimplemented source request producer: ' + name)
        return method()

    def _group(self, name, fields, request, *, zero_success=False, low_byte=True, io=None):
        reply = self._extension(name, io)
        if not isinstance(reply, RequestSourceReply) or type(reply.values) is not tuple or len(reply.values) != len(fields):
            raise QimeiRequestError('explicit source group result and String outputs required')
        result = _integer(reply.result) & (255 if low_byte else 0xFFFFFFFF)
        success = result == 0 if zero_success else result != 0
        if success:
            for number, value in zip(fields, reply.values):
                request.set_string(number, _bytes(value))
        return success

    def populate_base(self, request, sdk, *, io=None):
        if not isinstance(request, QimeiRequestState) or not isinstance(sdk, QimeiSdkContext):
            raise QimeiRequestError('source request and SDK context required')
        system = self.system if io is None else io.system
        request.set_decimal32(3, system.wow64())
        request.set_decimal32(38, system.is_admin())
        request.set_string(37, system.boot_descriptions())
        for fields, method in (((4, 5), system.machine_names), ((6, 7, 8, 9), system.processor_info)):
            reply = method()
            if reply.accepted:
                for number, value in zip(fields, reply.values):
                    request.set_string(number, value)
        reply = system.windows_info()
        if reply.accepted:
            request.set_string(10, reply.values[2])
        reply = system.bios_info()
        if reply.accepted:
            for number, value in zip((11, 12, 13, 14, 15), reply.values):
                request.set_string(number, value)
        for number, method in ((16, system.keyboard_layouts), (17, system.timezone_name)):
            reply = method()
            if reply.accepted:
                request.set_string(number, reply.value)
        reply = system.memory_info()
        if reply.accepted:
            for number, value in zip((18, 19), reply.values):
                request.set_decimal64(number, value)
        request.set_decimal32(1, system.process_id())
        reply = system.executable_path()
        if reply.accepted:
            request.set_string(2, reply.value)
            compatibility = system.compatibility_flags(reply.value)
            if compatibility.accepted:
                request.set_string(39, compatibility.value)
        observations = self.classifier_observations if io is None else io.classifier_observations
        if observations is None:
            observations = QimeiClassifierObservations(system.observations)
        request.set_decimal32(40, classify(observations))
        sdk.write_request_fields(request)
        request.set_u32(49, system.request_version())

    def populate(self, request=None, *, io=None):
        request = QimeiRequestState() if request is None else request
        if not isinstance(request, QimeiRequestState):
            raise QimeiRequestError('source request state required')
        if self._flag(3, io):
            values = self._extension('primary_adapter', io)
            if type(values) is not tuple or len(values) != 2:
                raise QimeiRequestError('source primary adapter requires two Strings')
            request.set_string(20, _bytes(values[0]))
            request.set_string(48, _bytes(values[1]))
            request.set_string(42, _bytes(self._extension('extension_7f67a', io)))
        if self._flag(4, io) and self._group('storage_device', (21, 22, 23), request, io=io):
            request.set_decimal64(41, self._extension('extension_898d4', io))
            request.set_string(43, _bytes(self._extension('extension_89b97', io)))
        if self._flag(5, io) and self._group('extension_7b1cb', (24, 25), request, io=io):
            request.set_decimal64(44, self._extension('extension_89d6a', io))
        for gate, name, fields in ((6, 'extension_92f6c', (26,)), (7, 'extension_9335e', (27,)),
                                    (8, 'extension_93721', (28,)), (9, 'extension_93ade', (13, 14, 15, 29, 30))):
            if self._flag(gate, io):
                self._group(name, fields, request, zero_success=True, low_byte=False, io=io)
        request.set_string(32, _bytes(self._extension('identity_3fafa', io)))
        if self._flag(10, io):
            self._group('extension_95cfb', (33, 34, 35), request, low_byte=False, io=io)
        if self._flag(11, io) and self._group('extension_7ad98', (36,), request, io=io):
            request.set_string(45, _bytes(self._extension('extension_8a29b', io)))
        if self._flag(18, io):
            request.set_string(51, _bytes(self._extension('identity_3fb10', io)))
        sdk = self.sdk_contexts.get(self.owner)
        if self._flag(1, io):
            self.populate_base(request, sdk, io=io)
        (self.extras if io is None else io.extras).populate(request, self.settings, settings_dependencies=self.settings_dependencies if io is None else io.settings_dependencies)
        return request
