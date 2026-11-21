import hashlib
import json
from pathlib import Path

from .errors import InputError
from .primary_logger import _String, _Tree
from .primary_vm import PrimaryProgramLimit
from .primary_worker_loop import _ensure_logger, _invoke


_KEYS = (b'LightAppSvc.mini_app_userapp.GetDropdownAppList', b'OidbSvcTrpcTcp.0xfd4_1')
_COMMANDS_SHA256 = 'a75d1d66712c7c16989f807350b03c322fd48a003a29bd366002db86c737990e'
_SOURCE_FEATURE = object()


def install_image(memory, image_base):
    memory.map(image_base + 0x677C238, bytearray(28),
               name='fixed command classifier PE zero fill', initialized=True)


def _large_commands():
    raw = (Path(__file__).with_name('data') / 'primary_sign_qq52230' / 'caller-commands.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _COMMANDS_SHA256:
        raise InputError('fixed command classifier asset identity mismatch')
    return frozenset(value.encode('ascii') for value in json.loads(raw)['commands'])


def _insert(runtime, owner, key, feature):
    memory, tree = runtime.memory, _Tree(runtime, owner)
    parent, slot = owner + 8, owner + 8
    node = memory.load(slot, 8)
    for _ in range(4096):
        if not node:
            node = runtime._operator_new(64)
            key.clone().write_to(node + 32)
            memory.store(node + 56, feature, 4, source='command_classifier.feature_id')
            memory.write(node, bytes(16), source='command_classifier.children')
            memory.store(node + 16, parent, 8, source='command_classifier.parent')
            memory.store(slot, node, 8, source='command_classifier.link')
            begin = memory.load(owner, 8)
            left = memory.load(begin, 8)
            if left:
                memory.store(owner, left, 8, source='command_classifier.begin')
            tree.balance(memory.load(owner + 8, 8), node)
            memory.store(owner + 16, memory.load(owner + 16, 8) + 1, 8,
                         source='command_classifier.count')
            return node
        present = _String.read(runtime, node + 32).value()
        value = key.value()
        if value == present:
            return node
        parent, slot = node, node + (0 if value < present else 8)
        node = memory.load(slot, 8)
    raise PrimaryProgramLimit('command classifier insertion exceeds its bounded traversal')


def _initialize(runtime):
    memory, base = runtime.memory, runtime.image_base
    guard, owner = base + 0x677C250, base + 0x677C238
    value = memory.load(guard, 4)
    if value & 1:
        return
    memory.store(guard, value | 1, 4, source='1BF6885.command_classifier_guard')
    keys = tuple(_String.construct(runtime, key) for key in _KEYS)
    memory.write(owner + 8, bytes(16), source='1BF6B7A.command_root_count')
    memory.store(owner, owner + 8, 8, source='1BF6B8F.command_begin')
    for key in keys:
        _insert(runtime, owner, key, 24)
    for key in reversed(keys):
        key.destroy()
    _invoke(runtime, 0x3E680B4, base + 0x1BF6D80)


def _find(runtime, command):
    memory = runtime.memory
    node = memory.load(runtime.image_base + 0x677C240, 8)
    for _ in range(4096):
        if not node:
            return None
        present = _String.read(runtime, node + 32).value()
        if command == present:
            return memory.load(node + 56, 4)
        node = memory.load(node + (0 if command < present else 8), 8)
    raise PrimaryProgramLimit('command classifier lookup exceeds its bounded traversal')


def classify(runtime, command, *, observed_feature=_SOURCE_FEATURE):
    if not isinstance(command, bytes):
        raise InputError('command classifier requires exact source command bytes')
    _initialize(runtime)
    feature = _find(runtime, command)
    if feature is None:
        if command not in _large_commands():
            return 2
        feature = 24
    if observed_feature is not _SOURCE_FEATURE:
        if observed_feature is not None and (type(observed_feature) is not int or
                                             not -(1 << 31) <= observed_feature < 1 << 31):
            raise InputError('configuration ID24 value must be signed32 or absent')
        runtime.events.append(('command_classification.feature_observation', feature, observed_feature))
        return observed_feature if observed_feature in (0, 1) else 2
    _ensure_logger(runtime)
    return _invoke(runtime, 0x1BE3F80, runtime.memory.load(runtime.image_base + 0x67516A8, 8), feature)


def destroy(runtime):
    memory, base = runtime.memory, runtime.image_base
    pending = [(memory.load(base + 0x677C240, 8), False)]
    seen = set()
    while pending:
        node, ready = pending.pop()
        if not node:
            continue
        if ready:
            _String.read(runtime, node + 32).destroy()
            runtime._free_allocation(node)
            continue
        if node in seen or len(seen) >= 4096:
            raise PrimaryProgramLimit('command classifier destructor exceeds its bounded tree')
        seen.add(node)
        pending.extend(((node, True), (memory.load(node + 8, 8), False), (memory.load(node, 8), False)))


def invoke(runtime, rva, arguments):
    if rva == 0x1BF6790:
        if len(arguments) != 1:
            raise InputError('command classifier takes one borrowed String24')
        return classify(runtime, _String.read(runtime, arguments[0]).value())
    if rva == 0x1BF6D80:
        if arguments:
            raise InputError('command classifier destructor takes no arguments')
        return destroy(runtime)
    raise InputError('unknown command classifier entry')
