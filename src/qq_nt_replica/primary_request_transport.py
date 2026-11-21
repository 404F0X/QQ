from dataclasses import dataclass
import hashlib

from .errors import InputError
from .primary_logger import _String, _Tree, feature
from .primary_vm import PrimaryProgramLimit, PrimarySemanticUnavailable
from .primary_worker_consumer import _invoke, _logger, _zero_string
from .primary_worker_response import _assign, _frame


_U64 = (1 << 64) - 1
_COMMANDS = (b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess',
             b'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey',
             b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access',
             b'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish')


@dataclass(frozen=True)
class RequestTransportBinding:
    type_address: int
    send_address: int
    type_callback: object
    send_callback: object
    alternate_send_address: int | None = None
    alternate_send_callback: object = None

    def __post_init__(self):
        if (any(type(value) is not int or not 0 < value <= _U64 for value in (self.type_address, self.send_address)) or
                not callable(self.type_callback) or not callable(self.send_callback)):
            raise InputError('request transport requires actual virtual targets and explicit callbacks')
        if self.alternate_send_address is not None or self.alternate_send_callback is not None:
            if (type(self.alternate_send_address) is not int or not 0 < self.alternate_send_address <= _U64 or
                    not callable(self.alternate_send_callback)):
                raise InputError('alternate transport send requires its actual virtual target and callback together')

    def type(self, receiver):
        value = self.type_callback(receiver)
        if type(value) is not int or not 0 <= value <= _U64:
            raise InputError('request transport type result must be unsigned64')
        return value & 0xFFFFFFFF

    def send(self, runtime, receiver, command, pointer, count, sequence):
        value = _String.read(runtime, command)
        result = self.send_callback(receiver, value.value(), runtime.memory.read(pointer, count), sequence)
        value.destroy()
        runtime.events.append(('request.transport_send_return', result))

    def send_alternate(self, runtime, receiver, command, pointer, count, sequence):
        if self.alternate_send_callback is None:
            raise PrimarySemanticUnavailable('alternate transport send callback is not bound')
        value = _String.read(runtime, command)
        result = self.alternate_send_callback(receiver, value.value(), runtime.memory.read(pointer, count), sequence)
        value.destroy()
        runtime.events.append(('request.transport_alternate_send_return', result))


def install_image(memory, base):
    from .primary_request_audit import install_image as install_audit
    install_audit(memory, base)
    from .primary_module_callback import install_image as install_module_callback
    install_module_callback(memory, base)
    memory.map(base + 0x677D160, bytearray(104), name='request transport PE zero fill', initialized=True)
    values = (base + rva for rva in (0x1CF40E0, 0x1CF4110, 0x63EC0, 0x1FE0))
    memory.map(base + 0x414B4C8, bytearray(b''.join(value.to_bytes(8, 'little') for value in values)),
               name='fixed request shared record vtable', initialized=True)


def initialize_commands(runtime):
    for index, command in enumerate(_COMMANDS):
        destination = runtime.image_base + 0x677D160 + 24 * index
        _String.construct(runtime, command).write_to(destination)
    runtime.events.append(('request.command_initialization',))


def _critical(runtime, pointer, enter):
    if pointer not in runtime.locks:
        raise PrimarySemanticUnavailable('request transport requires its initialized critical section')
    if not enter and runtime.locks[pointer] == 0:
        raise PrimaryProgramLimit('request transport cannot release an unowned critical section')
    runtime.locks[pointer] += 1 if enter else -1
    runtime.events.append(('EnterCriticalSection' if enter else 'LeaveCriticalSection', pointer))
    return 0


class _Map(_Tree):
    def __init__(self, runtime, address, strings=False):
        super().__init__(runtime, address)
        self.strings = strings

    def key(self, node):
        if self.strings:
            return _String.read(self.runtime, node + 32).value()
        value = self.load(node, 32)
        return value - (1 << 64) if value >> 63 else value

    def find(self, key):
        node = self.load(self.address, 8)
        for _ in range(4096):
            if not node or self.key(node) == key:
                return node
            node = self.load(node, 8 if self.key(node) < key else 0)
        raise PrimaryProgramLimit('request pending tree traversal exceeds its bound')

    def insert_node(self, key, node):
        parent = slot = self.address + 8
        current = self.load(slot)
        for _ in range(4096):
            if not current:
                self.memory.write(node, bytes(16), source='request.tree_children')
                self.store(node, 16, parent)
                self.store(slot, 0, node)
                begin = self.load(self.address)
                if self.load(begin):
                    self.store(self.address, 0, self.load(begin))
                self.balance(self.load(self.address, 8), node)
                self.store(self.address, 16, self.load(self.address, 16) + 1)
                return node
            if self.key(current) == key:
                return current
            parent, slot = current, current + (8 if self.key(current) < key else 0)
            current = self.load(slot)
        raise PrimaryProgramLimit('request pending insertion exceeds its bound')

    def black(self, node):
        return not node or bool(self.load(node, 24, 1))

    def transplant(self, old, new):
        parent = self.load(old, 16)
        self.store(parent, 0 if self.load(parent) == old else 8, new)
        if new:
            self.store(new, 16, parent)

    def erase(self, node):
        removed, black = node, self.black(node)
        left, right = self.load(node), self.load(node, 8)
        if not left:
            child, parent = right, self.load(node, 16)
            self.transplant(node, right)
        elif not right:
            child, parent = left, self.load(node, 16)
            self.transplant(node, left)
        else:
            removed = right
            for _ in range(4096):
                if not self.load(removed):
                    break
                removed = self.load(removed)
            else:
                raise PrimaryProgramLimit('request successor traversal exceeds its bound')
            black, child = self.black(removed), self.load(removed, 8)
            parent = self.load(removed, 16)
            if parent == node:
                parent = removed
            else:
                self.transplant(removed, child)
                self.store(removed, 8, right)
                self.store(right, 16, removed)
            self.transplant(node, removed)
            self.store(removed, 0, left)
            self.store(left, 16, removed)
            self.store(removed, 24, int(self.black(node)), 1)
        if black:
            for _ in range(4096):
                if child == self.load(self.address, 8) or not self.black(child):
                    break
                side = 0 if child == self.load(parent) else 8
                other = 8 - side
                sibling = self.load(parent, other)
                if not sibling:
                    raise InputError('request pending tree has an invalid black height')
                if not self.black(sibling):
                    self.store(sibling, 24, 1, 1)
                    self.store(parent, 24, 0, 1)
                    self.rotate(parent, side == 0)
                    sibling = self.load(parent, other)
                if self.black(self.load(sibling)) and self.black(self.load(sibling, 8)):
                    self.store(sibling, 24, 0, 1)
                    child, parent = parent, self.load(parent, 16)
                else:
                    if self.black(self.load(sibling, other)):
                        self.store(self.load(sibling, side), 24, 1, 1)
                        self.store(sibling, 24, 0, 1)
                        self.rotate(sibling, side != 0)
                        sibling = self.load(parent, other)
                    self.store(sibling, 24, int(self.black(parent)), 1)
                    self.store(parent, 24, 1, 1)
                    self.store(self.load(sibling, other), 24, 1, 1)
                    self.rotate(parent, side == 0)
                    child = self.load(self.address, 8)
                    break
            else:
                raise PrimaryProgramLimit('request pending deletion exceeds its bound')
            if child:
                self.store(child, 24, 1, 1)
        first = self.load(self.address, 8)
        if first:
            for _ in range(4096):
                if not self.load(first):
                    break
                first = self.load(first)
            else:
                raise PrimaryProgramLimit('request minimum traversal exceeds its bound')
        self.store(self.address, 0, first or self.address + 8)
        self.store(self.address, 16, self.load(self.address, 16) - 1)


def _destroy_function(runtime, function):
    memory, base = runtime.memory, runtime.image_base
    active = memory.load(function + 24, 8)
    if not active:
        return
    inline = active == function
    target = memory.load(memory.load(active, 8) + (24 if inline else 32), 8)
    if memory.load(active, 8) in (base + 0x436EC18, base + 0x414ABD8, base + 0x414BB08) and target == base + (0x28F0 if inline else 0x1FE0):
        _invoke(runtime, target - base, active)
        return
    if memory.load(active, 8) == base + 0x433C478 and target == base + (0xB95880 if inline else 0xBED000):
        _invoke(runtime, target - base, active)
        return
    if target in (base + 0x1BF4450, base + 0x1BF4490, base + 0x1D02990, base + 0x1D029A0):
        _invoke(runtime, target - base, active)
        return
    if target != base + (0xBDC9F0 if inline else 0xBDCA00):
        raise PrimarySemanticUnavailable('request completion callback destructor is not bound')
    _String.read(runtime, active + 16).destroy()
    if not inline:
        runtime._free_allocation(active)


def release_record(runtime, record):
    memory, base = runtime.memory, runtime.image_base
    previous = memory.load(record + 8, 4)
    memory.store(record + 8, (previous - 1) & 0xFFFFFFFF, 4, source='request.record_owner_release')
    if previous:
        return
    if memory.load(record, 8) != base + 0x414B4C8:
        raise PrimarySemanticUnavailable('request shared record destructor vtable is not bound')
    _destroy_function(runtime, record + 144)
    for offset in (96, 72, 48, 24):
        _String.read(runtime, record + offset).destroy()
    _invoke(runtime, 0x75AD90, record)


def _clone_function(runtime, source, destination):
    active = runtime.memory.load(source + 32, 8)
    if not active:
        return
    if runtime.memory.load(active, 8) in (runtime.image_base + 0x436EC18, runtime.image_base + 0x414ABD8, runtime.image_base + 0x414BB08) and active == source + 8:
        memory, base = runtime.memory, runtime.image_base
        if memory.load(destination + 24, 8):
            raise PrimarySemanticUnavailable('High inline handoff requires its newly constructed empty record')
        clone = memory.load(memory.load(active, 8) + 8, 8)
        expected = {base + 0x436EC18: 0x2DF1450, base + 0x414ABD8: 0x1C513C0, base + 0x414BB08: 0x1D27500}
        if clone != base + expected[memory.load(active, 8)]:
            raise PrimarySemanticUnavailable('High inline handoff clone target differs from source')
        temporary, _ = _frame(runtime, 32, '1CE7B91.High_inline_function_temporary')
        memory.store(temporary + 24, temporary, 8, source='1CE7B91.inline_temporary_owner')
        _invoke(runtime, clone - base, active, temporary)
        _invoke(runtime, memory.load(memory.load(temporary, 8) + 8, 8) - base, temporary, destination)
        _invoke(runtime, memory.load(memory.load(temporary, 8) + 24, 8) - base, temporary)
        memory.store(temporary + 24, memory.load(destination + 24, 8), 8, source='BED8CF.inline_temporary_previous_owner')
        memory.store(destination + 24, destination, 8, source='BED952.inline_record_owner')
        memory.unmap(temporary)
        return
    target = runtime.memory.load(runtime.memory.load(active, 8) + 16, 8)
    if runtime.memory.load(active, 8) == runtime.image_base + 0x414BB08 and target == runtime.image_base + 0x1D27510:
        copied = _invoke(runtime, 0x1D27510, active)
        runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')
        return
    if runtime.memory.load(active, 8) == runtime.image_base + 0x436EC18 and target == runtime.image_base + 0x2DF1470:
        copied = _invoke(runtime, 0x2DF1470, active)
        runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')
        return
    if runtime.memory.load(active, 8) == runtime.image_base + 0x414ABD8 and target == runtime.image_base + 0x1C513E0:
        copied = _invoke(runtime, 0x1C513E0, active)
        runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')
        return
    if runtime.memory.load(active, 8) == runtime.image_base + 0x433C478 and target == runtime.image_base + 0x2DE0BA0:
        copied = _invoke(runtime, 0x2DE0BA0, active)
        runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')
        return
    if target in (runtime.image_base + 0x1BF4390, runtime.image_base + 0x1D028D0):
        copied = _invoke(runtime, target - runtime.image_base, active)
        runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')
        return
    if target != runtime.image_base + 0xBDC970:
        raise PrimarySemanticUnavailable('configured request requires the actual callback clone target')
    copied = runtime._operator_new(48)
    runtime.memory.store(copied, runtime.memory.load(active, 8), 8, source='request.callback_vtable')
    runtime.memory.store(copied + 8, runtime.memory.load(active + 8, 8), 8, source='request.callback_device')
    _String.read(runtime, active + 16).clone().write_to(copied + 16)
    runtime.memory.store(copied + 40, runtime.memory.load(active + 40, 8), 8, source='request.callback_time')
    runtime.memory.store(destination + 24, copied, 8, source='request.callback_owner')


def duplicate(runtime, context, command, tag):
    saved_command, saved_tag = (_String.read(runtime, context + offset).value() for offset in (0, 24))
    if tag and saved_tag:
        return int(tag == saved_tag)
    return int(saved_command == command and saved_tag == tag)


def _cache_manager(runtime):
    memory, base = runtime.memory, runtime.image_base
    pointer = memory.load(base + 0x677D1C0, 8)
    if not pointer:
        pointer = runtime._operator_new(64)
        _invoke(runtime, 0x1CF35E0, pointer)
        memory.store(base + 0x677D1C0, pointer, 8, source='request.cache_manager_publish')
        runtime._request_cache_manager = pointer
    if pointer not in getattr(runtime, '_constructed_request_managers', ()) and pointer != getattr(runtime, '_request_cache_manager', None):
        raise PrimarySemanticUnavailable('request cache manager requires its actual constructed container state')
    return _Map(runtime, pointer + 40, True)


def _remember_digest(runtime, table, tag, digest):
    if not tag:
        return
    if table.load(table.address, 16) >= 101:
        node = table.load(table.address)
        table.erase(node)
        for offset in (32, 56):
            _String.read(runtime, node + offset).destroy()
        runtime._free_allocation(node)
    node = table.find(digest)
    if not node:
        node = runtime._operator_new(80)
        _String.construct(runtime, digest).write_to(node + 32)
        _zero_string(runtime).write_to(node + 56)
        table.insert_node(digest, node)
    value = _String.construct(runtime, tag)
    _assign(runtime, node + 56, value)
    value.destroy()


def dispatch(runtime, receiver, record, function, metadata, status, packet, frame, rbp):
    memory, base = runtime.memory, runtime.image_base
    binding = runtime.request_transport

    def transport_type():
        gate = _invoke(runtime, 0xBA21A0)
        transport = memory.load(gate + 8, 8)
        if not transport:
            return None
        target = memory.load(memory.load(transport, 8) + 16, 8)
        if binding is None or target != binding.type_address:
            raise PrimarySemanticUnavailable(f'encoded request requires current transport type callback {target:#x}')
        return binding.type(transport)

    first = transport_type()
    if first in (None, 0):
        a2 = bool(memory.load(receiver, 1) & 1)
    else:
        second = transport_type()
        if second is None:
            raise PrimarySemanticUnavailable('request transport disappeared before its second type call')
        a2 = second == 1
    command_address = base + 0x677D160 + 24 * (int(a2) * 2 + int(status == 0))
    command = _String.read(runtime, command_address).value()
    if not command:
        raise PrimarySemanticUnavailable('configured request requires initialized source service commands')
    _String.read(runtime, command_address).clone().write_to(record + 48)
    tag = _String.read(runtime, record + 24).value()
    cache = _cache_manager(runtime)
    if duplicate(runtime, metadata, command, tag):
        runtime.events.append(('request.duplicate_suppressed', command, tag))
        packet.destroy()
        release_record(runtime, record)
        return
    gate = _invoke(runtime, 0xBA21A0)
    _invoke(runtime, 0x75B070, gate + 56)
    _clone_function(runtime, function, record + 144)
    sequence = memory.load(receiver + 48, 8)
    memory.store(receiver + 48, (sequence + 1) & _U64, 8, source='request.sequence_advance')
    memory.store(record + 128, sequence, 8, source='request.sequence')
    memory.store(record + 176, _invoke(runtime, 0x3E8ED3C, 0), 8, source='request.created_at')
    node = runtime._operator_new(56)
    memory.store(node + 32, sequence, 8, source='request.pending_key')
    memory.store(node + 40, record + 24, 8, source='request.pending_value')
    memory.store(node + 48, record, 8, source='request.pending_control')
    memory.store(record + 8, memory.load(record + 8, 4) + 1, 4, source='request.pending_owner_add')
    signed = sequence - (1 << 64) if sequence >> 63 else sequence
    inserted = _Map(runtime, gate + 24).insert_node(signed, node)
    if inserted != node:
        release_record(runtime, record)
        runtime._free_allocation(node)
    pointer, count = memory.load(record + 120, 8), len(packet.value()) & 0xFFFFFFFF
    digest = hashlib.md5(memory.read(pointer, count)).digest()
    _remember_digest(runtime, cache, tag, digest)
    transport = memory.load(_invoke(runtime, 0xBA21A0) + 8, 8)
    target = memory.load(memory.load(transport, 8) + 8, 8)
    if binding is None or target != binding.send_address:
        raise PrimarySemanticUnavailable(f'configured request requires actual send callback {target:#x}')
    outgoing = _String.read(runtime, record + 48).clone()
    outgoing.write_to(rbp - 64)
    runtime.events.append(('request.pending_dispatch', sequence, record, command, digest))
    binding.send(runtime, transport, rbp - 64, pointer, count, sequence)
    _invoke(runtime, 0x75B0A0, gate + 56)
    packet.destroy()
    release_record(runtime, record)


def complete(runtime, receiver, command, pointer, count, success, sequence, error):
    _complete(runtime, receiver, command, pointer, count, success, sequence, error, consume_command=True)


def _complete(runtime, receiver, command, pointer, count, success, sequence, error, *, consume_command):
    from . import primary_request_audit as audit
    memory, base = runtime.memory, runtime.image_base
    frame, rbp = _frame(runtime, 0x348, '1CE9930.request_completion_frame')
    audit.begin(runtime)
    if feature(runtime, _logger(runtime), 43) == 1:
        memory.unmap(frame)
        return _complete_enhanced(runtime, receiver, command, pointer, count, success, sequence, error,
                                  consume_command=consume_command)
    event, columns = rbp - 32, rbp + 592
    audit.construct(runtime, event)
    gate = _invoke(runtime, 0xBA21A0)
    _invoke(runtime, 0x75B070, gate + 56)
    signed = sequence - (1 << 64) if sequence >> 63 else sequence
    table = _Map(runtime, gate + 24)
    node = table.find(signed)
    if not node or not memory.load(node + 40, 8):
        _invoke(runtime, 0x75B0A0, gate + 56)
        audit.destroy(runtime, event)
        if consume_command:
            _String.read(runtime, command).destroy()
        memory.unmap(frame)
        runtime.events.append(('request.completion_without_pending', sequence))
        return 'no_pending'
    record = memory.load(node + 48, 8)
    if memory.load(node + 40, 8) != record + 24:
        raise PrimarySemanticUnavailable('request completion requires the actual shared-record alias')
    memory.store(record + 8, memory.load(record + 8, 4) + 1, 4, source='request.completion_owner_add')
    selected = _String.read(runtime, record + 48).value()
    audit.annotate(runtime, event, _COMMANDS.index(selected) if selected in _COMMANDS else None,
                   _String.read(runtime, record + 24).value())
    wire, result = None, None
    empty_response = bool(success & 255) and not count & 0xFFFFFFFF
    if empty_response:
        result_pointer, result_count, business_success, business_error = pointer, 0, 1, 0
    elif success & 255:
        mode = int(selected in (_COMMANDS[0], _COMMANDS[2]))
        wire = _String.construct(runtime, memory.read(pointer, count & 0xFFFFFFFF))
        wire.write_to(rbp + 496)
        _zero_string(runtime).write_to(rbp + 392)
        _invoke(runtime, 0x1CD3CB0, rbp + 392, rbp + 496, mode, record + 72, rbp + 444)
        result = _String.read(runtime, rbp + 392)
        status = memory.load(rbp + 444, 4)
        result_pointer = result.get(16, 8) if result.get(0, 1) & 1 else rbp + 393
        result_count, business_success, business_error = len(result.value()), int(status == 0), status
        audit.submit(runtime, event, columns, status)
    else:
        result_pointer, result_count, business_success = pointer, count & 0xFFFFFFFF, 0
        transport_error = error & 0xFFFFFFFF
        business_error = (transport_error + 899) & 0xFFFFFFFF if transport_error else 999
    active = memory.load(record + 168, 8)
    target = memory.load(memory.load(active, 8) + 40, 8) if active else 0
    if target not in (base + 0xBDCA30, base + 0x1BF44D0, base + 0x2DF14A0, base + 0x2DE0C10, base + 0x1C51410) and not (
                memory.load(active, 8) == base + 0x414BB08 and target == base + 0x1D27530):
        raise PrimarySemanticUnavailable('request completion business callback is not bound')
    memory.store(rbp + 592, result_pointer, 8, source='request.business_pointer')
    memory.store(rbp + 416, result_count & 0xFFFFFFFF, 4, source='request.business_count')
    memory.store(rbp + 495, business_success, 1, source='request.business_success')
    memory.store(rbp + 520, business_error, 4, source='request.business_error')
    _invoke(runtime, target - base, active, rbp + 592, rbp + 416, rbp + 495, rbp + 520)
    table.erase(node)
    release_record(runtime, record)
    runtime._free_allocation(node)
    if empty_response:
        topic = _String.construct(runtime, b'-3001')
        _assign(runtime, event + 224, topic)
        topic.destroy()
        audit._owner(runtime, audit._response_image())
        for offset in (0, 24):
            _zero_string(runtime).write_to(columns + offset)
        runtime.events.append(('request.audit_submit', -3001, None, 0, 100))
        audit.consume(runtime, base + 0x67519B8, event, columns, 0, 100, 0)
        for offset in (0, 24):
            _String.read(runtime, columns + offset).destroy()
    if not success & 255:
        audit.submit(runtime, event, columns, -3000, error)
        audit.finish_failure(runtime)
    if result is not None:
        result.destroy()
        wire.destroy()
    release_record(runtime, record)
    _invoke(runtime, 0x75B0A0, gate + 56)
    audit.destroy(runtime, event)
    if consume_command:
        _String.read(runtime, command).destroy()
    memory.unmap(frame)
    runtime.events.append(('request.completion_consumed', sequence, record))
    return 'dispatched'


def _signed64(value):
    value &= _U64
    return value - (1 << 64) if value >> 63 else value


def _timed_admitted(runtime, receiver, command):
    memory = runtime.memory
    _invoke(runtime, 0x75B070, receiver + 56)
    try:
        table = _Map(runtime, receiver + 96, True)
        node = table.find(_String.read(runtime, command).value())
        if not node:
            return 1
        frame, _ = _frame(runtime, 8, '1CE6355.timed_clock')
        try:
            _invoke(runtime, 0x759B30, frame)
            elapsed = _signed64(memory.load(frame, 8) - memory.load(node + 56, 8))
            duration = _signed64(memory.load(node + 64, 8) * 1000000000)
        finally:
            memory.unmap(frame)
        if elapsed < duration:
            return 0
        table.erase(node)
        _String.read(runtime, node + 32).destroy()
        runtime._free_allocation(node)
        return 1
    finally:
        _invoke(runtime, 0x75B0A0, receiver + 56)


def _store_timed(runtime, receiver, command, seconds):
    memory = runtime.memory
    _invoke(runtime, 0x75B070, receiver + 56)
    try:
        key = _String.read(runtime, command).value()
        table = _Map(runtime, receiver + 96, True)
        node = table.find(key)
        if not node:
            node = runtime._operator_new(72)
            _String.construct(runtime, key).write_to(node + 32)
            table.insert_node(key, node)
        frame, _ = _frame(runtime, 8, '1CF0858.timed_clock')
        try:
            _invoke(runtime, 0x759B30, frame)
            memory.store(node + 56, memory.load(frame, 8), 8, source='1CF0865.timed_created_at')
            memory.store(node + 64, seconds & _U64, 8, source='1CF086C.timed_seconds')
        finally:
            memory.unmap(frame)
    finally:
        _invoke(runtime, 0x75B0A0, receiver + 56)


def _enhanced_duplicate(runtime, metadata, command, tag):
    if _String.read(runtime, metadata).value() == b'trpc.o3.report.Report.SsoReport':
        return 1
    return duplicate(runtime, metadata, _String.read(runtime, command).value(), _String.read(runtime, tag).value())


def _enhanced_record(runtime, receiver, command, body, mode):
    memory, base = runtime.memory, runtime.image_base
    record = runtime._operator_new(0xB8)
    memory.store(record, base + 0x414B4C8, 8, source='1CE4F3F.request_record_vtable')
    memory.store(record + 8, 0, 4, source='1CE4F2A.request_owner_count')
    memory.store(record + 16, 0, 4, source='1CE4F31.request_weak_count')
    memory.write(record + 24, bytes(160), source='1CE4F49.request_record_fields')
    _String.read(runtime, command).clone().write_to(record + 24)
    if not mode & 255:
        _String.read(runtime, command).clone().write_to(record + 48)
        _String.read(runtime, body).clone().write_to(record + 96)
        return record
    frame, rbp = _frame(runtime, 0x130, '1CE4EF0.request_producer_frame')
    packet = None
    try:
        _invoke(runtime, 0x1CC6E10, rbp - 56, body, command, rbp - 64, record + 72, rbp - 60)
        packet = _String.read(runtime, rbp - 56)
        status, error = memory.load(rbp - 64, 4), memory.load(rbp - 60, 4)
        if error or status not in (0, 1):
            release_record(runtime, record)
            return 0

        def transport_type():
            gate = _invoke(runtime, 0xBA21A0)
            transport = memory.load(gate + 8, 8)
            if not transport:
                return None
            target = memory.load(memory.load(transport, 8) + 16, 8)
            binding = runtime.request_transport
            if binding is None or target != binding.type_address:
                raise PrimarySemanticUnavailable('enhanced request requires its bound transport type callback')
            return binding.type(transport)

        first = transport_type()
        if first in (None, 0):
            a2 = bool(memory.load(receiver, 1) & 1)
        else:
            second = transport_type()
            if second is None:
                raise PrimarySemanticUnavailable('enhanced transport disappeared before its second type call')
            a2 = second == 1
        selected = base + 0x677D160 + 24 * (int(a2) * 2 + int(status == 0))
        _String.read(runtime, selected).clone().write_to(record + 48)
        packet.clone().write_to(record + 96)
        return record
    finally:
        if packet is not None:
            packet.destroy()
        memory.unmap(frame)


def _register_enhanced(runtime, receiver, record, function):
    memory = runtime.memory
    if not memory.load(function + 32, 8):
        return
    _invoke(runtime, 0x75B070, receiver + 56)
    try:
        _clone_function(runtime, function, record + 144)
        sequence = (memory.load(receiver + 48, 8) + 1) & _U64
        memory.store(receiver + 48, sequence, 8, source='1CE610D.enhanced_sequence_advance')
        memory.store(record + 128, sequence, 8, source='1CE6118.enhanced_sequence')
        memory.store(record + 176, _invoke(runtime, 0x3E8ED3C, 0), 8, source='1CE612A.enhanced_created_at')
        node = runtime._operator_new(56)
        memory.store(node + 32, sequence, 8, source='request.pending_key')
        memory.store(node + 40, record + 24, 8, source='request.pending_value')
        memory.store(node + 48, record, 8, source='request.pending_control')
        memory.store(record + 8, memory.load(record + 8, 4) + 1, 4, source='request.pending_owner_add')
        if _Map(runtime, receiver + 24).insert_node(_signed64(sequence), node) != node:
            release_record(runtime, record)
            runtime._free_allocation(node)
    finally:
        _invoke(runtime, 0x75B0A0, receiver + 56)


def _business_callback(runtime, active, pointer, count, success, error):
    if not active:
        return
    memory, base = runtime.memory, runtime.image_base
    target = memory.load(memory.load(active, 8) + 40, 8)
    if target not in (base + 0xBDCA30, base + 0x1BF44D0, base + 0x2DF14A0, base + 0x2DE0C10, base + 0x1C51410):
        raise PrimarySemanticUnavailable('enhanced request business callback is not bound')
    frame, rbp = _frame(runtime, 64, 'enhanced.request_business_arguments')
    try:
        memory.store(frame, pointer, 8, source='request.business_pointer')
        memory.store(frame + 8, count & 0xFFFFFFFF, 4, source='request.business_count')
        memory.store(frame + 12, success & 255, 1, source='request.business_success')
        memory.store(frame + 16, error & 0xFFFFFFFF, 4, source='request.business_error')
        _invoke(runtime, target - base, active, frame, frame + 8, frame + 12, frame + 16)
    finally:
        memory.unmap(frame)


def send_enhanced(runtime, receiver, command, body, function, metadata, mode):
    memory = runtime.memory
    record = 0
    frame, _ = _frame(runtime, 48, '1CE3390.enhanced_send_arguments')
    try:
        error = 907 if not memory.load(receiver + 8, 8) else 0
        if not error and not _timed_admitted(runtime, receiver, command):
            error = 1999
        if not error:
            record = _enhanced_record(runtime, receiver, command, body, mode)
            if not record:
                error = 4
        if record:
            _cache_manager(runtime)
            if _enhanced_duplicate(runtime, metadata, record + 48, record + 24):
                runtime.events.append(('request.enhanced_duplicate_suppressed',))
                return
        if error:
            _zero_string(runtime).write_to(frame)
            _business_callback(runtime, memory.load(function + 32, 8), frame + 1, 0, 0, error)
            return
        registration, _ = _frame(runtime, 40, '1CE4CDC.registration_callback_copy')
        memory.write(registration, bytes(40), source='1CE4CDC.registration_callback_empty')
        try:
            _clone_function(runtime, function, registration + 8)
            _register_enhanced(runtime, receiver, record, registration)
        finally:
            _destroy_function(runtime, registration + 8)
            memory.unmap(registration)
        transport = memory.load(receiver + 8, 8)
        target = memory.load(memory.load(transport, 8) + 8, 8)
        binding = runtime.request_transport
        if binding is None or target != binding.send_address:
            raise PrimarySemanticUnavailable('enhanced request requires its actual bound transport send callback')
        packet = _String.read(runtime, record + 96)
        pointer = packet.get(16, 8) if packet.get(0, 1) & 1 else record + 97
        _String.read(runtime, record + 48).clone().write_to(frame)
        sequence = memory.load(record + 128, 8)
        runtime.events.append(('request.enhanced_pending_dispatch', sequence, record))
        binding.send(runtime, transport, frame, pointer, len(packet.value()) & 0xFFFFFFFF, sequence)
    finally:
        if record:
            release_record(runtime, record)
        _destroy_function(runtime, function + 8)
        memory.unmap(frame)


def _erase_enhanced(runtime, receiver, sequence):
    memory = runtime.memory
    _invoke(runtime, 0x75B070, receiver + 56)
    try:
        table = _Map(runtime, receiver + 24)
        node = table.find(_signed64(sequence))
        if node:
            record = memory.load(node + 48, 8)
            table.erase(node)
            release_record(runtime, record)
            runtime._free_allocation(node)
    finally:
        _invoke(runtime, 0x75B0A0, receiver + 56)


def _enhanced_audit_state(runtime, failed):
    from . import primary_request_audit as audit
    from contextlib import nullcontext
    claim = _enhanced_audit_claim(runtime, failed)
    with claim if claim is not None else nullcontext():
        if failed:
            audit.finish_failure(runtime)
        for rva in (0x1BF75A0, 0x1BF8090):
            with claim.step(rva) if claim is not None else nullcontext():
                _invoke(runtime, rva, int(failed), 9, 1, 1)


def _enhanced_audit_claim(runtime, failed):
    if getattr(runtime, 'primary_backend', 'reference') != 'direct':
        return None
    import sys
    from .primary_request_audit_scope import _FACTORY, _RequestAuditClaim
    from .primary_signer import PrimarySigner

    class Claim(_RequestAuditClaim):
        _arguments = (int(failed), 9, 1, 1)

        def valid(self):
            from threading import get_ident
            frame = sys._getframe(1)
            while frame is not None and frame is not self.source:
                frame = frame.f_back
            source, completion, public = self.source, self.completion, self.public
            current = public.f_locals if public is not None else {}
            pending = completion.f_locals if completion is not None else {}
            scope, runtime = self.scope, self.runtime
            return (self.active and get_ident() == self.thread and frame is source and
                source.f_code is _enhanced_audit_state.__code__ and source.f_locals.get('runtime') is runtime and
                source.f_locals.get('failed') is failed and source.f_back is completion and
                completion.f_code is _complete_enhanced.__code__ and
                public.f_code is PrimarySigner.complete_request.__code__ and
                current.get('self') is self.owner.signer and current.get('runtime') is runtime and
                current.get('command_address') == pending.get('command') and
                current.get('pointer') == pending.get('pointer') and
                len(current.get('response', b'')) == pending.get('count') and
                all(current.get(key) == pending.get(key) for key in ('success', 'sequence', 'error')) and
                pending.get('runtime') is runtime and pending.get('consume_command') is False and
                pending.get('receiver') == runtime.image_base + 0x6751AB8 and
                runtime.memory.load(runtime.image_base + 0x6751B30, 4) & 1 and
                bool(pending.get('success', 0) & 255) is not failed and
                self._arguments == (int(failed), 9, 1, 1) and scope.public_owner is self.owner and
                scope._request_audit is self and scope._valid_public() and self.owner.serial == self.serial and
                runtime.__dict__.get('_primary_direct_scope') is scope and runtime._active_main is None and
                runtime._main_generation == self.generation and not runtime._active_failed)

        def __enter__(self):
            self.scope._request_audit = self
            try:
                self.require()
            except BaseException:
                self.scope._request_audit = None
                self.active = False
                self.source = self.completion = self.public = None
                raise
            return self

        def __exit__(self, kind, value, traceback):
            try:
                if kind is None:
                    self.require()
                    if self.stage != 'complete' or not self.status_completed:
                        raise PrimarySemanticUnavailable('enhanced audit pair did not complete its ordered source update')
                    self.scope.report['enhancedRequestAudit'] = dict(completed=True, failed=failed,
                        publicSerial=self.serial, materialInitialized=self.material_used)
            finally:
                self.active = False
                self.source = self.completion = self.public = None
                if self.scope._request_audit is self:
                    self.scope._request_audit = None
                elif kind is None:
                    raise PrimarySemanticUnavailable('enhanced audit claim ownership changed before exit')

    scope = runtime.__dict__.get('_primary_direct_scope')
    source = sys._getframe(1)
    frame, public = source, None
    while frame is not None:
        if frame.f_code is PrimarySigner.complete_request.__code__:
            public = frame
            break
        frame = frame.f_back
    if (scope is None or not scope._valid_public() or source.f_code is not _enhanced_audit_state.__code__ or
            source.f_back.f_code is not _complete_enhanced.__code__ or public is None or
            scope._request_audit is not None or scope._caller is not None or scope._status_host is not None or
            scope._audit is not None or runtime._program_calls):
        raise PrimarySemanticUnavailable('enhanced audit requires its actual public completion source')
    return Claim(scope, source, source.f_back, public, _FACTORY)


def _complete_enhanced(runtime, receiver, command, pointer, count, success, sequence, error, *, consume_command):
    from . import primary_request_audit as audit
    memory, base = runtime.memory, runtime.image_base
    if receiver != _invoke(runtime, 0xBA21A0):
        raise PrimarySemanticUnavailable('enhanced completion requires the constructed SDK receiver gate')
    frame, rbp = _frame(runtime, 0x348, '1CE82B0.enhanced_completion_frame')
    event, columns = rbp - 32, rbp + 592
    record, wire, result = 0, None, None
    audit.construct(runtime, event)
    try:
        _invoke(runtime, 0x75B070, receiver + 56)
        try:
            node = _Map(runtime, receiver + 24).find(_signed64(sequence))
            if node:
                alias, record = memory.load(node + 40, 8), memory.load(node + 48, 8)
                if record:
                    if alias and alias != record + 24:
                        raise PrimarySemanticUnavailable('enhanced completion requires its shared-record alias')
                    memory.store(record + 8, memory.load(record + 8, 4) + 1, 4, source='request.completion_owner_add')
                if not alias:
                    return 'no_pending'
        finally:
            _invoke(runtime, 0x75B0A0, receiver + 56)
        if not record or not memory.load(record + 168, 8):
            runtime.events.append(('request.completion_without_pending', sequence))
            return 'no_pending'
        selected = _String.read(runtime, record + 48).value()
        audit.annotate(runtime, event, _COMMANDS.index(selected) if selected in _COMMANDS else None,
                       _String.read(runtime, record + 24).value())
        empty_response = bool(success & 255) and not count & 0xFFFFFFFF
        if success & 255:
            _enhanced_audit_state(runtime, False)
        if empty_response:
            result_pointer, result_count, business_success, business_error = pointer, 0, 1, 0
        elif success & 255:
            wire = _String.construct(runtime, memory.read(pointer, count & 0xFFFFFFFF))
            wire.write_to(rbp + 496)
            memory.store(rbp + 448, 0, 8, source='enhanced.response_extra_initial')
            _invoke(runtime, 0x1CD3CB0, rbp + 392, rbp + 496,
                    int(selected in (_COMMANDS[0], _COMMANDS[2])), record + 72, rbp + 444, rbp + 448)
            result = _String.read(runtime, rbp + 392)
            status, seconds = memory.load(rbp + 444, 4), memory.load(rbp + 448, 8)
            business_success, business_error = int(status == 0), status
            if seconds:
                business_success, business_error = 0, 1999
                _store_timed(runtime, receiver, record + 24, seconds)
            result_pointer = result.get(16, 8) if result.get(0, 1) & 1 else rbp + 393
            result_count = len(result.value())
        else:
            result_pointer, result_count, business_success = pointer, count & 0xFFFFFFFF, 0
            transport_error = error & 0xFFFFFFFF
            business_error = (transport_error + 899) & 0xFFFFFFFF if transport_error else 999
        _business_callback(runtime, memory.load(record + 168, 8), result_pointer, result_count,
                           business_success, business_error)
        _erase_enhanced(runtime, receiver, sequence)
        if not success & 255:
            audit.submit(runtime, event, columns, -3000, error)
            _enhanced_audit_state(runtime, True)
        elif not empty_response:
            audit.submit(runtime, event, columns, status)
        runtime.events.append(('request.completion_consumed', sequence, record))
        return 'dispatched'
    finally:
        if result is not None:
            result.destroy()
        if wire is not None:
            wire.destroy()
        if record:
            release_record(runtime, record)
        audit.destroy(runtime, event)
        if consume_command:
            _String.read(runtime, command).destroy()
        memory.unmap(frame)


def invoke(runtime, rva, values):
    if rva == 0x1CE3390 and len(values) == 6:
        return send_enhanced(runtime, *values)
    if rva == 0x1CE82B0 and len(values) == 7:
        return _complete_enhanced(runtime, *values, consume_command=True)
    if rva == 0x1CE4EF0 and len(values) == 5:
        receiver, output, command, body, mode = values
        record = _enhanced_record(runtime, receiver, command, body, mode)
        runtime.memory.store(output, record + 24 if record else 0, 8, source='1CE574A.request_value')
        runtime.memory.store(output + 8, record, 8, source='1CE5751.request_control')
        return output
    if rva == 0x1CE6300 and len(values) == 2:
        return _timed_admitted(runtime, *values)
    if rva == 0x1CE6850 and len(values) == 4:
        return _enhanced_duplicate(runtime, *values[1:])
    if rva in (0x75B070, 0x75B0A0) and len(values) == 1:
        return _critical(runtime, values[0], rva == 0x75B070)
    if rva == 0x1CE9930 and len(values) == 7:
        return complete(runtime, *values)
    if rva == 0x1CF2D00 and len(values) == 3:
        context, command, tag = values
        return duplicate(runtime, context, _String.read(runtime, command).value(), _String.read(runtime, tag).value())
    if rva == 0x1CF4110 and len(values) == 1:
        record = values[0]
        _destroy_function(runtime, record + 144)
        for offset in (96, 72, 48, 24):
            _String.read(runtime, record + offset).destroy()
        return None
    raise InputError('unsupported request transport entry or argument count')
