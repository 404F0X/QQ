from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path

from .errors import InputError


_MASK64 = 0xFFFFFFFFFFFFFFFF
_MASK32 = 0xFFFFFFFF
_DEVICE_SEED = (0x4537CEBB9AB78D26, 0x9EACDDC54FA81D98, 0xF75C03B05AAC6550, 0xD91690459973F0ED)
_CHECKPOINT_KEY = bytes.fromhex("a842fc943cf76cb9c97d644113b70fa94890474e98efd2c58670bb71147b8df5")
_PROFILE_KEY = bytes.fromhex("9d49fc392a613758c090bb5590b615945a27dc4122798a23fb6944bd71da70f7")
_OBJECT_PREFIXES = ("PCI#", "SCSI", "HDAUDIO", "SWD#SGDEVAPI", "USB4#ROOT_DEVICE_ROUTER",
                    "INTELAUDIO", "USB#ROOT_HUB30")


@dataclass(frozen=True)
class DisplayObservation:
    device_id: str
    state_flags: int


@dataclass(frozen=True)
class DeviceObservations:
    cpuid: dict
    system_information_status: int
    system_information: bytes | None
    volume_serial: int | None
    uuid_status: int
    uuid_bytes: bytes | None
    object_names: tuple[str, ...] | None
    displays: tuple[DisplayObservation, ...]
    injected_material: bytes | None = None
    object_directory_digest: int | None = None
    display_digest: int | None = None
    uuid_tail: bytes | None = None
    system_information_material: bytes | None = None


@dataclass(frozen=True)
class RegistryValueObservation:
    open_status: int
    query_status: int | None
    value_type: int
    data: bytes
    returned_size: int


@dataclass(frozen=True)
class CapiObservation:
    public_key_bits: bytes | None
    error_code: int
    last_error: int = 0


@dataclass(frozen=True)
class DeviceEnvironmentObservations:
    hypervisor_vendor: bytes
    microsoft_service_present: bool
    microsoft_vm_id_present: bool
    storage_descriptor: bytes | None
    machine_values: tuple[RegistryValueObservation | None, ...]
    virtual_disk_present: bool


def device_environment_classification(observations):
    if not isinstance(observations, DeviceEnvironmentObservations):
        raise InputError("device environment classification needs structured source observations")
    vendor = observations.hypervisor_vendor
    if not isinstance(vendor, bytes) or len(vendor) != 12:
        raise InputError("hypervisor CPUID vendor must contain exactly twelve source bytes")
    if any(type(value) is not bool for value in (observations.microsoft_service_present,
                                                observations.microsoft_vm_id_present,
                                                observations.virtual_disk_present)):
        raise InputError("device environment existence observations must be explicit booleans")
    if vendor == b"Microsoft Hv" and not observations.microsoft_service_present and observations.microsoft_vm_id_present:
        return 4
    if vendor == b"VMwareVMware":
        return 2
    if vendor == b"VBoxVBoxVBox":
        return 3
    if vendor[:8] == b"KVMKVMKV":
        return 5
    descriptor = observations.storage_descriptor
    if descriptor is not None:
        if not isinstance(descriptor, bytes) or len(descriptor) < 40:
            raise InputError("successful storage descriptor observation needs at least forty bytes")
        offset = int.from_bytes(descriptor[16:20], "little")
        if offset >= len(descriptor) or b"\0" not in descriptor[offset:]:
            raise InputError("storage descriptor vendor must be an in-bounds terminated source string")
        vendor_string = descriptor[offset:].split(b"\0", 1)[0]
        if b"virtio" in vendor_string.lower():
            return 5
    if vendor == b"XenVMMXenVMM":
        return 6
    if vendor == b"Parallels Hv" or vendor[:8] == b"prl hype":
        return 7
    if not isinstance(observations.machine_values, tuple) or len(observations.machine_values) != 4:
        raise InputError("machine configuration requires four ordered query observations")
    for value in observations.machine_values:
        if not isinstance(value, RegistryValueObservation):
            raise InputError("missing ordered machine configuration query observation")
        if value.open_status == 0 and value.query_status == 0:
            if not isinstance(value.data, bytes) or len(value.data) != 8:
                raise InputError("successful machine queries need their source eight-byte initialized buffer")
            if value.data[:4] == bytes(4):
                return 8
    return 8 if observations.virtual_disk_present else 0


def _wide(value):
    if not isinstance(value, str):
        raise InputError("device enumeration names must be UTF16 string observations")
    return value.encode("utf-16le", "surrogatepass")


def _wide_key(raw):
    return tuple(int.from_bytes(raw[i:i + 2], "little") for i in range(0, len(raw), 2))


def object_directory_material(names):
    if names is None:
        return 0
    selected = set()
    for name in names:
        if not isinstance(name, str):
            raise InputError("GLOBAL?? names must be source UTF16 strings")
        if name.startswith(_OBJECT_PREFIXES):
            index = name.rfind("#")
            selected.add(_wide(name[:index] if index != -1 else name))
    return mix_device_bytes(b"".join(sorted(selected, key=_wide_key))) & _MASK32 if selected else 0


def display_material(displays):
    selected = set()
    for display in displays:
        if (not isinstance(display, DisplayObservation) or type(display.state_flags) is not int or
                not 0 <= display.state_flags <= _MASK32):
            raise InputError("display enumeration requires exact child ID and DWORD flags")
        if display.state_flags & 1 and not display.state_flags & 8:
            raw = _wide(display.device_id)
            units = _wide_key(raw)
            index = next((i for i in range(9, len(units)) if units[i] == 92), len(units))
            selected.add(raw[:index * 2])
    return mix_device_bytes(b"".join(sorted(selected, key=_wide_key))) & _MASK32 if selected else 0


def initial_device_profile(observations):
    if not isinstance(observations, DeviceObservations):
        raise InputError("device profile requires structured source observations")

    def cpu(leaf):
        words = observations.cpuid.get(leaf)
        if (not isinstance(words, tuple) or len(words) != 4 or
                any(type(word) is not int or not 0 <= word <= _MASK32 for word in words)):
            raise InputError(f"missing exact four-DWORD CPUID observation for leaf {leaf:08X}")
        return words

    def pack(words):
        return b"".join(word.to_bytes(4, "little") for word in words)

    profile = bytearray(64)
    vendor = cpu(0)
    brand = b"".join(pack(cpu(leaf)) for leaf in range(0x80000002, 0x80000006))
    profile[0] = mix_device_bytes(brand + pack((vendor[1], vendor[3], vendor[2]))) & 255
    version = list(cpu(1))
    version[1] &= 0x00FFFFFF
    profile[1] = mix_device_bytes(pack(version)) & 255
    profile[2] = mix_device_bytes(pack(cpu(2))) & 255
    hypervisor = cpu(0x40000000)
    profile[3] = mix_device_bytes(pack(hypervisor[1:])) & 255
    profile[4:8] = object_directory_material(observations.object_names).to_bytes(4, "little")
    if observations.injected_material is not None:
        if not isinstance(observations.injected_material, bytes) or len(observations.injected_material) != 96:
            raise InputError("nonzero host device injection requires its exact 96 observed bytes")
        profile[8:12] = (mix_device_bytes(observations.injected_material) & _MASK32).to_bytes(4, "little")
    if type(observations.uuid_status) is not int or not 0 <= observations.uuid_status <= _MASK32:
        raise InputError("UUID observation status must be an explicit DWORD")
    if observations.uuid_status == 0:
        tail = observations.uuid_tail
        if tail is None:
            if not isinstance(observations.uuid_bytes, bytes) or len(observations.uuid_bytes) != 16:
                raise InputError("successful UUID observation must contain all sixteen source bytes or its exact six consumed bytes")
            tail = observations.uuid_bytes[10:]
        elif not isinstance(tail, bytes) or len(tail) != 6:
            raise InputError("successful UUID tail requires exactly six raw source bytes")
        elif observations.uuid_bytes is not None and (not isinstance(observations.uuid_bytes, bytes) or len(observations.uuid_bytes) != 16 or observations.uuid_bytes[10:] != tail):
            raise InputError("UUID full output and consumed tail disagree")
        value = mix_device_bytes(tail) & _MASK32
        profile[12:16] = value.to_bytes(4, "little")
    information = observations.system_information
    if type(observations.system_information_status) is not int:
        raise InputError("system-information status must be explicit")
    if observations.system_information_status == 0:
        material = observations.system_information_material
        if material is None:
            if not isinstance(information, bytes) or len(information) != 12:
                raise InputError("successful system-information class1 requires twelve bytes or its exact eight consumed bytes")
            material = information[2:6] + information[8:12]
        elif not isinstance(material, bytes) or len(material) != 8:
            raise InputError("system-information material requires eight raw source bytes")
        elif information is not None and (not isinstance(information, bytes) or len(information) != 12 or information[2:6] + information[8:12] != material):
            raise InputError("system-information output and consumed bytes disagree")
        profile[18:20] = (mix_device_bytes(material) & 0xFFFF).to_bytes(2, "little")
    if observations.volume_serial is not None:
        serial = observations.volume_serial
        if type(serial) is not int or not 0 <= serial <= _MASK32:
            raise InputError("successful volume serial observation must be DWORD")
        profile[16:18] = (mix_device_bytes(serial.to_bytes(4, "little")) & 0xFFFF).to_bytes(2, "little")
    profile[20:24] = display_material(observations.displays).to_bytes(4, "little")
    for value, offset in ((observations.object_directory_digest, 4), (observations.display_digest, 20)):
        if value is not None:
            if type(value) is not int or not 0 <= value <= _MASK32:
                raise InputError("raw enumeration digest must be an explicit DWORD")
            profile[offset:offset + 4] = value.to_bytes(4, "little")
    profile[63] = 1
    return bytes(profile)


def _rotate(value, count, bits):
    mask = (1 << bits) - 1
    return ((value << count) | (value >> (bits - count))) & mask


def _sip_round(words):
    a, b, c, d = words
    a = (a + b) & _MASK64
    b = _rotate(b, 13, 64) ^ a
    a = _rotate(a, 32, 64)
    c = (c + d) & _MASK64
    d = _rotate(d, 16, 64) ^ c
    a = (a + d) & _MASK64
    d = _rotate(d, 21, 64) ^ a
    c = (c + b) & _MASK64
    b = _rotate(b, 17, 64) ^ c
    c = _rotate(c, 32, 64)
    return a, b, c, d


def mix_device_bytes(value):
    if not isinstance(value, bytes):
        raise InputError("device byte mixer requires exact observation bytes")
    words = _DEVICE_SEED
    for byte in value:
        a, b, c, d = words
        a, b, c, d = _sip_round((a ^ byte, b, c, d))
        d ^= byte << 24
        words = d, a, b, c
    a, b, c, d = words
    a, b, c, d = _sip_round((a, b, c ^ 255, d))
    a, b, c, d = _sip_round((a ^ c, b ^ d, c ^ 255, d))
    return a ^ b ^ c ^ d


def _checkpoint_block(key, nonce, counter):
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise InputError("device checkpoint nonce must be twelve exact bytes")
    initial = [counter, *(int.from_bytes(nonce[i:i + 4], "little") for i in (0, 4, 8)),
               *(int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)),
               0x59EF210B, 0xC70CE636, 0xE2E58553, 0xD046EA82]
    state = initial.copy()

    def quarter(a, b, c, d):
        state[a] = (state[a] + state[b]) & _MASK32
        state[d] = _rotate(state[d] ^ state[a], 16, 32)
        state[c] = (state[c] + state[d]) & _MASK32
        state[b] = _rotate(state[b] ^ state[c], 12, 32)
        state[a] = (state[a] + state[b]) & _MASK32
        state[d] = _rotate(state[d] ^ state[a], 8, 32)
        state[c] = (state[c] + state[d]) & _MASK32
        state[b] = _rotate(state[b] ^ state[c], 7, 32)

    for _ in range(13):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            quarter(*indices)
    return b"".join(((word + original) & _MASK32).to_bytes(4, "little")
                    for word, original in zip(state, initial))


def checkpoint_stream_block(nonce):
    return _checkpoint_block(bytes(32), nonce, 0x21F46447)


def checkpoint_transform(value, nonce):
    if not isinstance(value, bytes) or len(value) != 1000:
        raise InputError("device checkpoint transform needs exactly 1000 bytes")
    counter = 0xBE44BB8A
    accumulator = [0] * 16
    result = bytearray()
    for offset in range(0, 1000, 64):
        block = _checkpoint_block(_CHECKPOINT_KEY, nonce, counter)
        accumulator = [(current + int.from_bytes(block[i * 4:i * 4 + 4], "little")) & _MASK32
                       for i, current in enumerate(accumulator)]
        stream = b"".join(word.to_bytes(4, "little") for word in accumulator)
        result.extend(a ^ b for a, b in zip(value[offset:offset + 64], stream))
        counter = (counter + 0x55FF8D55) & _MASK32
    return bytes(result)


def poly1305(message, key):
    if not isinstance(message, bytes) or not isinstance(key, bytes) or len(key) != 32:
        raise InputError("Poly1305 requires message bytes and a 32-byte key")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b"\x01", "little")) * r) % ((1 << 130) - 5)
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def checkpoint_tag(ciphertext, nonce):
    if not isinstance(ciphertext, bytes) or len(ciphertext) != 1000:
        raise InputError("device checkpoint ciphertext must be exactly 1000 bytes")
    message = ciphertext + bytes.fromhex("7843cb1424494cf7") + (1000).to_bytes(4, "little")
    return poly1305(message, checkpoint_stream_block(nonce)[:32])


def decode_profile(value):
    if not isinstance(value, bytes):
        raise InputError("profile.dat2 decoder requires exact observed file bytes")
    if len(value) != 50:
        return None
    ciphertext, tag, nonce = value[:22], value[22:38], value[38:50]
    message = ciphertext + bytes.fromhex("7843cb1424494cf7") + (22).to_bytes(4, "little")
    expected = poly1305(message, checkpoint_stream_block(nonce)[:32])
    if not hmac.compare_digest(expected, tag):
        return None
    stream = _checkpoint_block(_PROFILE_KEY, nonce, 0xBE44BB8A)
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


def encode_profile(material, random_bytes):
    if not isinstance(material, bytes) or len(material) != 22:
        raise InputError("profile.dat2 writer requires exactly 22 material bytes")
    parts = [random_bytes(4) for _ in range(3)]
    if any(not isinstance(part, bytes) or len(part) != 4 for part in parts):
        raise InputError("profile nonce requires three exact observed rand_s DWORD outputs")
    nonce = b"".join(parts)
    stream = _checkpoint_block(_PROFILE_KEY, nonce, 0xBE44BB8A)
    ciphertext = bytes(a ^ b for a, b in zip(material, stream))
    message = ciphertext + bytes.fromhex("7843cb1424494cf7") + (22).to_bytes(4, "little")
    return ciphertext + poly1305(message, checkpoint_stream_block(nonce)[:32]) + nonce


@dataclass(frozen=True)
class CheckpointResult:
    success: bool
    record: bytes | None
    error_code: int


def decode_checkpoint(value, *, previous_error=0):
    if not isinstance(value, bytes) or type(previous_error) is not int:
        raise InputError("checkpoint decoder needs file bytes and an explicit previous error")
    if len(value) < 1028:
        return CheckpointResult(False, None, 0x1A)
    ciphertext, tag, nonce = value[:1000], value[1000:1016], value[1016:1028]
    if not hmac.compare_digest(checkpoint_tag(ciphertext, nonce), tag):
        return CheckpointResult(False, None, 0x1B)
    record = checkpoint_transform(ciphertext, nonce)
    if record[:2] != b"\x01\0":
        return CheckpointResult(False, None, previous_error)
    return CheckpointResult(True, record, previous_error)


def encode_checkpoint(record, random_bytes):
    if not isinstance(record, bytes) or len(record) != 1000:
        raise InputError("device checkpoint writer requires exactly 1000 record bytes")
    parts = [random_bytes(4) for _ in range(3)]
    if any(not isinstance(part, bytes) or len(part) != 4 for part in parts):
        raise InputError("checkpoint nonce requires three exact observed rand_s DWORD outputs")
    nonce = b"".join(parts)
    ciphertext = checkpoint_transform(record, nonce)
    return ciphertext + checkpoint_tag(ciphertext, nonce) + nonce


def _new_record(hardware_profile, fingerprint, method, flagged):
    if not isinstance(hardware_profile, bytes) or len(hardware_profile) != 64:
        raise InputError("new checkpoint record needs the exact computed 64-byte hardware profile")
    record = bytearray(1000)
    record[:2] = b"\x01\0"
    record[8:72] = hardware_profile
    record[72:80] = fingerprint.to_bytes(8, "little")
    record[80] = method
    record[81] = int(flagged)
    return bytes(record)


def new_checkpoint_record(hardware_profile, material, *, method=6, flagged=False):
    if (not isinstance(material, bytes) or len(material) != 22 or method not in (3, 4, 5, 6) or
            type(flagged) is not bool):
        raise InputError("checkpoint record needs source method3/4/5/6, 22-byte material and its sticky flag")
    return _new_record(hardware_profile, mix_device_bytes(material), method, flagged)


def invalid_checkpoint_record(hardware_profile):
    return _new_record(hardware_profile, 0, 0, True)


def checkpoint_hardware_invalidates(record, hardware_profile):
    if not isinstance(record, bytes) or len(record) != 1000 or not isinstance(hardware_profile, bytes) or len(hardware_profile) != 64:
        raise InputError("hardware matcher requires a decoded record and computed 64-byte profile")
    distance = sum((a ^ b).bit_count() for a, b in zip(record[8:32], hardware_profile[:24]))
    return (record[71] == hardware_profile[63] == 1 and distance >= 36 and
            int.from_bytes(record[72:80], "little") != 0)


def checkpoint_needs_update(record, hardware_profile, material, *, flagged=False):
    if record is None:
        return True
    if (not isinstance(record, bytes) or len(record) != 1000 or
            not isinstance(hardware_profile, bytes) or len(hardware_profile) != 64 or
            not isinstance(material, bytes) or len(material) != 22 or type(flagged) is not bool):
        raise InputError("checkpoint comparison requires exact decoded source values")
    return (record[:2] != b"\x01\0" or record[72:80] != mix_device_bytes(material).to_bytes(8, "little") or
            record[71] != hardware_profile[63] or bool(record[81] & 1) != flagged or
            record[8:32] != hardware_profile[:24])


def _device_substitution(filename, identity, variant):
    raw = (Path(__file__).with_name("data") / "primary_sign_qq52230" / filename).read_bytes()
    if hashlib.sha256(raw).hexdigest() != identity:
        raise InputError("fixed device substitution asset identity mismatch")
    return [raw[variant * 256 + i] ^ ((i + 23) & 255) for i in range(256)]


_MATERIAL_KEY = bytes.fromhex("40ae97772b7ee37ff2f338dee848df36aef6493928fba8292ea3c47f4ab53cda")


def _device_material_message(seed):
    if not isinstance(seed, bytes) or len(seed) != 16:
        raise InputError("device material requires exactly sixteen seed bytes")
    table = _device_substitution("device-material-sboxes.bin",
                                 "2b28d89c4d42465e621c9110291f91d30ced9a544681601ff0b14ded61a77ab2",
                                 seed[11] % 5)
    transformed = [table[value] for value in seed]
    for left, right in ((3, 2), (11, 5), (0, 12), (15, 13), (6, 1), (14, 10), (9, 7), (8, 4)):
        transformed[left], transformed[right] = transformed[right], transformed[left]
    return bytes(transformed) + bytes.fromhex("1b282c353349d964")


def device_material(seed):
    return seed + poly1305(_device_material_message(seed), _MATERIAL_KEY)[:6]


def device_public_key_material(public_key_bits):
    if not isinstance(public_key_bits, bytes):
        raise InputError("device public key material requires raw exported PublicKey bits")
    return device_material(hashlib.sha256(public_key_bits).digest()[:16])


def device_aes(value, key, variant):
    if (not isinstance(value, bytes) or len(value) % 16 or
            not isinstance(key, bytes) or len(key) != 16 or type(variant) is not int or
            not 0 <= variant < 5):
        raise InputError("device AES requires complete blocks, an AES128 key and a source variant")
    box = _device_substitution("device-aes-sboxes.bin",
                               "a922c95334ad72e13e8d10b88fe32cb696cb2e2aa5ed7706b58d6bdd7c57b603", variant)

    def xtime(item):
        return ((item << 1) ^ (0x11B if item & 128 else 0)) & 255

    expanded = list(key)
    rcon = 1
    while len(expanded) < 176:
        word = expanded[-4:]
        if len(expanded) % 16 == 0:
            word = [box[word[1]] ^ rcon, box[word[2]], box[word[3]], box[word[0]]]
            rcon = xtime(rcon)
        for item in word:
            expanded.append(item ^ expanded[-16])
    result = bytearray()
    for offset in range(0, len(value), 16):
        state = [item ^ expanded[i] for i, item in enumerate(value[offset:offset + 16])]
        for round_number in range(1, 11):
            state = [box[state[((column + row) % 4) * 4 + row]]
                     for column in range(4) for row in range(4)]
            if round_number != 10:
                for column in range(0, 16, 4):
                    a, b, c, d = state[column:column + 4]
                    total = a ^ b ^ c ^ d
                    state[column:column + 4] = [a ^ total ^ xtime(a ^ b), b ^ total ^ xtime(b ^ c),
                                                c ^ total ^ xtime(c ^ d), d ^ total ^ xtime(d ^ a)]
            state = [item ^ expanded[16 * round_number + i] for i, item in enumerate(state)]
        result.extend(state)
    return bytes(result)


def encode_device_body(body, time_seconds, random_bytes):
    if (not isinstance(body, bytes) or len(body) > 24 or type(time_seconds) is not int or
            not 0 <= time_seconds <= _MASK32):
        raise InputError("device encoding needs at most 24 body bytes and DWORD time seconds")
    values = [random_bytes(4) for _ in range(5)]
    if any(not isinstance(value, bytes) or len(value) != 4 for value in values):
        raise InputError("device header needs five exact observed rand_s DWORD outputs")
    header = bytes(value[0] for value in values)
    first_key, second_key = bytearray(16), bytearray(16)
    for index, value in zip((14, 4, 12, 8, 1), header):
        first_key[index] = value
    for index, value in zip((0, 7, 4, 13, 10), header):
        second_key[index] = value
    plain = b"\x03\x01\x74\x2e" + (time_seconds ^ 0xDE9DC120).to_bytes(4, "little") + body
    plain += bytes([32 - len(plain)]) * (32 - len(plain))
    first = device_aes(plain, bytes(first_key), first_key[4] % 5)
    second = device_aes(first, bytes(second_key), second_key[4] % 5)
    return (b"\xd1" + header + second).hex().upper().encode("ascii")
