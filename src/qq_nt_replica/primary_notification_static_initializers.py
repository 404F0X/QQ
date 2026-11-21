from .errors import InputError
from .primary_notification_startup import construct
from .primary_logger import _String
from .primary_worker_consumer import _invoke


_TIMEZONE_BYTES = bytes.fromhex(
    '0108326566373635333a3c3d3e00000108626764703c7e23316c786c74686d365563756b71762f537c615f697b657b7c0000'
    '01087d697d65797c00000108646c646c6d656d517d697d65797c000001087167746b5e677b696e7b7b6d000001087464726e'
    '607c5b6d63656d000001086673755975617565797c00000108716867695977617b657b7c00000108666e77596361716f687c'
    '0000010872645869726d6f6d796760660000010861636575665d6769796b6c7c00000108616e707e5961617f6f6a7c0000'
    '01086b62777f7373416171677a4a777f736a6300000108756b6e617f69696d0000')
_EXIT_HEADERS = {0x2DF7450 + index * 0x20: 0x6D86588 + index * 24 for index in range(15)}
_EXIT_HEADERS.update({0x35A69D0 + index * 0x20: 0x6D88D78 + index * 24 for index in range(14)})
_SUPPORTED = (0x1D27F30, 0x2E07D30, 0x2E0AB10, 0x2E0FE10, 0x35BE420, 0x35C0550)
_MODULE_PREFIX_BYTES = bytes.fromhex(
    '013e045350010003050c0a0b080000013e545152460a4815075a4e5a425e5b006355435d474019654a57695f4d534d4a'
    '0000013e4b5f4b534f4a0000013e525a525a5b535b674b5f4b534f4a0000013e4751425d68514d5f584d4d5b0000013e'
    '42524458564a6d5b55535b0000013e5045436f435743534f4a0000013e475e515f6f41574d534d4a0000013e5058416f'
    '555747595e4a0000013e44526e5f445b595b4f5156500000013e57555343506b515f4f5d5a4a0000013e575846486f57'
    '5749595c4a0000013e5d5441494545775747514c7c4149455c550000013e435d5857495f5f5b0000')
_MODULE_SUFFIX_BYTES = bytes.fromhex(
    '013e6652465e4247764450565c0000')
_MODULE_RECIPES = (
    '4d455e44474c771616157b52530f505e55',
    '4d455e44474c771516157b52530f505e55',
    '53505a4054551d585152',
    '5c554254455e1d585c4a',
    '4c5d19505c1f405e55',
    '484b1559455b',
    '405443584347575e4917485e55',
    '5e504559555d51491457575b5b',
    '4d5a4a40474d45504a434755494c4c13585352',
    '4a5d4d47404a42574d4440524e4b4b1455575d5b',
    '4e5a444c744b4648514157560d444d52',
    '55585f1a041b04160a175c5352',
    '565e5a5618041908140a15585152',
    '4940434f5f454d0a140b140e120f445352',
    '49424e414f4a5c0a140b140e120f445352',
    '5d54595f461e0013585352',
    '5c58435c1c0a1d585152',
    '595f5556575b1d585152',
    '5d5b51425c4644150d0815585152',
    '5c5a50435d4745145b4b4a13585352',
    '58575d5f431c5d53595b',
    '44544454021e0a13585352',
    '5840485c5f015a4b4d13130b5f12111455575d5b',
    '594f5f5f455c404b421511120d444d52',
    '4844404b415872475b544448544d4a54155c5552',
    '444250464751471455575d5b',
    '4c595d51031f545352',
    '584a5848425b034850400f464b554314400d0e13585352',
    '47414b49404e474740540c140914080a155c5552',
    '42444e4c46404a0a140b140e120f445352',
    '584a5848425b034850400f464b554314400d0e13585352',
    '5d5b51425c4644150d0815585152',
    '4e5a444c744b4648514157560d444d52',
    '4c5f434a4e4a4954527a4d53410f445352',
    '54574a514b41534b46424b45434d4546524603061d545d52',
    '59575b5c1d545d52',
    '4642445e42584a795f12110c4d4f455b',
    '5e4347554705010a155c5552',
    '46455b461d545d52',
    '465654401d545d52',
    '5e44561c5d5f555b',
    '53505a4054551d585152',
    '54465e1d5c411e4b5450',
    '465343425555465f155c5552',
    '5240565c525118410e0f1453535b5b',
    '5a46525e52441d585152',
    '5b4d5d5d475e4249401713107e130d585152',
    '5941495d5e005b4a4c12120a4f4417091457575b5b',
    '484b1559455b',
    '4743455f43594b784f4417110c4f4f5b5b',
    '584a5848425b034850400f464b55431440030c13585352',
    '5a59445f454f5d45484c454b4d434b485c4815585152',
    '40431e444759435757145553595b',
    '504955447c484e5d5b7348525b475b42684c03061d545d52',
    '4744514b1c5f5f5b5b',
    '5b455b52441f545352',
    '475c59565b1f545352',
    '454140555353525c504e15585c4a',
    '5e58575f4244415259175c5352',
)
_LIBRARY_RECIPES = (
    '5855435852580608155c5552',
    '4045524202001d585152',
    '51515d00001f545352',
    '52544757475d0608155c5552',
    '475f535d5c000013585352',
    '5841505f5e1f545352',
    '50555159555f4213585352',
)

_PROCESS_RECIPES = (
    '4345534245',
    '48485a4c4244494d565541544d',
    '4c4c5e444445414943',
    '48485a5c57434f404e48454952',
    '4f4d46584f4347504054',
    '4d4a594a584d4a4654',
    '4c40444f455c4042',
    '4b474348425b4147574256464c4254',
    '4f43474c465f5a574b4543',
    '4c5e4259584a4854',
    '4a49424846404d4952',
    '4b495e4158494f43',
    '49475c4548444a434054',
    '445154444a534f',
    '445154444a534f',
    '485d584d4d4d4f4b404254',
    '485d584d4d4d4f4b404254',
    '4e455a4c5b1e4e4e4a535754',
    '4b405f4846404d4952',
    '4a424e46424d4752',
    '455a4d4a565248',
    '46595054',
    '4a55585948475b43',
    '4745594a4253',
    '49435f474f474a4d',
    '51465a5c4759544c535d485458505c54',
    '46434e414442',
    '46434e414442',
    '484d404f464d4753',
    '484a5f5f45464c54',
    '43495b4a584d5f474a4e4749',
    '4547415c4a4642414b52',
    '4644425f49465d4952',
    '4341475a4945415646521114',
    '494b4d50524e',
    '495a47575345',
    '46144a5347415f43',
    '4517495044425c40474b4f',
    '481a50454343',
    '444d4e4e4c48594d4243',
    '42465d4b5d4f485257444e41',
    '45584e46424d4752',
    '454440474d41475452',
    '43434e415b494e43',
    '4249435f48475b43',
    '4357484846404d4952',
    '414e4e46424d4752',
    '4f4757464454',
    '414959484a5a4043',
    '454d5d4c4e5e585247415543',
    '43415b414a4f5b564a4c',
    '425c4a4645424444504242',
    '4e57554e575154',
    '405a48464b5a5c4254',
    '4f5a53565048',
    '41594b5e4b5b4c4254',
    '5e485544455b5a5248',
    '5942444248594a42524751524054',
    '5c5d414a4d585956454143',
    '515741534c48',
    '5b5d4b594642585247415543',
    '5157415c5048',
    '5f5b444447474e49',
    '5f5b434f5f4a4854',
    '5b504d5c5a424e4e4a454f52',
    '524641494b444d',
    '58404b474f495f404e48454952',
    '5d565549434d4a4d',
    '5c57544846404d4952',
    '5f54574147595f45494a',
    '595251404e424c4e5a534454',
    '5c57545e5a4d495343',
    '5c4e584045414f4d4d424c44434254',
    '5a4f5b4d5b4c59454843',
    '5a4f5b4d5b4c59454843',
    '57444b53575543',
    '57444b53575543',
    '54484345',
    '574e404c474848',
    '574e4048414953',
    '58414f474e465c15',
    '58544e465f494042',
    '58544e465f494042',
    '575b4149504e4b',
    '575b4149504e4b',
    '5c504a5b4358585046434d4f',
    '404c525e440252524b4c515d154f4143',
    '5d51585d41414545470f575f43',
    '5d51585d41414545470f575f43',
    '404c47484b0252524b4c515d154f4143',
    '404c47484b0252524b4c515d154f4143',
    '5c505a4b4c5f485055494243',
    '58545e53454b454f',
    '58404e4c414952',
    '5741554846404d4952',
    '575c5f4846404d4952',
    '5647404c4452',
    '5b4a4d41495f4b5554425e',
    '56474a5c4c48',
    '564744454843',
    '59495f774d4b4e494a48',
    '405152535e555c57515551555a5c5c54',
    '4d5f4358594f415543',
    '594b41585b455f414652',
    '5d5e594b7748464c414952',
    '5e5d5a48745c5c51',
    '5d5e594b77584f57524254',
    '514349',
    '4c444849405d4d49',
    '405848404b4d4e4e4a454f52',
    '47554e46424d4752',
    '5b4d5e46444f4048',
    '41594c44404f45501312',
    '435b404f455d1f12',
    '4d4f4543',
)

_INTEGRITY_STRINGS = (
    ('6674777873767531746e7375', 0x35BE518, 0x35BE564, 0x35BE569),
    ('7b7f74726e3b7e68', 0x35BE648, 0x35BE694, 0x35BE699),
    ('7d73667a767e726a377068', 0x35BE788, 0x35BE7D4, 0x35BE7D9),
    ('7b75607c7078746c31766e7575', 0x35BE8C8, 0x35BE914, 0x35BE919),
    ('7b75607c7078746c3172727e7e', 0x35BEA08, 0x35BEA54, 0x35BEA59),
    ('71777f386e7e66377268', 0x35BEB38, 0x35BEB84, 0x35BEB89),
    ('7664654d7f7164707c74786847', 0x35BEC78, 0x35BECC4, 0x35BECC9),
    ('607066607b7e7e31746e7375', 0x35BEDB8, 0x35BEE04, 0x35BEE09),
    ('6b797863676e6d776b6e6e296c766b75', 0x35BEF08, 0x35BEF54, 0x35BEF59),
    ('4d4e307c607e', 0x35BF028, 0x35BF074, 0x35BF079),
    ('61677563627462317072787e', 0x35BF168, 0x35BF1B4, 0x35BF1B9),
    ('6b797863676e6d776b6e6e2967766569', 0x35BF2B8, 0x35BF304, 0x35BF309),
    ('7d72787a663978767c7e', 0x35BF3E8, 0x35BF434, 0x35BF439),
    ('43405e4338717877', 0x35BF518, 0x35BF564, 0x35BF569),
)


def install_image(memory, base):
    if not any(region.address <= base + 0x48C7B93 and base + 0x48C7B96 <= region.address + len(region.data)
               for region in memory._regions):
        memory.map(base + 0x48C7B93, b'\\*\0', name='fixed notification account wildcard', initialized=True)
    if memory.read(base + 0x48C7B93, 3) != b'\\*\0':
        raise InputError('notification account wildcard differs from its fixed PE literal')
    for rva, target in ((0x64290E0, 0x3E97020), (0x64290E8, 0x3E94F90), (0x5E954D8, 0x3E94F90)):
        address = base + rva
        if not any(region.address <= address and address + 8 <= region.address + len(region.data)
                   for region in memory._regions):
            memory.map(address, (base + target).to_bytes(8, 'little'),
                       name='fixed notification default CRT JSON hook', initialized=True)
        if memory.load(address, 8) != base + target:
            raise InputError('notification JSON hook differs from its fixed original PE initializer')
    for rva, size, initialized in ((0x677DE38, 327, False), (0x6D86588, 0x250, True), (0x6D869C8, 232, True), (0x6D88D78, 0x170, True), (0x6D890C0, 40, True)):
        cursor, end = base + rva, base + rva + size
        for region in tuple(memory._regions):
            start, stop = region.address, region.address + len(region.data)
            if stop <= cursor or start >= end:
                continue
            if cursor < start:
                memory.map(cursor, bytearray(start - cursor),
                           name='supported notification static PE zero fill' if initialized else 'notification module static storage', initialized=initialized)
            cursor = max(cursor, stop)
        if cursor < end:
            memory.map(cursor, bytearray(end - cursor),
                       name='supported notification static PE zero fill' if initialized else 'notification module static storage', initialized=initialized)


def construct_timezone(runtime):
    if (getattr(runtime, 'notification_timezone_initializer_state', None) is not None or
            getattr(runtime, 'notification_timezone_name_initialized', None) is not None):
        raise InputError('notification timezone static initializer is not fresh')
    base = runtime.image_base
    runtime.notification_timezone_initializer_state = (base, 'running')
    try:
        for index, value in enumerate(_TIMEZONE_BYTES):
            runtime.memory.store(base + 0x6D869C8 + index, value, 1,
                                 source=f'{0x2E0FE10 + index * 7:X}.notification_static_initializer')
    except BaseException:
        runtime.notification_timezone_initializer_state = (base, 'failed')
        raise
    runtime.notification_timezone_name_initialized = base + 0x6D86AA4
    runtime.notification_timezone_initializer_state = (base, 'complete')


def initialize_supported(runtime):
    if (getattr(runtime, 'notification_static_initializers', None) is not None or
            getattr(runtime, 'notification_timezone_initializer_state', None) is not None or
            getattr(runtime, 'notification_timezone_name_initialized', None) is not None or
            getattr(runtime, 'notification_integrity_initializer_state', None) is not None or
            getattr(runtime, 'notification_process_names_initializer_state', None) is not None or
            getattr(runtime, 'notification_module_startup_initializer_state', None) is not None or
            getattr(runtime, 'notification_module_names_initializer_state', None) is not None or
            getattr(runtime, 'notification_module_libraries_initializer_state', None) is not None):
        raise InputError('supported notification static initialization is not fresh')
    base = runtime.image_base
    runtime.notification_static_initializers = (base, 'running', _SUPPORTED)
    try:
        construct_module_startup(runtime)
        construct(runtime)
        initialize_static_unit(runtime)
        construct_timezone(runtime)
        construct_integrity(runtime)
        construct_process_names(runtime)
    except BaseException:
        runtime.notification_static_initializers = (base, 'failed', _SUPPORTED)
        raise
    runtime.notification_static_initializers = (base, 'complete', _SUPPORTED)


def construct_integrity(runtime):
    if getattr(runtime, 'notification_integrity_initializer_state', None) is not None:
        raise InputError('notification integrity static initializer is not fresh')
    memory, base = runtime.memory, runtime.image_base
    runtime.notification_integrity_initializer_state = (base, 'running')
    try:
        for index, (encoded_hex, flag_site, copy_site, terminator_site) in enumerate(_INTEGRITY_STRINGS):
            encoded = bytes.fromhex(encoded_hex)
            length = len(encoded)
            value = bytes(byte ^ ((offset + 1) & 255) ^ 0x1B ^ length
                          for offset, byte in enumerate(encoded))
            if not 0 < length < 23 or b'\0' in value:
                raise InputError('notification integrity static literal leaves its fixed short String domain')
            address = base + 0x6D88D78 + index * 24
            memory.store(address, length * 2, 1, source=f'{flag_site:X}.integrity_static_string_flag')
            memory.write(address + 1, value, source=f'{copy_site:X}.integrity_static_string_payload')
            memory.store(address + length + 1, 0, 1,
                         source=f'{terminator_site:X}.integrity_static_string_terminator')
            _invoke(runtime, 0x3E680B4, base + 0x35A69D0 + index * 0x20)
    except BaseException:
        runtime.notification_integrity_initializer_state = (base, 'failed')
        raise
    runtime.notification_integrity_initializer_state = (base, 'complete')


def construct_process_names(runtime):
    from .primary_worker_response import _frame
    if getattr(runtime, 'notification_process_names_initializer_state', None) is not None:
        raise InputError('notification process-name static initializer is not fresh')
    memory, base = runtime.memory, runtime.image_base
    runtime.notification_process_names_initializer_state = (base, 'running')
    frame = None
    try:
        frame, rbp = _frame(runtime, 0xB80, '35C0550.process_names_static_frame')
        first = rbp - 0x50
        for index, recipe in enumerate(_PROCESS_RECIPES):
            encoded = bytes.fromhex(recipe)
            value = bytes(byte ^ 0x26 ^ (offset + 1) ^ len(encoded) for offset, byte in enumerate(encoded))
            if not 0 < len(value) <= 16 or b'\0' in value:
                raise InputError('process-name literal leaves its fixed short String domain')
            _String.construct(runtime, value).write_to(first + index * 24)
        pair = first + 115 * 24
        memory.store(pair, first, 8, source='35CACDF.process_names_range_first')
        memory.store(pair + 8, 115, 8, source='35CACDF.process_names_range_count')
        _invoke(runtime, 0x1224BDC, base + 0x6D890C0, pair)
        for index in range(114, -1, -1):
            _String.read(runtime, first + index * 24).destroy()
        _invoke(runtime, 0x3E680B4, base + 0x35CB7E0)
    except BaseException:
        runtime.notification_process_names_initializer_state = (base, 'failed')
        raise
    finally:
        if frame is not None:
            memory.unmap(frame)
    runtime.notification_process_names_initializer_state = (base, 'complete')


def destroy_process_names(runtime):
    from .primary_vm import PrimaryProgramLimit
    memory, base = runtime.memory, runtime.image_base
    if getattr(runtime, 'notification_process_names_initializer_state', None) != (base, 'complete'):
        raise InputError('process-name destructor requires its completed original constructor')
    address = base + 0x6D890C0
    node = memory.load(address + 16, 8)
    try:
        for ignored in range(4096):
            if not node:
                break
            following = memory.load(node, 8)
            _String.read(runtime, node + 16).destroy()
            runtime._free_allocation(node)
            node = following
        else:
            raise PrimaryProgramLimit('process-name destructor exceeds its bounded source domain')
        buckets = memory.load(address, 8)
        if buckets:
            runtime._free_allocation(buckets)
        memory.store(address, 0, 8, source='35CB7F9.clear_process_names_buckets')
    except BaseException:
        runtime.notification_process_names_initializer_state = (base, 'destroy_failed')
        raise
    runtime.notification_process_names_initializer_state = (base, 'destroyed')


def _construct_module_strings(runtime, first, recipes):
    for index, recipe in enumerate(recipes):
        encoded = bytes.fromhex(recipe)
        value = bytes(byte ^ 0x3E ^ (offset + 1) ^ len(encoded) for offset, byte in enumerate(encoded))
        if not value or b'\0' in value:
            raise InputError('notification module literal leaves its fixed CString domain')
        _String.construct(runtime, value).write_to(first + index * 24)


def construct_module_names(runtime):
    from .primary_worker_response import _frame
    if getattr(runtime, 'notification_module_names_initializer_state', None) is not None:
        raise InputError('notification module-name static initializer is not fresh')
    memory, base = runtime.memory, runtime.image_base
    runtime.notification_module_names_initializer_state = (base, 'running')
    frame = None
    try:
        frame, rbp = _frame(runtime, 0xAE0, '1D193B0.module_names_static_frame')
        first, pair = rbp - 0x48, rbp - 0x58
        _construct_module_strings(runtime, first, _MODULE_RECIPES)
        memory.store(pair, first, 8, source='1D1F1BB.module_names_range_first')
        memory.store(pair + 8, 59, 8, source='1D1F1BF.module_names_range_count')
        _invoke(runtime, 0x1224BDC, base + 0x677DF20, pair)
        for index in range(58, -1, -1):
            _String.read(runtime, first + index * 24).destroy()
        result = _invoke(runtime, 0x3E680B4, base + 0x1D1F7F0)
    except BaseException:
        runtime.notification_module_names_initializer_state = (base, 'failed')
        raise
    finally:
        if frame is not None:
            memory.unmap(frame)
    runtime.notification_module_names_initializer_state = (base, 'complete')
    return result


def construct_module_startup(runtime):
    from .primary_worker_response import _frame
    if any(getattr(runtime, name, None) is not None for name in ('notification_module_startup_initializer_state',
           'notification_module_names_initializer_state', 'notification_module_libraries_initializer_state')):
        raise InputError('notification module startup is not fresh')
    memory, base = runtime.memory, runtime.image_base
    runtime.notification_module_startup_initializer_state = (base, 'running')
    frame = None
    neighbor_started = False
    try:
        frame, rbp = _frame(runtime, 0x160, '1D27F30.module_startup_static_frame')
        for index, value in enumerate(_MODULE_PREFIX_BYTES):
            memory.store(base + 0x677DE38 + index, value, 1, source=f'{0x1D27F50 + index * 7:X}.module_encoded_prefix')
        _invoke(runtime, 0x1D193B0)
        runtime.notification_module_libraries_initializer_state = (base, 'running')
        neighbor_started = True
        first, pair = rbp - 0x60, rbp + 0xC0
        _construct_module_strings(runtime, first, _LIBRARY_RECIPES)
        memory.store(pair, first, 8, source='1D28EFB.module_libraries_range_first')
        memory.store(pair + 8, 7, 8, source='1D28F02.module_libraries_range_count')
        _invoke(runtime, 0x1224BDC, base + 0x677DF48, pair)
        for index in range(6, -1, -1):
            _String.read(runtime, first + index * 24).destroy()
        _invoke(runtime, 0x3E680B4, base + 0x1D1F860)
        runtime.notification_module_libraries_initializer_state = (base, 'complete')
        for index, value in enumerate(_MODULE_SUFFIX_BYTES):
            memory.store(base + 0x677DF70 + index, value, 1, source=f'{0x1D28F77 + index * 7:X}.module_encoded_suffix')
    except BaseException:
        runtime.notification_module_startup_initializer_state = (base, 'failed')
        if neighbor_started and runtime.notification_module_libraries_initializer_state[1] == 'running':
            runtime.notification_module_libraries_initializer_state = (base, 'failed')
        raise
    finally:
        if frame is not None:
            memory.unmap(frame)
    runtime.notification_module_startup_initializer_state = (base, 'complete')


def _destroy_module_set(runtime, rva, state_name, clear_site):
    from .primary_vm import PrimaryProgramLimit
    memory, base = runtime.memory, runtime.image_base
    if getattr(runtime, state_name, None) != (base, 'complete'):
        raise InputError('notification module destructor requires its completed original constructor')
    address = base + rva
    try:
        node = memory.load(address + 16, 8)
        for ignored in range(4096):
            if not node:
                break
            following = memory.load(node, 8)
            _String.read(runtime, node + 16).destroy()
            runtime._free_allocation(node)
            node = following
        else:
            raise PrimaryProgramLimit('notification module destructor exceeds its bounded source domain')
        buckets = memory.load(address, 8)
        memory.store(address, 0, 8, source=f'{clear_site:X}.clear_module_buckets')
        if buckets:
            runtime._free_allocation(buckets)
    except BaseException:
        setattr(runtime, state_name, (base, 'destroy_failed'))
        raise
    setattr(runtime, state_name, (base, 'destroyed'))


def invoke(runtime, rva, values):
    if values:
        raise InputError('notification static initializer and exit callbacks take no arguments')
    if rva == 0x1D27F30:
        return construct_module_startup(runtime)
    if rva == 0x1D193B0:
        return construct_module_names(runtime)
    if rva == 0x1D1F7F0:
        return _destroy_module_set(runtime, 0x677DF20, 'notification_module_names_initializer_state', 0x1D1F809)
    if rva == 0x1D1F860:
        return _destroy_module_set(runtime, 0x677DF48, 'notification_module_libraries_initializer_state', 0x1D1F879)
    if rva == 0x35C0550:
        return construct_process_names(runtime)
    if rva == 0x35CB7E0:
        return destroy_process_names(runtime)
    if rva == 0x2E0FE10:
        return construct_timezone(runtime)
    if rva == 0x35BE420:
        return construct_integrity(runtime)
    if rva not in _EXIT_HEADERS:
        raise InputError('unsupported notification static callback')
    address = runtime.image_base + _EXIT_HEADERS[rva]
    _String.read(runtime, address).destroy()


_UNIT_BODY_SHA='98b24aa2d18deec97f05f00bc1defb8e12b7674c8b03787e9ffe0bc2ddc7c41f'
def _unit_plan():
    import hashlib
    from pathlib import Path
    raw=(Path(__file__).with_name('data')/'primary_sign_qq52230/static-unit-2e0ab10.bin').read_bytes()
    if len(raw)!=1625 or hashlib.sha256(raw).hexdigest()!=_UNIT_BODY_SHA or raw[-1:]!=b'\xC3':
        raise InputError('static unit fixed body changed')
    plan=[]
    for index in range(232):
        instruction=raw[7*index:7*index+7]
        target=0x2E0AB10+7*index+7+int.from_bytes(instruction[2:6],'little',signed=True)
        if instruction[:2]!=b'\xC6\x05' or target!=0x6D867D8+index:
            raise InputError('static unit source write template changed')
        plan.append((target,instruction[6]))
    return plan

class _StaticUnit:
    def __init__(self,signer):
        self.signer=signer;self.runtime=signer.runtime;self.memory=signer.memory;self.base=signer.image_base
        self.epoch=self.runtime._primary_allocator_selector_epoch
        self.region,offset=self.memory._span(self.base+0x6D867D8,232)
        if offset or len(self.region.data)!=232:raise InputError('static unit image span differs')
        self.phase='fresh'
    def validate(self,runtime):
        region,offset=runtime.memory._span(runtime.image_base+0x6D867D8,232)
        if (runtime is not self.runtime or runtime.memory is not self.memory or runtime.image_base!=self.base or
            self.signer.runtime is not runtime or runtime._primary_entry_owner is not self.signer or
            runtime._primary_allocator_selector_epoch is not self.epoch or region is not self.region or offset or
            getattr(runtime,'_static_unit_2e0ab10',None) is not self or
            getattr(runtime._custom_allocator_backend,'closed',True)):
            raise InputError('static unit runtime/image epoch is stale or closed')

def bind_static_unit(signer):
    if getattr(signer.runtime,'_static_unit_2e0ab10',None) is not None:raise InputError('static unit cannot rebind')
    signer.runtime._static_unit_2e0ab10=_StaticUnit(signer)

def initialize_static_unit(runtime):
    unit=getattr(runtime,'_static_unit_2e0ab10',None)
    if type(unit) is not _StaticUnit:raise InputError('static unit lacks fresh runtime image binding')
    unit.validate(runtime)
    if unit.phase!='fresh':raise InputError('static unit is not fresh')
    unit.phase='running'
    try:
        for rva,value in _unit_plan():runtime.memory.store(unit.base+rva,value,1,source=f'{0x2E0AB10+7*(rva-0x6D867D8):X}.static_unit_byte')
    except BaseException:
        unit.phase='failed';raise
    unit.phase='complete'
    # The leaf does not define RAX; its supported caller discards the return.
