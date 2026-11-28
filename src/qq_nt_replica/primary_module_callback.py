from .errors import InputError
from .primary_logger import log


_SOURCE_FILE = bytes.fromhex('523a5c6465766f70735c776f726b73706163655c702d38323462373437353661643634653132383338363031636364653665636566625c706c6174666f726d735c57696e646f77735c6c696273656378785c656e76696e666f5c656e756d6d6f64756c65732e637070')
_TAG = b'[FGESDK]'


def install_image(memory, image_base):
    values = (0x142A0, 0x1D27500, 0x1D27510, 0x28F0, 0x1FE0, 0x1D27530)
    memory.map(image_base + 0x414BB08,
               b''.join((image_base + value).to_bytes(8, 'little') for value in values),
               name='fixed module report callback vtable', initialized=True)


def invoke(runtime, rva, values):
    if rva == 0x1D27500 and len(values) == 2:
        table = runtime.image_base + 0x414BB08
        runtime.memory.store(values[1], table, 8, source='1D27507.module_callback_copy_vtable')
        return table
    if rva == 0x1D27510 and len(values) == 1:
        destination = runtime._operator_new(16)
        runtime.memory.store(destination, runtime.image_base + 0x414BB08, 8,
                             source='1D27525.module_callback_clone_vtable')
        return destination
    if rva == 0x1D27530 and len(values) == 5:
        success = runtime.memory.load(values[3], 1)
        return log(runtime, _SOURCE_FILE, 296 if success else 293,
                   b'dylib whitelist report success' if success else b'report bad dylib failed',
                   _TAG, 2)
    raise InputError('module report callback source interface argument count mismatch')
