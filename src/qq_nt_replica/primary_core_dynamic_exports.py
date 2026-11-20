DYNAMIC_EXPORTS = (
    dict(library='ntdll.dll', export='RtlCaptureStackBackTrace', handler_key='RtlCaptureStackBackTrace',
         supported=True, result_signed=False, result_width=16, argument_widths=(32, 32, 64, 64),
         argument_kinds=('uint', 'uint', 'output', 'nullable_pointer'), call_path='prepare_only',
         effects='frame_count_0_to_4; output32; returned_frames_and_changed_bytes', argument_domain=(0, 4, 0)),
    dict(library='kernel32.dll', export='GetModuleFileNameA', handler_key='GetModuleFileNameA',
         supported=True, result_signed=False, result_width=32, argument_widths=(64, 64, 32),
         argument_kinds=('observed_module_or_zero', 'output', 'uint'), call_path='nativecall',
         effects='capacity_1_to_520; count_plus_nul_on_nontruncated_success_and_changed_bytes', argument_domain=(1, 520)),
    dict(library='user32.dll', export='GetCursorPos', handler_key='GetCursorPos',
         supported=True, result_signed=False, result_width=32, argument_widths=(64,), argument_kinds=('output',),
         call_path='nativecall', effects='output8; success_all_else_changed_bytes', argument_domain=()),
    dict(library='user32.dll', export='FindWindowA', handler_key='FindWindowA',
         supported=True, result_signed=False, result_width=64, argument_widths=(64, 64),
         argument_kinds=('nullable_cstr', 'nullable_cstr'), call_path='nativecall',
         effects='borrowed_hwnd_or_zero; no_writes',
         argument_domain=((b'Chrome_WidgetWin_1', b'QQ'), (b'WTWindow', None), (b'_EL_HideOwner', None))),
    dict(library='common.dll', export='__GetG3Guid', handler_key=None,
         supported=False, result_signed=False, result_width=32, argument_widths=(64,), argument_kinds=('output',),
         call_path='unsupported', effects='caller_prezero16; external_write_bound_and_status_unknown', argument_domain=()),
)


def lookup_export(library, name):
    if isinstance(library, bytes):
        library = library.decode('ascii', errors='replace')
    if isinstance(name, bytes):
        name = name.decode('ascii', errors='replace')
    if not isinstance(library, str) or not isinstance(name, str):
        return None
    return next((row for row in DYNAMIC_EXPORTS
                 if row['library'] == library.lower() and row['export'] == name), None)


def logical_identity(row):
    return {'library': row['library'], 'export': row['export']}
