#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "primary_worker_bridge.h"
#if !defined(_M_AMD64) || defined(_M_ARM64EC)
#error AMD64 required
#endif
#define ASSERT_OFFSET(f, n) _Static_assert(offsetof(PWBRIDGE_LAUNCH, f) == n, #f)
_Static_assert(sizeof(void *) == 8 && sizeof(DWORD) == 4, "native widths");
_Static_assert(sizeof(PWBRIDGE_LAUNCH) == 80, "launch size");
ASSERT_OFFSET(dispatch, 8);
ASSERT_OFFSET(token, 16);
ASSERT_OFFSET(module, 24);
ASSERT_OFFSET(action, 32);
ASSERT_OFFSET(host_status, 40);
ASSERT_OFFSET(callback_result, 48);
ASSERT_OFFSET(process_id, 56);
ASSERT_OFFSET(marker, 64);
ASSERT_OFFSET(cookie, 72);
typedef uint32_t (WINAPI *PWBRIDGE_DISPATCH)(uint64_t, PWBRIDGE_LAUNCH *);

uint32_t __cdecl pwbridge_record_size_v1(void) { return (uint32_t)sizeof(PWBRIDGE_LAUNCH); }
uint32_t __cdecl pwbridge_abi_version_v1(void) { return PWBRIDGE_ABI; }
__declspec(noinline) uint32_t __stdcall pwbridge_module_marker_v1(void) { return PWBRIDGE_ABI; }

DWORD WINAPI pwbridge_thread_entry_v1(void *argument) {
    PWBRIDGE_LAUNCH *record = (PWBRIDGE_LAUNCH *)argument;
    HMODULE own_module = NULL, module;
    uint32_t action, code, status;
    uint64_t dispatch, token;
    if (!record) return PWBRIDGE_HOST_FAILURE;
    if (record->abi_version != PWBRIDGE_ABI || record->size != sizeof(PWBRIDGE_LAUNCH) ||
        record->cookie != PWBRIDGE_COOKIE || !record->dispatch || !record->token ||
        record->process_id != GetCurrentProcessId() ||
        record->marker != (uint64_t)(uintptr_t)&pwbridge_module_marker_v1 ||
        record->state != 0 || record->action != PWBRIDGE_RETURN || record->host_status != 0) {
        record->host_status = 1;
        record->win32_error = ERROR_INVALID_PARAMETER;
        record->state = 4;
        return PWBRIDGE_HOST_FAILURE;
    }
    dispatch = record->dispatch;
    token = record->token;
    record->thread_id = GetCurrentThreadId();
    record->state = 1;
    status = ((PWBRIDGE_DISPATCH)(uintptr_t)record->dispatch)(record->token, record);
    record->callback_result = status;
    record->state = 2;
    if (record->abi_version != PWBRIDGE_ABI || record->size != sizeof(PWBRIDGE_LAUNCH) ||
        record->cookie != PWBRIDGE_COOKIE || record->dispatch != dispatch || record->token != token ||
        record->process_id != GetCurrentProcessId() || record->thread_id != GetCurrentThreadId() ||
        record->marker != (uint64_t)(uintptr_t)&pwbridge_module_marker_v1) {
        record->host_status = 1;
        record->win32_error = ERROR_INVALID_PARAMETER;
        return PWBRIDGE_HOST_FAILURE;
    }
    if (status || record->host_status) {
        record->host_status = record->host_status ? record->host_status : 2;
        return PWBRIDGE_HOST_FAILURE;
    }
    action = record->action;
    code = record->exit_code;
    module = (HMODULE)(uintptr_t)record->module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)(uintptr_t)&pwbridge_module_marker_v1, &own_module)) {
        record->win32_error = GetLastError();
        record->host_status = 3;
        return PWBRIDGE_HOST_FAILURE;
    }
    if (action > PWBRIDGE_FREE_LIBRARY_EXIT ||
        (action == PWBRIDGE_EXIT_THREAD && module) ||
        (action == PWBRIDGE_FREE_LIBRARY_EXIT && module != own_module)) {
        record->host_status = 3;
        record->win32_error = ERROR_INVALID_PARAMETER;
        return PWBRIDGE_HOST_FAILURE;
    }
    record->state = 3;
    if (action == PWBRIDGE_FREE_LIBRARY_EXIT) FreeLibraryAndExitThread(module, code);
    if (action == PWBRIDGE_EXIT_THREAD) ExitThread(code);
    record->state = 5;
    return code;
}
