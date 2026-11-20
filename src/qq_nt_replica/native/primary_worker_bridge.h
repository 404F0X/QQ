#ifndef PRIMARY_WORKER_BRIDGE_H
#define PRIMARY_WORKER_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#pragma pack(push, 8)
typedef struct {
    uint32_t abi_version, size;
    uint64_t dispatch, token, module;
    uint32_t action, exit_code, host_status, state;
    uint32_t callback_result, win32_error, process_id, thread_id;
    uint64_t marker, cookie;
} PWBRIDGE_LAUNCH;
#pragma pack(pop)
#define PWBRIDGE_ABI 1u
#define PWBRIDGE_COOKIE UINT64_C(0x5057425249444731)
#define PWBRIDGE_HOST_FAILURE 0xE0001046u
#define PWBRIDGE_RETURN 0u
#define PWBRIDGE_EXIT_THREAD 1u
#define PWBRIDGE_FREE_LIBRARY_EXIT 2u
__declspec(dllexport) uint32_t __cdecl pwbridge_record_size_v1(void);
__declspec(dllexport) uint32_t __cdecl pwbridge_abi_version_v1(void);
__declspec(dllexport) uint32_t __stdcall pwbridge_module_marker_v1(void);
__declspec(dllexport) unsigned long __stdcall pwbridge_thread_entry_v1(void *argument);
#endif
