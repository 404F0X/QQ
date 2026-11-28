#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include "primary_caller_bridge.h"
#if !defined(_M_AMD64) || defined(_M_ARM64EC)
#error AMD64 required
#endif
#define ASSERT_OFFSET(t, f, n) _Static_assert(offsetof(t, f) == n, #f)
_Static_assert(sizeof(void *) == 8, "pointer");
_Static_assert(sizeof(CONTEXT) == 1232, "CONTEXT");
_Static_assert(__alignof(CONTEXT) == 16, "CONTEXT alignment");
_Static_assert(sizeof(DWORD) == 4 && sizeof(LONG) == 4 && sizeof(int) == 4, "32 bits");
_Static_assert(sizeof(WORD) == 2 && sizeof(DWORD64) == 8 && sizeof(BOOL) == 4, "widths");
ASSERT_OFFSET(CONTEXT, Rip, 248);
ASSERT_OFFSET(CONTEXT, Rsp, 152);
_Static_assert(sizeof(PCBRIDGE_STEP) == 2528, "step");
_Static_assert(sizeof(PCBRIDGE_WIRE) == 8904, "wire");
ASSERT_OFFSET(PCBRIDGE_STEP, status, 0);
ASSERT_OFFSET(PCBRIDGE_STEP, exception_code, 4);
ASSERT_OFFSET(PCBRIDGE_STEP, reserved0, 8);
ASSERT_OFFSET(PCBRIDGE_STEP, reserved1, 12);
ASSERT_OFFSET(PCBRIDGE_STEP, pc, 16);
ASSERT_OFFSET(PCBRIDGE_STEP, entry, 24);
ASSERT_OFFSET(PCBRIDGE_STEP, image_base, 32);
ASSERT_OFFSET(PCBRIDGE_STEP, unwind_result, 40);
ASSERT_OFFSET(PCBRIDGE_STEP, handler_data, 48);
ASSERT_OFFSET(PCBRIDGE_STEP, establisher_frame, 56);
ASSERT_OFFSET(PCBRIDGE_STEP, before, 64);
ASSERT_OFFSET(PCBRIDGE_STEP, after, 1296);
ASSERT_OFFSET(PCBRIDGE_WIRE, abi_version, 0);
ASSERT_OFFSET(PCBRIDGE_WIRE, size, 4);
ASSERT_OFFSET(PCBRIDGE_WIRE, header_status, 8);
ASSERT_OFFSET(PCBRIDGE_WIRE, win32_error, 12);
ASSERT_OFFSET(PCBRIDGE_WIRE, process_id, 16);
ASSERT_OFFSET(PCBRIDGE_WIRE, thread_id, 20);
ASSERT_OFFSET(PCBRIDGE_WIRE, step_count, 24);
ASSERT_OFFSET(PCBRIDGE_WIRE, frame_count, 28);
ASSERT_OFFSET(PCBRIDGE_WIRE, sequence, 32);
ASSERT_OFFSET(PCBRIDGE_WIRE, capture_export, 40);
ASSERT_OFFSET(PCBRIDGE_WIRE, capture_site, 48);
ASSERT_OFFSET(PCBRIDGE_WIRE, stack_low, 56);
ASSERT_OFFSET(PCBRIDGE_WIRE, stack_high, 64);
ASSERT_OFFSET(PCBRIDGE_WIRE, frames, 72);
ASSERT_OFFSET(PCBRIDGE_WIRE, initial_context, 88);
ASSERT_OFFSET(PCBRIDGE_WIRE, steps, 1320);
typedef WORD (NTAPI *CAPTURE_BACKTRACE)(DWORD, DWORD, PVOID *, PDWORD);
static volatile LONG64 sequence_number;

__declspec(noinline) static void capture_active(uint32_t flag, PCBRIDGE_WIRE *wire) {
    CONTEXT initial, working;
    HMODULE ntdll;
    CAPTURE_BACKTRACE backtrace;
    PVOID frames[2] = {0};
    ULONG_PTR low, high;
    unsigned int i;
    memset(&initial, 0, sizeof(initial));
    memset(&working, 0, sizeof(working));
    ntdll = GetModuleHandleW(L"ntdll.dll");
    backtrace = ntdll ? (CAPTURE_BACKTRACE)(void *)GetProcAddress(ntdll, "RtlCaptureStackBackTrace") : NULL;
    wire->capture_export = (uint64_t)(uintptr_t)backtrace;
    wire->capture_site = (uint64_t)(uintptr_t)&capture_active;
    GetCurrentThreadStackLimits(&low, &high);
    wire->stack_low = (uint64_t)low;
    wire->stack_high = (uint64_t)high;
    __try {
        if (flag) {
            if (!backtrace) {
                wire->header_status = 3;
                wire->win32_error = GetLastError();
                return;
            }
            wire->frame_count = backtrace(0, 2, frames, NULL);
            wire->frames[0] = (uint64_t)(uintptr_t)frames[0];
            wire->frames[1] = (uint64_t)(uintptr_t)frames[1];
        }
        RtlCaptureContext(&initial);
        memcpy(wire->initial_context, &initial, sizeof(initial));
        memcpy(&working, &initial, sizeof(working));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wire->header_status = 3;
        wire->win32_error = GetExceptionCode();
        return;
    }
    for (i = 0; i < 3; ++i) {
        PCBRIDGE_STEP *step = &wire->steps[i];
        DWORD64 image = 0, establisher = 0;
        PVOID handler_data = NULL;
        PRUNTIME_FUNCTION entry = NULL;
        PEXCEPTION_ROUTINE handler;
        wire->step_count = i + 1;
        step->pc = working.Rip;
        memcpy(step->before, &working, sizeof(working));
        __try {
            entry = RtlLookupFunctionEntry(working.Rip, &image, NULL);
            step->entry = (uint64_t)(uintptr_t)entry;
            if (!entry) {
                step->status = 1;
                break;
            }
            step->image_base = image;
            handler = RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, working.Rip, entry,
                                      &working, &handler_data, &establisher, NULL);
            memcpy(step->after, &working, sizeof(working));
            step->unwind_result = (uint64_t)(uintptr_t)handler;
            step->handler_data = (uint64_t)(uintptr_t)handler_data;
            step->establisher_frame = establisher;
            step->status = 2;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            step->status = 3;
            step->exception_code = GetExceptionCode();
            memset(step->after, 0, sizeof(step->after));
            step->unwind_result = 0;
            step->handler_data = 0;
            step->establisher_frame = 0;
            break;
        }
    }
}

uint32_t __cdecl pcbridge_capture_v1(uint32_t flag, void *output, uint32_t output_size) {
    PCBRIDGE_WIRE *wire;
    if (!output || output_size != sizeof(PCBRIDGE_WIRE)) return 1;
    wire = (PCBRIDGE_WIRE *)output;
    memset(wire, 0, sizeof(*wire));
    wire->abi_version = 1;
    wire->size = sizeof(*wire);
    if (flag > 1) return wire->header_status = 1;
    wire->process_id = GetCurrentProcessId();
    wire->thread_id = GetCurrentThreadId();
    wire->sequence = (uint64_t)InterlockedIncrement64(&sequence_number);
    capture_active(flag, wire);
    return wire->header_status;
}
