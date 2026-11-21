#ifndef PRIMARY_CALLER_BRIDGE_H
#define PRIMARY_CALLER_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#pragma pack(push, 8)
typedef struct {
    uint32_t status, exception_code, reserved0, reserved1;
    uint64_t pc, entry, image_base, unwind_result, handler_data, establisher_frame;
    uint8_t before[1232], after[1232];
} PCBRIDGE_STEP;
typedef struct {
    uint32_t abi_version, size, header_status, win32_error;
    uint32_t process_id, thread_id, step_count, frame_count;
    uint64_t sequence, capture_export, capture_site, stack_low, stack_high;
    uint64_t frames[2];
    uint8_t initial_context[1232];
    PCBRIDGE_STEP steps[3];
} PCBRIDGE_WIRE;
#pragma pack(pop)
__declspec(dllexport) uint32_t __cdecl pcbridge_capture_v1(uint32_t capture_backtrace, void *output, uint32_t output_size);
#endif
