/* A return-only execution diagnostic. x0 carries the challenge and response;
 * no stack, memory, firmware services or writable storage are touched. This
 * is a probe-specific ABI, not nlr_app_main's API-table calling convention. */
.text
.p2align 2
.global nlr_return_probe
.type nlr_return_probe, %function
nlr_return_probe:
    ror x0, x0, #17
    eor x0, x0, x0, lsl #13
    add x0, x0, #0x311
    ret
.size nlr_return_probe, .-nlr_return_probe
