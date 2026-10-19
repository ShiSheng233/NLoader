/* Worker-frame context save and restore for generic program runs.

 * api->exit must leave the application without returning into it (PLAN 5.1)
 * and resume in nlr_program_run's frame. The freestanding aarch64-none-elf
 * build has no <setjmp.h> and clang rejects __builtin_setjmp for this
 * target, so the context is saved explicitly. This is a normal
 * returns-twice pair, not a libc setjmp: nlr_program_run calls
 * nlr_program_setjmp once and nlr_program_longjmp (from api.c's exit
 * wrapper, while the program is on the stack) resumes that same return
 * point with value 1.
 *
 * Saved per AAPCS64: x19-x28, frame pointer, return address, stack pointer
 * and d8-d15. x18 is not saved: the bare aarch64-none-elf toolchain used
 * for these programs allocates it as a call-clobbered temporary. This
 * same-worker call boundary is separate from the original operating
 * system's full register save and restore during task switches.
 *
 * Context layout (8-byte words): 0-9 x19..x28, 10 x29, 11 x30, 12 sp,
 * 13-20 d8-d15; NLR_CONTEXT_SLOTS pads to 24 words. */

/* ELF keeps undecorated symbol names; Mach-O prefixes them with an
 * underscore. The host behaviour test builds this file for Mach-O, the
 * package build for ELF. */
#ifdef __MACH__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

#ifndef __has_feature
#define __has_feature(feature) 0
#endif

.text
.p2align 2
.global SYM(nlr_program_setjmp)
#ifndef __MACH__
.type SYM(nlr_program_setjmp), %function
#endif
SYM(nlr_program_setjmp):
    stp x19, x20, [x0, #0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x16, sp
    str x16, [x0, #96]
    stp d8, d9, [x0, #104]
    stp d10, d11, [x0, #120]
    stp d12, d13, [x0, #136]
    stp d14, d15, [x0, #152]
    mov x0, xzr
    ret
#ifndef __MACH__
.size SYM(nlr_program_setjmp), .-SYM(nlr_program_setjmp)
#endif

.global SYM(nlr_program_longjmp)
#ifndef __MACH__
.type SYM(nlr_program_longjmp), %function
#endif
SYM(nlr_program_longjmp):
#if __has_feature(address_sanitizer)
    /* Host ASan must retire the abandoned frames before this explicit stack
     * restore, just as its libc longjmp interceptor does. Firmware has no
     * sanitizer and emits none of these instructions. */
    stp x0, x1, [sp, #-16]!
    bl SYM(__asan_handle_no_return)
    ldp x0, x1, [sp], #16
#endif
    mov x17, x1
    ldp x19, x20, [x0, #0]
    ldp x21, x22, [x0, #16]
    ldp x23, x24, [x0, #32]
    ldp x25, x26, [x0, #48]
    ldp x27, x28, [x0, #64]
    ldr x29, [x0, #80]
    ldp d8, d9, [x0, #104]
    ldp d10, d11, [x0, #120]
    ldp d12, d13, [x0, #136]
    ldp d14, d15, [x0, #152]
    ldr x16, [x0, #96]
    mov sp, x16
    ldr x30, [x0, #88]
    mov x0, x17
    ret
#ifndef __MACH__
.size SYM(nlr_program_longjmp), .-SYM(nlr_program_longjmp)
#endif
