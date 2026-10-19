/* Argument-preserving trampoline: the retargeted init-tail branch lands
 * here, the body fills the entry-row text slot, and execution tail-branches
 * to the original callee with all argument registers restored. x17 is the
 * standard intra-procedural scratch register and is sacrificed for the
 * branch target loaded from the injected table (offset 0x48, guarded by a
 * static assert in nlr/menu.h). */

/* ELF keeps undecorated symbol names; Mach-O prefixes them with an
 * underscore. The host behaviour test builds this file for Mach-O, the
 * package build for ELF. */
#ifdef __MACH__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

.text
.p2align 2
.global SYM(nlr_menu_prefill_trampoline)
#ifndef __MACH__
.type SYM(nlr_menu_prefill_trampoline), %function
#endif
SYM(nlr_menu_prefill_trampoline):
    stp x29, x30, [sp, #-0xB0]!
    stp x0, x1, [sp, #0x10]
    stp x2, x3, [sp, #0x20]
    stp x4, x5, [sp, #0x30]
    stp x6, x7, [sp, #0x40]
    stp x8, x9, [sp, #0x50]
    stp x10, x11, [sp, #0x60]
    stp x12, x13, [sp, #0x70]
    stp x14, x15, [sp, #0x80]
    stp x16, x17, [sp, #0x90]
    bl SYM(nlr_menu_prefill_body)
    ldp x0, x1, [sp, #0x10]
    ldp x2, x3, [sp, #0x20]
    ldp x4, x5, [sp, #0x30]
    ldp x6, x7, [sp, #0x40]
    ldp x8, x9, [sp, #0x50]
    ldp x10, x11, [sp, #0x60]
    ldp x12, x13, [sp, #0x70]
    ldp x14, x15, [sp, #0x80]
    ldp x16, x17, [sp, #0x90]
    /* The pair must form the FIELD address nlr_menu_prefill + 0x48. Giving
     * the ADRP the same addend makes the linker compute the field's page
     * (it may differ from the symbol's page when the struct sits near a
     * 4 KiB boundary); the low-bits relocation supplies the rest. Assuming
     * the struct itself is page-aligned would read a neighbouring field
     * and tail-branch into unrelated code. Syntax differs per object
     * format: Mach-O uses @PAGE/@PAGEOFF, ELF uses :lo12:. */
#ifdef __MACH__
    adrp x17, SYM(nlr_menu_prefill)+0x48@PAGE
    ldr x17, [x17, #SYM(nlr_menu_prefill)+0x48@PAGEOFF]
#else
    adrp x17, SYM(nlr_menu_prefill)+0x48
    ldr x17, [x17, #:lo12:SYM(nlr_menu_prefill)+0x48]
#endif
    ldp x29, x30, [sp], #0xB0
    br x17
#ifndef __MACH__
.size SYM(nlr_menu_prefill_trampoline), .-SYM(nlr_menu_prefill_trampoline)
#endif
