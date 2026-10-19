/* Program entry for general NPLD v2 programs (PLAN 6.4). The loader calls
 * the file entry with x0 = struct nlr_api *, and the build-time program
 * type selects which SDK entry receives it: -DNLR_PROGRAM_FOREGROUND for
 * foreground programs, -DNLR_PROGRAM_EXTENSION for resource extensions.
 *
 * Position-independent: every reference below resolves inside the program
 * image (the branch target is another object of the same program), and no
 * firmware address is ever named. The branch is a tail call, so the SDK
 * entry's return value in x0 becomes the program's return value to the
 * loader.
 */

    .text
    .globl _start
    .type _start, %function
_start:
#if defined(NLR_PROGRAM_FOREGROUND) == defined(NLR_PROGRAM_EXTENSION)
#error "select exactly one program type: NLR_PROGRAM_FOREGROUND or NLR_PROGRAM_EXTENSION"
#endif
#ifdef NLR_PROGRAM_FOREGROUND
    b nlr_app_main
#endif
#ifdef NLR_PROGRAM_EXTENSION
    b nlr_extension_init
#endif
    .size _start, .-_start