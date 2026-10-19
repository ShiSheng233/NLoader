#ifndef NLR_TEST_TARGET_H
#define NLR_TEST_TARGET_H

/* The piece of Z 8 C3.11 firmware these fixtures patch.
 *
 * 0x40266fe8 is `ADD X0, X0, #1; RET`, from the same family of dispatch
 * thunks as the Z 6III target, and nothing in the image refers to it: no
 * branch, no ADRP/ADD pair and no 64-bit pointer names it or the word eight
 * bytes after it. Calling it is the fixture's own business and patching it
 * changes nothing the camera does.
 *
 * It satisfies what the channel asks of a hook target: the sixteen bytes
 * from it lie in one cache line (0x40266fe8 & 63 == 40), the detour's
 * literal at +8 is eight-byte aligned, it is inside the declared code
 * window, and its four instructions are position-independent.
 *
 * The four words are what the loader is told to expect, so a build whose
 * firmware does not hold them is refused instead of patched. */
#define NLR_TEST_TARGET 0x40266fe8UL

#define NLR_TEST_W0 0x91000400u /* ADD X0, X0, #1          */
#define NLR_TEST_W1 0xd65f03c0u /* RET                     */
#define NLR_TEST_W2 0xd29ff008u /* MOV X8, #0xff80         */
#define NLR_TEST_W3 0x79c00009u /* LDRSH W9, [X0]          */

#define NLR_TEST_PLAIN   2u
#define NLR_TEST_REPLACE 0x4242u
#define NLR_TEST_LEFT    0x5151u

static const unsigned char nlr_test_expect[16] = {
    0x00, 0x04, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    0x08, 0xf0, 0x9f, 0xd2, 0x09, 0x00, 0xc0, 0x79,
};

static inline uint64_t nlr_test_call(uint64_t value)
{
    uint64_t (*target)(uint64_t) = (uint64_t (*)(uint64_t))NLR_TEST_TARGET;
    return target(value);
}

#endif
