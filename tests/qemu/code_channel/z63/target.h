#ifndef NLR_TEST_TARGET_H
#define NLR_TEST_TARGET_H

/* The piece of Z 6III 2.00 firmware these fixtures patch.
 *
 * 0x40263cb0 is `ADD X0, X0, #1; RET`, and nothing in the image refers to
 * it: it is one of a family of dispatch thunks the compiler emitted and
 * nothing reached (no cross-reference to it or to its neighbour at
 * 0x40263cb8, which is dead the same way). So calling it is the fixture's
 * own business, patching it changes nothing the camera does, and a mistake
 * here cannot break a path the firmware uses.
 *
 * It also satisfies what the channel asks of a hook target: the sixteen
 * bytes from it end exactly on the cache line (0x40263cb0 & 63 == 48), it
 * is inside the declared code window, and its four instructions are
 * position-independent, so a continuation can run them from the program's
 * own image.
 *
 * The four words are what the loader is told to expect, so a build whose
 * firmware does not hold them is refused instead of patched. */
#define NLR_TEST_TARGET 0x40263cb0UL

#define NLR_TEST_W0 0x91000400u /* ADD X0, X0, #1          */
#define NLR_TEST_W1 0xd65f03c0u /* RET                     */
#define NLR_TEST_W2 0xd29a6a08u /* MOV X8, #0xd350         */
#define NLR_TEST_W3 0x79c00009u /* LDRSH W9, [X0]          */

/* What the target returns for 1, what the fixtures' replacing handler
 * returns instead, and what the hook a run leaves behind on purpose
 * returns -- seeing that one at the start of a later run would mean a
 * handler in freed memory was still in the camera's code. */
#define NLR_TEST_PLAIN   2u
#define NLR_TEST_REPLACE 0x4242u
#define NLR_TEST_LEFT    0x5151u

static const unsigned char nlr_test_expect[16] = {
    0x00, 0x04, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    0x08, 0x6a, 0x9a, 0xd2, 0x09, 0x00, 0xc0, 0x79,
};

/* The target as a function: it adds one to its argument. */
static inline uint64_t nlr_test_call(uint64_t value)
{
    uint64_t (*target)(uint64_t) = (uint64_t (*)(uint64_t))NLR_TEST_TARGET;
    return target(value);
}

#endif
