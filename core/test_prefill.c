/* Host behavior test for the prefill trampoline. The host is arm64, so the
 * real trampoline and body run natively against a mock stock callee: the
 * test drives the trampoline with distinctive argument registers, checks
 * that the callee received them unchanged (except the documented x17
 * scratch), that the body delegates to the original text writer exactly
 * once without replacing its results, and that execution continued at
 * the original call site.
 *
 * The injected struct is deliberately placed MID-PAGE (0x100 bytes into a
 * 4 KiB-aligned container) through an assembler alias. A trampoline that
 * only forms the page base of the struct plus a fixed field offset would
 * read a neighbouring field here and branch into unrelated code; the alias
 * makes that failure observable instead of masked by a page-aligned
 * placement. */
#include "nlr/menu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DESCRIPTOR_STRIDE 0x18u
#define DESCRIPTOR_SLOTS 300u
#define TEST_SLOT 299u
#define TEST_STYLE 4u

static const char label_text[] = "NLoader";

#define BUFFER_STRIDE 0x33u
static _Alignas(8) uint8_t descriptors[DESCRIPTOR_SLOTS * DESCRIPTOR_STRIDE];
static _Alignas(8) uint8_t slot_buffers[DESCRIPTOR_SLOTS * BUFFER_STRIDE];
static _Alignas(8) uint8_t font_cache[16 * 0x10];
static _Alignas(8) uint8_t font_records[16 * 0x10];

static unsigned long captured[18];
static int failures;
static unsigned text_store_calls;
static uint8_t expected_descriptor[DESCRIPTOR_STRIDE];
static uint8_t expected_buffer[BUFFER_STRIDE];
static uint8_t expected_font_cache[0x10];

#define CHECK(cond)                                   \
    do {                                              \
        if (!(cond)) {                                \
            printf("FAIL %d: %s\n", __LINE__, #cond); \
            failures++;                               \
        }                                             \
    } while (0)

/* The struct lives 0x100 bytes into a page-aligned container. The alias
 * gives the trampoline's adrp/ldr pair the member's address; the C code
 * sees the same address through the extern declaration. */
static _Alignas(4096) struct {
    char pad[0x100];
    struct nlr_menu_prefill prefill;
} prefill_container;

__asm__(".globl _nlr_menu_prefill\n"
        ".set _nlr_menu_prefill, _prefill_container+256\n");
extern const struct nlr_menu_prefill nlr_menu_prefill;

/* This mock checks the delegation contract, not the vendor's text format.
 * Distinct output markers expose any manual descriptor, buffer or font
 * writes performed by the core after the vendor writer returns. */
static void mock_text_store(const char *text, uint32_t slot, uint32_t style)
{
    text_store_calls++;
    CHECK(text_store_calls == 1);
    CHECK(text == label_text);
    CHECK(slot == TEST_SLOT);
    CHECK(style == TEST_STYLE);

    uint8_t *descriptor = descriptors + (size_t)TEST_SLOT * DESCRIPTOR_STRIDE;
    uint8_t *buffer = slot_buffers + (size_t)TEST_SLOT * BUFFER_STRIDE;
    uint8_t *cache = font_cache + TEST_STYLE * 0x10;
    uint64_t buffer_pointer = 0;
    memcpy(&buffer_pointer, descriptor + 8, sizeof buffer_pointer);
    CHECK(buffer_pointer == (uint64_t)(uintptr_t)buffer);
    /* The stock initializer has supplied the buffer pointer; no other
     * prefill writes may precede the writer call. */
    uint8_t initialized_descriptor[DESCRIPTOR_STRIDE] = {0};
    memcpy(initialized_descriptor + 8, &buffer_pointer, sizeof buffer_pointer);
    CHECK(memcmp(descriptor, initialized_descriptor, DESCRIPTOR_STRIDE) == 0);
    uint8_t empty_buffer[BUFFER_STRIDE] = {0};
    uint8_t empty_cache[0x10] = {0};
    CHECK(memcmp(buffer, empty_buffer, BUFFER_STRIDE) == 0);
    CHECK(memcmp(cache, empty_cache, sizeof empty_cache) == 0);

    memset(expected_descriptor, 0xd3, sizeof expected_descriptor);
    memcpy(expected_descriptor + 8, &buffer_pointer, sizeof buffer_pointer);
    memset(expected_buffer, 0xb7, sizeof expected_buffer);
    memset(expected_font_cache, 0xf1, sizeof expected_font_cache);
    memcpy(descriptor, expected_descriptor, sizeof expected_descriptor);
    memcpy(buffer, expected_buffer, sizeof expected_buffer);
    memcpy(cache, expected_font_cache, sizeof expected_font_cache);
}

/* Naked mock of the original callee: captures x0-x17 (all of them, not only
 * the ABI argument registers, because the trampoline promises full
 * preservation) and returns to the trampoline's restored link register. */
__attribute__((naked)) static void mock_stock_callee(void)
{
    __asm__ volatile("adrp x19, _captured@PAGE\n\t"
                     "add x19, x19, _captured@PAGEOFF\n\t"
                     "stp x0, x1, [x19]\n\t"
                     "stp x2, x3, [x19, #16]\n\t"
                     "stp x4, x5, [x19, #32]\n\t"
                     "stp x6, x7, [x19, #48]\n\t"
                     "stp x8, x9, [x19, #64]\n\t"
                     "stp x10, x11, [x19, #80]\n\t"
                     "stp x12, x13, [x19, #96]\n\t"
                     "stp x14, x15, [x19, #112]\n\t"
                     "stp x16, x17, [x19, #128]\n\t"
                     "ret\n\t");
}

int main(void)
{
    /* Distinctive per-register values, including the caller-saved pair the
     * trampoline must hand back untouched. */
    unsigned long args[18];
    for (unsigned n = 0; n < 18; n++)
        args[n] = 0x11110000u + n * 7;

    font_records[TEST_STYLE * 0x10] = 0x5au;
    font_records[TEST_STYLE * 0x10 + 0xf] = 0xa5u;
    memset(font_cache, 0, sizeof font_cache);
    memset(descriptors, 0, sizeof descriptors);
    memset(slot_buffers, 0, sizeof slot_buffers);
    /* Mirror the original initialization that runs before the hook. */
    uint64_t initial_buffer =
        (uint64_t)(uintptr_t)(slot_buffers + (size_t)TEST_SLOT * BUFFER_STRIDE);
    memcpy(descriptors + (size_t)TEST_SLOT * DESCRIPTOR_STRIDE + 8,
           &initial_buffer, sizeof initial_buffer);

    struct nlr_menu_prefill *p = &prefill_container.prefill;
    p->descriptor_base = (uint64_t)(uintptr_t)descriptors;
    p->slot_stride = DESCRIPTOR_STRIDE;
    p->buffer_base = (uint64_t)(uintptr_t)slot_buffers;
    p->buffer_stride = BUFFER_STRIDE;
    p->font_cache_base = (uint64_t)(uintptr_t)font_cache;
    p->font_record_base = (uint64_t)(uintptr_t)font_records;
    p->entry_slot = TEST_SLOT;
    p->entry_style = TEST_STYLE;
    p->text = label_text;
    p->prefill_call_site = 0;
    p->return_target = (uint64_t)(uintptr_t)mock_stock_callee;
    p->text_store = mock_text_store;

    CHECK(((uintptr_t)&nlr_menu_prefill & 0xFFF) == 0x100); /* mid-page held */

    /* Explicit register variables pin each argument to its register; the
     * outputs read the registers back after the round trip. x17 is the
     * documented intra-procedural scratch: the callee receives the branch
     * target in it, so only x0-x16 are asserted unchanged after the call. */
    register unsigned long r0 asm("x0") = args[0];
    register unsigned long r1 asm("x1") = args[1];
    register unsigned long r2 asm("x2") = args[2];
    register unsigned long r3 asm("x3") = args[3];
    register unsigned long r4 asm("x4") = args[4];
    register unsigned long r5 asm("x5") = args[5];
    register unsigned long r6 asm("x6") = args[6];
    register unsigned long r7 asm("x7") = args[7];
    register unsigned long r8 asm("x8") = args[8];
    register unsigned long r9 asm("x9") = args[9];
    register unsigned long r10 asm("x10") = args[10];
    register unsigned long r11 asm("x11") = args[11];
    register unsigned long r12 asm("x12") = args[12];
    register unsigned long r13 asm("x13") = args[13];
    register unsigned long r14 asm("x14") = args[14];
    register unsigned long r15 asm("x15") = args[15];
    register unsigned long r16 asm("x16") = args[16];
    register unsigned long r17 asm("x17") = args[17];
    __asm__ volatile("bl _nlr_menu_prefill_trampoline"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4),
                       "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9),
                       "+r"(r10), "+r"(r11), "+r"(r12), "+r"(r13), "+r"(r14),
                       "+r"(r15), "+r"(r16), "+r"(r17)
                     :
                     : "x19", "lr", "memory", "cc");

    /* Reaching this line means the trampoline returned through the mock
     * callee using the restored link register. x0-x16 must arrive
     * unchanged; x17 is the intra-procedural scratch the trampoline loads
     * the tail-branch target into, so the callee observes exactly the
     * configured return target — the proof that the field address was
     * formed from the full location rather than the page base. */
    for (unsigned n = 0; n < 17; n++)
        CHECK(captured[n] == args[n]);
    CHECK(captured[17] == (unsigned long)(uintptr_t)mock_stock_callee);
    CHECK(r0 == args[0]);
    CHECK(r1 == args[1]);
    CHECK(r2 == args[2]);
    CHECK(r3 == args[3]);
    CHECK(r4 == args[4]);
    CHECK(r5 == args[5]);
    CHECK(r6 == args[6]);
    CHECK(r7 == args[7]);
    CHECK(r8 == args[8]);
    CHECK(r9 == args[9]);
    CHECK(r10 == args[10]);
    CHECK(r11 == args[11]);
    CHECK(r12 == args[12]);
    CHECK(r13 == args[13]);
    CHECK(r14 == args[14]);
    CHECK(r15 == args[15]);
    CHECK(r16 == args[16]); /* x17 is the documented sacrifice */

    const uint8_t *descriptor =
        descriptors + (size_t)TEST_SLOT * DESCRIPTOR_STRIDE;
    const uint8_t *slot_buffer =
        slot_buffers + (size_t)TEST_SLOT * BUFFER_STRIDE;
    CHECK(text_store_calls == 1);
    CHECK(memcmp(descriptor, expected_descriptor, sizeof expected_descriptor) == 0);
    CHECK(memcmp(slot_buffer, expected_buffer, sizeof expected_buffer) == 0);
    CHECK(memcmp(font_cache + TEST_STYLE * 0x10, expected_font_cache,
                 sizeof expected_font_cache) == 0);
    /* Other descriptors stay untouched. */
    CHECK(descriptors[0] == 0 && descriptors[0x18] == 0);
    CHECK(font_records[TEST_STYLE * 0x10] == 0x5au);
    CHECK(font_records[TEST_STYLE * 0x10 + 0xf] == 0xa5u);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("prefill trampoline tests passed\n");
    return 0;
}
