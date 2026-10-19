#include "nlr/exec.h"
#include "nlr/runtime.h"

/* The firmware's own code (ABI 4). The camera's text runs from DRAM, and
 * the mapping service keeps a writable alias of those physical pages, so
 * nothing here changes the permissions of a page another core may be
 * executing: a patch translates the code address, writes through the alias,
 * cleans the data cache to the point of coherency and invalidates the
 * instruction cache, which the architecture broadcasts to every core.
 *
 * One patch covers whole instructions inside a single cache line, so the
 * maintenance switches instruction fetch from all the old bytes to all the
 * new ones in one step. A core already executing inside those bytes still
 * finishes the instructions it fetched, which is why a hook on a path the
 * camera runs continuously belongs in a resource extension's load, not in a
 * foreground program. */

/* AArch64 encodings the detour is made of: LDR X16, [PC, #8]; BR X16. */
#define CODE_LDR_X16_PC8 0x58000050u
#define CODE_BR_X16      0xd61f0200u

static uint32_t code_word(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

/* Whole instructions, 4-byte aligned, inside the declared code window and
 * inside one cache line. */
static int code_range_ok(const struct nlr_code_services *cs, uint64_t at,
                         uint32_t len)
{
    if (!len || len > NLR_CODE_PATCH_MAX || (len & 3u) || (at & 3u))
        return 0;
    if (cs->text_hi <= cs->text_lo || at < cs->text_lo ||
        at >= cs->text_hi || len > cs->text_hi - at)
        return 0;
    return (uint32_t)(at & (NLR_CACHE_LINE - 1u)) + len <= NLR_CACHE_LINE;
}

/* The writable alias of a code address: the physical address of its page,
 * which this mapping is the identity of, plus the offset in the page. The
 * alias must lie in the declared band and be mapped writable, and the code
 * address itself must still be mapped executable — anything else means the
 * window does not describe this body and nothing is written. */
static int code_alias(const struct nlr_code_services *cs, uint64_t at,
                      volatile uint32_t **out)
{
    *out = 0;
    uint64_t page = at & ~(uint64_t)(NLR_EXEC_PAGE_SIZE - 1u);
    uint64_t physical = 0;
    if (cs->translate(cs->manager, (uintptr_t)page, &physical) != 0)
        return NLR_IO;
    if (physical < cs->alias_lo || physical >= cs->alias_hi ||
        NLR_EXEC_PAGE_SIZE > cs->alias_hi - physical)
        return NLR_BOUNDS;
    uint64_t alias = physical + (at - page);
    uint32_t flags = 0;
    if (cs->query((void *)(uintptr_t)alias, &flags) != 0 ||
        flags != cs->flag_writable)
        return NLR_IO;
    flags = 0;
    if (cs->query((void *)(uintptr_t)at, &flags) != 0 ||
        flags != cs->flag_executable)
        return NLR_IO;
    /* The alias is what gets cleaned, and the model's D-cache service
     * silently does nothing for an address its own region table calls
     * uncacheable, so the alias must be in it. The code address is not
     * asked: that table describes the DRAM regions, not the window the
     * firmware's text is executed through (the predicate answers "no" for
     * it), and the instruction-cache service needs no such answer. */
    if (cs->cacheable && !cs->cacheable((void *)(uintptr_t)alias))
        return NLR_IO;
    *out = (volatile uint32_t *)(uintptr_t)alias;
    return NLR_OK;
}

int nlr_code_patch(const struct nlr_code_services *cs, uint64_t at,
                   const uint8_t *bytes, uint32_t len)
{
    if (!cs || !cs->translate || !cs->query || !cs->clean || !cs->invalidate ||
        !cs->manager || !cs->flag_writable || !cs->flag_executable ||
        cs->flag_writable == cs->flag_executable)
        return NLR_NOT_READY;
    if (!bytes || !code_range_ok(cs, at, len))
        return NLR_BOUNDS;
    volatile uint32_t *alias = 0;
    int result = code_alias(cs, at, &alias);
    if (result != NLR_OK)
        return result;
    /* One instruction per store: no half-written instruction ever exists in
     * memory, and the whole line reaches instruction fetch together below. */
    for (uint32_t n = 0; n < len; n += 4u)
        alias[n / 4u] = code_word(bytes + n);
    cs->clean((void *)alias, len);
    cs->invalidate((void *)(uintptr_t)at, len);
    return NLR_OK;
}

/* An instruction a handler's continuation could run from somewhere else.
 * The detour overwrites four of them, and a handler that continues into the
 * function it replaced reproduces them in its own image, so a
 * position-dependent one cannot be hooked this way. */
static int instruction_movable(uint32_t w)
{
    if ((w & 0x1f000000u) == 0x10000000u)
        return 0; /* ADR, ADRP */
    if ((w & 0x7c000000u) == 0x14000000u)
        return 0; /* B, BL */
    if ((w & 0xfe000000u) == 0x54000000u)
        return 0; /* B.cond */
    if ((w & 0x7e000000u) == 0x34000000u)
        return 0; /* CBZ, CBNZ */
    if ((w & 0x7e000000u) == 0x36000000u)
        return 0; /* TBZ, TBNZ */
    if ((w & 0x3b000000u) == 0x18000000u)
        return 0; /* LDR, LDRSW, PRFM literal */
    return 1;
}

static uint32_t hook_find(const struct nlr_runtime *r, uint64_t target)
{
    for (uint32_t n = 0; n < NLR_CODE_HOOKS_MAX; n++)
        if (r->hooks.slot[n].target == target)
            return n;
    return NLR_CODE_HOOKS_MAX;
}

static int inside(uint64_t address, const void *base, uint32_t bytes)
{
    uint64_t lo = (uint64_t)(uintptr_t)base;
    return base && bytes && address >= lo && address < lo + bytes;
}

/* The loader-owned code block a handler lives in: the block of the program
 * installing the hook, or a resident extension's. The detour outlives the
 * call that installed it, so a handler anywhere else — the stack, a data
 * block, firmware text, memory this loader does not own at all — is not
 * something whose lifetime the loader can promise, and is refused. A
 * detour into firmware text needs no hook record: that is a patch. */
static int hook_owner(const struct nlr_runtime *r, uint64_t handler,
                      uint64_t *base, uint32_t *bytes)
{
    const struct nlr_program_state *p = &r->load.program;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 2 &&
        inside(handler, p->code_page, p->region_bytes)) {
        *base = (uint64_t)(uintptr_t)p->code_page;
        *bytes = p->region_bytes;
        return 1;
    }
    for (uint32_t n = 0; n < NLR_RESIDENT_MAX; n++) {
        const struct nlr_program_record *rec = &r->resident[n];
        if (!rec->used || !inside(handler, rec->code_block, rec->code_bytes))
            continue;
        *base = (uint64_t)(uintptr_t)rec->code_block;
        *bytes = rec->code_bytes;
        return 1;
    }
    return 0;
}

int nlr_code_hook(struct nlr_runtime *r, uint64_t target, const uint8_t *expect,
                  uint64_t handler)
{
    if (!r || !r->load.svc)
        return NLR_NOT_READY;
    const struct nlr_code_services *cs = r->load.svc->code;
    if (!cs)
        return NLR_NOT_READY;
    if (!expect || !handler || !target ||
        !code_range_ok(cs, target, NLR_CODE_HOOK_BYTES))
        return NLR_BOUNDS;
    /* The handler address is read as one doubleword eight bytes into the
     * detour, so a target that is not 8-byte aligned only works on a body
     * whose profile says unaligned loads are legal there. */
    if ((target & 7u) && !cs->unaligned_literals)
        return NLR_BOUNDS;
    /* Where the branch lands has to be executable code this loader owns,
     * and it has to still be there when the firmware takes the branch. */
    uint64_t owner_base = 0;
    uint32_t owner_bytes = 0;
    uint32_t handler_flags = 0;
    if ((handler & 3u) ||
        cs->query((void *)(uintptr_t)handler, &handler_flags) != 0 ||
        handler_flags != cs->flag_executable ||
        !hook_owner(r, handler, &owner_base, &owner_bytes))
        return NLR_BOUNDS;
    if (hook_find(r, target) != NLR_CODE_HOOKS_MAX)
        return NLR_BUSY;
    uint32_t slot = hook_find(r, 0);
    if (slot == NLR_CODE_HOOKS_MAX)
        return NLR_BUSY;
    /* The firmware has to hold exactly the bytes the program was built
     * against: a program never patches a build it does not know. */
    const volatile uint8_t *at = (const volatile uint8_t *)(uintptr_t)target;
    uint8_t original[NLR_CODE_HOOK_BYTES];
    for (uint32_t n = 0; n < NLR_CODE_HOOK_BYTES; n++) {
        original[n] = at[n];
        if (original[n] != expect[n])
            return NLR_FORMAT;
    }
    for (uint32_t n = 0; n < NLR_CODE_HOOK_BYTES; n += 4u)
        if (!instruction_movable(code_word(original + n)))
            return NLR_FORMAT;
    uint8_t detour[NLR_CODE_HOOK_BYTES];
    const uint32_t words[2] = { CODE_LDR_X16_PC8, CODE_BR_X16 };
    for (uint32_t n = 0; n < 2u; n++)
        for (uint32_t b = 0; b < 4u; b++)
            detour[n * 4u + b] = (uint8_t)(words[n] >> (8u * b));
    for (uint32_t b = 0; b < 8u; b++)
        detour[8u + b] = (uint8_t)(handler >> (8u * b));
    int result = nlr_code_patch(cs, target, detour, NLR_CODE_HOOK_BYTES);
    if (result != NLR_OK)
        return result;
    for (uint32_t n = 0; n < NLR_CODE_HOOK_BYTES; n++)
        r->hooks.slot[slot].original[n] = original[n];
    r->hooks.slot[slot].handler = handler;
    r->hooks.slot[slot].owner_base = owner_base;
    r->hooks.slot[slot].owner_bytes = owner_bytes;
    /* Written last: the target is what makes the record found, and the
     * bytes it describes must be there first. */
    __atomic_store_n(&r->hooks.slot[slot].target, target, __ATOMIC_RELEASE);
    r->hooks.count++;
    return NLR_OK;
}

int nlr_code_unhook(struct nlr_runtime *r, uint64_t target)
{
    if (!r || !r->load.svc || !r->load.svc->code)
        return NLR_NOT_READY;
    uint32_t slot = target ? hook_find(r, target) : NLR_CODE_HOOKS_MAX;
    if (slot == NLR_CODE_HOOKS_MAX)
        return NLR_FORMAT;
    int result = nlr_code_patch(r->load.svc->code, target,
                                r->hooks.slot[slot].original,
                                NLR_CODE_HOOK_BYTES);
    if (result != NLR_OK)
        return result; /* the hook stays recorded: the bytes are still ours */
    __atomic_store_n(&r->hooks.slot[slot].target, (uint64_t)0,
                     __ATOMIC_RELEASE);
    r->hooks.slot[slot].handler = 0;
    r->hooks.slot[slot].owner_base = 0;
    r->hooks.slot[slot].owner_bytes = 0;
    if (r->hooks.count)
        r->hooks.count--;
    return NLR_OK;
}

int nlr_code_unhook_region(struct nlr_runtime *r, const void *base,
                           uint32_t bytes)
{
    if (!r)
        return NLR_NOT_READY;
    if (!base || !bytes)
        return NLR_OK;
    uint64_t lo = (uint64_t)(uintptr_t)base;
    uint64_t hi = lo + bytes;
    int result = NLR_OK;
    for (uint32_t n = 0; n < NLR_CODE_HOOKS_MAX; n++) {
        uint64_t target = __atomic_load_n(&r->hooks.slot[n].target,
                                          __ATOMIC_ACQUIRE);
        uint64_t owner = r->hooks.slot[n].owner_base;
        if (!target || owner + r->hooks.slot[n].owner_bytes <= lo ||
            owner >= hi)
            continue;
        /* A hook that cannot be put back keeps its record and its bytes,
         * and the failure travels up: the caller must not release the
         * memory the firmware now branches into. */
        int one = nlr_code_unhook(r, target);
        if (one != NLR_OK && result == NLR_OK)
            result = one;
    }
    return result;
}
