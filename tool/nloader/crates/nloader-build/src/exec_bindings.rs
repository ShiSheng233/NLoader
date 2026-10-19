//! Executable-page adapters for the audited Z8 mapping service family.
use crate::Error;
use nloader_profile::{MmuFamily, Profile};
use std::fmt::Write;

pub(crate) const NEUTRAL: &str = r#"
#include "nlr/exec.h"
const struct nlr_exec_services nlr_exec_services = { 0 };
"#;

/// Select the declared mapping family; execution builds must never degrade to
/// neutral bindings when declarations are incomplete.
pub(crate) fn generate(profile: &Profile) -> Result<String, Error> {
    match profile.abi.mmu {
        // The same service and the same bindings; the families differ only
        // in how the stock attribute dispatch encodes its arms, which is a
        // validation concern and not one of these addresses.
        Some(MmuFamily::Z8BlockV1 | MmuFamily::Z63BlockV1) => generate_block_v1(profile),
        None => Err(Error::Object("abi.mmu is not declared".into())),
    }
}

fn generate_block_v1(profile: &Profile) -> Result<String, Error> {
    let e = &profile.services.exec;
    let fields = [
        ("NLR_EXEC_MANAGER", e.manager),
        ("NLR_EXEC_CACHE_MANAGER", e.cache_manager),
        ("NLR_EXEC_QUERY", e.page_query),
        ("NLR_EXEC_PROTECT", e.page_protect),
        ("NLR_EXEC_TLB", e.tlb_sync),
        ("NLR_EXEC_TRANSLATE", e.mmu_translate),
        ("NLR_EXEC_ICACHE", e.icache_inval),
        ("NLR_EXEC_CACHEABLE", e.cacheable),
        // The entry the profile names as its write-back when it has one.
        // The maintenance a read ends with is what every model used before
        // the two were told apart, and stays the fallback for a profile
        // that has not been given the separate declaration.
        (
            "NLR_EXEC_CLEAN",
            profile
                .services
                .dcache_clean
                .or(profile.services.dcache_inv_post),
        ),
        ("NLR_EXEC_ALLOC", profile.services.mem_alloc),
        ("NLR_EXEC_FREE", profile.services.mem_free),
    ];
    if fields.iter().any(|(_, value)| value.is_none()) || e.region_bytes != Some(0x200000) {
        return Err(Error::Object(
            "mapping family requires every execution service and a 2 MiB region".into(),
        ));
    }
    // The encodings live in the profile (M2 D1 step 4); the adapter only
    // checks what the declared mapping family means by them.
    let flag_writable = e.flag_writable.unwrap_or(0);
    let flag_executable = e.flag_executable.unwrap_or(0);
    if flag_writable == 0 || flag_executable == 0 || flag_writable == flag_executable {
        return Err(Error::Object(
            "mapping family requires distinct nonzero writable and executable encodings".into(),
        ));
    }
    // The coexistence budget (M2-T2) is injected the same way; an unconfigured
    // or vacuous profile must fail the build, not start programs without a
    // budget.
    let budget = profile.memory.program_budget_blocks.unwrap_or(0);
    let max_resident = profile.memory.program_max_resident.unwrap_or(0);
    if budget == 0 || max_resident == 0 {
        return Err(Error::Object(
            "mapping family requires a nonzero program_budget_blocks and program_max_resident"
                .into(),
        ));
    }
    let mut out = String::from("\n#include \"nlr/exec.h\"\n");
    for (name, value) in fields {
        writeln!(out, "#define {name} ((uintptr_t)0x{:x}ULL)", value.unwrap()).unwrap();
    }
    writeln!(
        out,
        "#define NLR_EXEC_REGION_BYTES {}u",
        e.region_bytes.unwrap()
    )
    .unwrap();
    writeln!(out, "#define NLR_EXEC_FLAGS_W {:#x}u", flag_writable).unwrap();
    writeln!(out, "#define NLR_EXEC_FLAGS_X {:#x}u", flag_executable).unwrap();
    writeln!(out, "#define NLR_PROGRAM_BUDGET_BLOCKS {budget}u").unwrap();
    writeln!(out, "#define NLR_PROGRAM_MAX_RESIDENT {max_resident}u").unwrap();
    // The registry table is sized at compile time; a profile declaring more
    // residents than it can hold must fail the build, not be clipped.
    writeln!(
        out,
        "#include \"nlr/runtime.h\"\n_Static_assert(NLR_PROGRAM_MAX_RESIDENT + 1u <= NLR_RESIDENT_MAX, \
         \"program_max_resident plus the foreground slot exceeds the registry table\");"
    )
    .unwrap();
    // The execution page comes from the same stock heap entry as the rest of
    // the loader, so it is allocated by the same convention.
    out.push_str(
        if profile
            .abi
            .mem
            .is_some_and(nloader_profile::MemFamily::allocates_through_out)
        {
            ALLOCATOR_THROUGH_OUT
        } else {
            ALLOCATOR_RETURNS_POINTER
        },
    );
    out.push_str(&grant_reader(profile));
    let aligned_source = aligned_allocator(profile)?;
    let aligned = aligned_source.is_some();
    if let Some(source) = &aligned_source {
        out.push_str(source);
    }
    out.push_str(ADAPTERS);
    if profile.services.heap.is_some() {
        out.push_str("    .grant_probe = nlr_exec_grant_probe,\n");
        out.push_str("    .grant_end = nlr_exec_grant_end,\n");
        out.push_str("    .grant_next = nlr_exec_grant_next,\n");
    }
    if aligned {
        out.push_str("    .allocate_aligned = nlr_exec_allocate_aligned,\n");
    }
    out.push_str("};\n");
    Ok(out)
}

/// The heap's own aligned entry (`services.exec.memalign`), on the heap
/// whose handle `memalign_heap` holds -- pool 0, the one `mem_alloc` is
/// asked for and `mem_free` returns to. The handle is read at each request:
/// it lives in the camera's RAM, set up before any program can start.
fn aligned_allocator(profile: &Profile) -> Result<Option<String>, Error> {
    let e = &profile.services.exec;
    match (e.memalign, e.memalign_heap) {
        (None, None) => Ok(None),
        (Some(entry), Some(heap)) => {
            if profile.services.heap.is_some()
                || profile
                    .abi
                    .mem
                    .is_some_and(nloader_profile::MemFamily::allocates_through_out)
            {
                return Err(Error::Object(
                    "the aligned heap entry needs the pointer-returning heap without grant books"
                        .into(),
                ));
            }
            Ok(Some(format!(
                "\n#define NLR_EXEC_MEMALIGN ((uintptr_t)0x{entry:x}ULL)\n\
                 #define NLR_EXEC_MEMALIGN_HEAP ((uintptr_t)0x{heap:x}ULL)\n{ALIGNED_ALLOCATOR}"
            )))
        }
        _ => Err(Error::Object(
            "services.exec.memalign and memalign_heap are declared together".into(),
        )),
    }
}

/// The model's own record of how much memory an allocation really got, when
/// the profile declares where the allocator keeps it. The allocator here is
/// a stack manager whose public entry drops the granted size, so without
/// this the loader cannot tell a whole block from a short one; the service
/// reads the same list the model's own free() resolves a block through.
/// Every node pointer is checked against the declared pool, so a list
/// changing under the walk can neither fault nor run away.
fn grant_reader(profile: &Profile) -> String {
    let Some(heap) = &profile.services.heap else {
        return String::new();
    };
    let (Some(manager), Some(allocated), Some(pool), Some(count)) = (
        heap.manager,
        heap.list_allocated,
        heap.node_pool,
        heap.node_count,
    ) else {
        return String::new();
    };
    format!(
        "\n/* The allocator's allocated-block list: {{next, base, size}} nodes out\n\
         \x20* of the pool at the manager's own tail. base is the block, which the\n\
         \x20* guard flag says the returned pointer sits above. */\n\
         static uint64_t nlr_exec_grant_end(void *allocation)\n\
         {{\n\
         \x20   const volatile uint8_t *manager = (const volatile uint8_t *)0x{manager:x}ULL;\n\
         \x20   uintptr_t base = (uintptr_t)allocation;\n\
         \x20   if (!base)\n\
         \x20       return 0;\n\
         \x20   if (manager[{guard_flag:#x}]) {{\n\
         \x20       if (base < {guard_bytes:#x}u)\n\
         \x20           return 0;\n\
         \x20       base -= {guard_bytes:#x}u;\n\
         \x20   }}\n\
         \x20   uintptr_t pool = (uintptr_t)0x{manager:x}ULL + {pool:#x}u;\n\
         \x20   uintptr_t pool_end = pool + (uintptr_t){count}u * {node_bytes:#x}u;\n\
         \x20   uintptr_t node = *(const volatile uintptr_t *)(manager + {allocated:#x}u);\n\
         \x20   for (uint32_t step = 0; step < {count}u && node; step++) {{\n\
         \x20       if (node < pool || node >= pool_end ||\n\
         \x20           (node - pool) % {node_bytes:#x}u)\n\
         \x20           return 0;\n\
         \x20       const volatile uintptr_t *fields = (const volatile uintptr_t *)node;\n\
         \x20       if (fields[{node_base:#x}u / sizeof *fields] == base) {{\n\
         \x20           uint64_t size = (uint64_t)fields[{node_size:#x}u / sizeof *fields];\n\
         \x20           if (!size || (uint64_t)base > UINT64_MAX - size)\n\
         \x20               return 0;\n\
         \x20           return (uint64_t)base + size;\n\
         \x20       }}\n\
         \x20       node = fields[{node_next:#x}u / sizeof *fields];\n\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n\
         \n/* What a request of `bytes` would really be granted now: this\n\
         \x20* allocator takes the first node of its free list whatever its size,\n\
         \x20* and maps the whole span it was asked for, so anything larger than\n\
         \x20* that node must not be asked for. The node's usable bytes are its\n\
         \x20* size less the guard page, rounded down to the page the allocator\n\
         \x20* rounds requests up to; a node of exactly the guard and one page\n\
         \x20* still gives that page. */\n\
         static uint32_t nlr_exec_grant_probe(uint32_t bytes)\n\
         {{\n\
         \x20   const volatile uint8_t *manager = (const volatile uint8_t *)0x{manager:x}ULL;\n\
         \x20   uintptr_t pool = (uintptr_t)0x{manager:x}ULL + {pool:#x}u;\n\
         \x20   uintptr_t pool_end = pool + (uintptr_t){count}u * {node_bytes:#x}u;\n\
         \x20   uintptr_t node = *(const volatile uintptr_t *)(manager + {free:#x}u);\n\
         \x20   if (!bytes || node < pool || node >= pool_end ||\n\
         \x20       (node - pool) % {node_bytes:#x}u)\n\
         \x20       return 0;\n\
         \x20   uint64_t size = (uint64_t)((const volatile uintptr_t *)node)[{node_size:#x}u / sizeof(uintptr_t)];\n\
         \x20   uint64_t guard = manager[{guard_flag:#x}] ? {guard_bytes:#x}u : 0u;\n\
         \x20   if (size < guard + {round_bytes:#x}u)\n\
         \x20       return 0;\n\
         \x20   uint64_t usable = (size - guard) & ~(uint64_t)({round_bytes:#x}u - 1u);\n\
         \x20   if (!usable)\n\
         \x20       return 0;\n\
         \x20   return usable < (uint64_t)bytes ? (uint32_t)usable : bytes;\n\
         }}\n\
         \n/* Where the next grant would start: the free list's head node, past\n\
         \x20* the guard page this allocator keeps in front of every block. */\n\
         static uint64_t nlr_exec_grant_next(uint64_t *guard)\n\
         {{\n\
         \x20   const volatile uint8_t *manager = (const volatile uint8_t *)0x{manager:x}ULL;\n\
         \x20   uintptr_t pool = (uintptr_t)0x{manager:x}ULL + {pool:#x}u;\n\
         \x20   uintptr_t pool_end = pool + (uintptr_t){count}u * {node_bytes:#x}u;\n\
         \x20   uintptr_t node = *(const volatile uintptr_t *)(manager + {free:#x}u);\n\
         \x20   if (!guard || node < pool || node >= pool_end ||\n\
         \x20       (node - pool) % {node_bytes:#x}u)\n\
         \x20       return 0;\n\
         \x20   uint64_t g = manager[{guard_flag:#x}] ? {guard_bytes:#x}u : 0u;\n\
         \x20   uint64_t base = (uint64_t)((const volatile uintptr_t *)node)[{node_base:#x}u / sizeof(uintptr_t)];\n\
         \x20   if (!base || base > UINT64_MAX - g)\n\
         \x20       return 0;\n\
         \x20   *guard = g;\n\
         \x20   return base + g;\n\
         }}\n",
        free = heap.list_free.unwrap_or(8),
        round_bytes = heap.round_bytes.unwrap_or(0x1000),
        manager = manager,
        allocated = allocated,
        pool = pool,
        count = count,
        node_bytes = heap.node_bytes.unwrap_or(0x18),
        node_next = heap.node_next.unwrap_or(0),
        node_base = heap.node_base.unwrap_or(8),
        node_size = heap.node_size.unwrap_or(0x10),
        guard_flag = heap.guard_flag.unwrap_or(0x20),
        guard_bytes = heap.guard_bytes.unwrap_or(0x1000),
    )
}

/// This body's heap entry takes the destination and returns a status, and
/// refuses a null destination. Called in the Z8 shape it returns -17, which
/// as a pointer rounds up to 0x100000000 and is audited as if it were the
/// page: the refusal has to be read from the status instead.
const ALLOCATOR_THROUGH_OUT: &str = r#"
static int32_t nlr_exec_allocate(uint32_t bytes, void **out)
{
    int32_t (*allocate)(uint32_t, void **) = (void *)NLR_EXEC_ALLOC;
    if (!out || !bytes) return NLR_NOT_READY;
    void *p = 0;
    int32_t status = allocate(bytes, &p);
    if (status || !p) {
        *out = 0;
        return NLR_NOT_READY;
    }
    *out = p;
    return NLR_OK;
}
static int32_t nlr_exec_release(void *allocation)
{
    int32_t (*release)(void *) = (void *)NLR_EXEC_FREE;
    if (!allocation) return NLR_NOT_READY;
    return release(allocation) ? NLR_NOT_READY : NLR_OK;
}
"#;

const ALLOCATOR_RETURNS_POINTER: &str = r#"
static int32_t nlr_exec_allocate(uint32_t bytes, void **out)
{
    void *(*allocate)(uint32_t, uint32_t) = (void *)NLR_EXEC_ALLOC;
    if (!out || !bytes) return NLR_NOT_READY;
    *out = allocate(bytes, 0);
    return *out ? NLR_OK : NLR_NOT_READY;
}
static int32_t nlr_exec_release(void *allocation)
{
    void (*release)(void *) = (void *)NLR_EXEC_FREE;
    if (!allocation) return NLR_NOT_READY;
    release(allocation);
    return NLR_OK;
}
"#;

/// The heap's aligned entry, on the heap handle the profile's word holds
/// (aligned_allocator defines both addresses).
const ALIGNED_ALLOCATOR: &str = r#"
static int32_t nlr_exec_allocate_aligned(uint32_t alignment, uint32_t bytes, void **out)
{
    void *(*memalign)(void *, uint64_t, uint64_t) = (void *)NLR_EXEC_MEMALIGN;
    if (!out) return NLR_NOT_READY;
    *out = 0;
    void *heap = *(void *const volatile *)NLR_EXEC_MEMALIGN_HEAP;
    if (!heap || !bytes || !alignment || (alignment & (alignment - 1u)))
        return NLR_NOT_READY;
    *out = memalign(heap, alignment, bytes);
    return *out ? NLR_OK : NLR_NOT_READY;
}
"#;

const ADAPTERS: &str = r#"

/* No address changes, permission changes, or memory allocations during audit.
 * The firmware owns manager/table storage; all child tables are constrained to
 * its current registered pool before dereferencing. Unknown layouts fail closed. */
static int32_t nlr_exec_audit(void *pages, uint32_t bytes, uint32_t flags)
{
#if defined(__aarch64__)
    uintptr_t start = (uintptr_t)pages;
    if (bytes != NLR_EXEC_REGION_BYTES ||
        (start & (NLR_EXEC_REGION_BYTES - 1u)) ||
        start >= (UINT64_C(1) << 39) ||
        bytes > (UINT64_C(1) << 39) - start ||
        (flags != NLR_EXEC_FLAGS_W && flags != NLR_EXEC_FLAGS_X))
        return NLR_NOT_READY;
    uint64_t el, tcr, ttbr, mair, sctlr, mpidr, ctr;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    if (el != 4) return NLR_NOT_READY;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(mair));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    /* Fixed CPU0 worker; ASID0 TTBR0, 39-bit/4KiB, hierarchy enabled.
     * Runtime cache/MMU state is checked, never replaced with boot constants. */
    if ((mpidr & UINT64_C(0xff00ffffff)) ||
        (tcr & 63) != 25 || ((tcr >> 14) & 3) ||
        (tcr & ((UINT64_C(1) << 7) | (UINT64_C(1) << 22) |
                (UINT64_C(1) << 39) | (UINT64_C(1) << 40) |
                (UINT64_C(1) << 41))) || (ttbr >> 48) ||
        ((mair >> 24) & 255) != 255 || (sctlr & 0x1005) != 0x1005)
        return NLR_NOT_READY;
    const volatile uint8_t *cache = (void *)NLR_EXEC_CACHE_MANAGER;
    uint32_t iline = 4u << (ctr & 15), dline = 4u << ((ctr >> 16) & 15);
    if (cache[0] || dline != 64 || iline > 4096 ||
        *(const volatile uint32_t *)(cache + 0x38) != iline ||
        *(const volatile uint32_t *)(cache + 0x3c) != dline ||
        /* Zero would mean an uninitialized manager; the threshold field is
         * also checked against each maintained range by its callers. */
        *(const volatile uint32_t *)(cache + 0x28) == 0u)
        return NLR_NOT_READY;
    const volatile uint8_t *manager = (void *)NLR_EXEC_MANAGER;
    if (manager[0x38]) return NLR_NOT_READY;
    uintptr_t root = *(const volatile uint64_t *)(manager + 0);
    uintptr_t pool = *(const volatile uint64_t *)(manager + 8);
    uint32_t count = *(const volatile uint32_t *)(manager + 0x10);
    uint64_t physical = *(const volatile uint64_t *)(manager + 0x30);
    uint64_t pool_bytes = (uint64_t)count * 4096;
    if (!root || !pool || !count || count != 192 ||
        ((root | pool | physical) & 4095) ||
        root >= (UINT64_C(1) << 39) || pool >= (UINT64_C(1) << 39) ||
        pool_bytes > (UINT64_C(1) << 39) - pool ||
        physical >= (UINT64_C(1) << 36) ||
        pool_bytes > (UINT64_C(1) << 36) - physical)
        return NLR_NOT_READY;
    int32_t (*translate)(const volatile void *, uintptr_t, uint64_t *) =
        (void *)NLR_EXEC_TRANSLATE;
    uint64_t root_pa = 0;
    if (translate(manager, root, &root_pa) ||
        (ttbr & UINT64_C(0x0000fffffffff000)) != root_pa)
        return NLR_NOT_READY;
    int32_t (*query)(void *, uint32_t *) = (void *)NLR_EXEC_QUERY;
    uint32_t (*cacheable)(void *) = (void *)NLR_EXEC_CACHEABLE;
    for (uint32_t n = 0; n < bytes; n += NLR_EXEC_REGION_BYTES) {
        uintptr_t va = start + n, table = root;
        for (unsigned level = 1; level <= 2; level++) {
            unsigned shift = 39 - 9 * level;
            uint64_t d = ((const volatile uint64_t *)table)[(va >> shift) & 511];
            if (level == 2) {
                /* The entire existing block belongs to this allocation.
                 * Table creation and live block demotion are never allowed. */
                if ((d & 3) != 1 || (d & UINT64_C(0x1ff000)) ||
                    (d & (UINT64_C(3) << 51)) || (d & 0x20))
                    return NLR_NOT_READY;
                uint64_t xn = UINT64_C(3) << 53;
                uint64_t expected_xn = flags == NLR_EXEC_FLAGS_W ? xn : 0;
                uint32_t ap = flags == NLR_EXEC_FLAGS_W ? 1 : 3;
                if (((d >> 6) & 3) != ap || ((d >> 2) & 7) != 3 ||
                    ((d >> 8) & 3) != 3 || !(d & (UINT64_C(1) << 10)) ||
                    (d & xn) != expected_xn)
                    return NLR_NOT_READY;
                break;
            }
            if ((d & 3) != 3 || (d & (UINT64_C(15) << 59)))
                return NLR_NOT_READY;
            uint64_t pa = d & UINT64_C(0xffffff000);
            if (pa < physical || pa - physical >= pool_bytes)
                return NLR_NOT_READY;
            table = pool + (uintptr_t)(pa - physical);
        }
        uint32_t actual = 0;
        if (query((void *)va, &actual) || actual != flags ||
            !cacheable((void *)va) ||
            !cacheable((void *)(va + NLR_EXEC_REGION_BYTES - 1u)))
            return NLR_NOT_READY;
    }
    return NLR_OK;
#else
    (void)pages; (void)bytes; (void)flags;
    return NLR_NOT_READY;
#endif
}
static int32_t nlr_exec_protect(void *page, uint64_t bytes, uint32_t flags)
{
    int32_t (*protect)(void *, uint64_t, uint32_t) = (void *)NLR_EXEC_PROTECT;
    void (*sync)(void *, uint64_t) = (void *)NLR_EXEC_TLB;
    if (bytes != NLR_EXEC_REGION_BYTES ||
        ((uintptr_t)page & (NLR_EXEC_REGION_BYTES - 1u)) ||
        (flags != NLR_EXEC_FLAGS_W && flags != NLR_EXEC_FLAGS_X))
        return NLR_NOT_READY;
    if (nlr_exec_audit(page, (uint32_t)bytes, NLR_EXEC_FLAGS_W) &&
        nlr_exec_audit(page, (uint32_t)bytes, NLR_EXEC_FLAGS_X))
        return NLR_NOT_READY;
    /* Bit29 suppresses native whole-cache maintenance and its coupled TLBI.
     * This is one complete L2 leaf: no table split or pool allocation occurs.
     * The independent native range TLBI runs even if protect reports failure,
     * since a failed native operation may have already changed permissions. */
    int32_t result = protect(page, bytes, flags | 0x20000000u);
    sync(page, bytes); /* DSB SY; broadcast VAE1IS; DSB SY; ISB. */
    if (result) return result;
    return nlr_exec_audit(page, (uint32_t)bytes, flags);
}
static int32_t nlr_exec_clean(void *page, uint32_t bytes)
{
    void (*clean)(void *, uint32_t) = (void *)NLR_EXEC_CLEAN;
    uint32_t (*cacheable)(void *) = (void *)NLR_EXEC_CACHEABLE;
    if (nlr_exec_audit(page, bytes, NLR_EXEC_FLAGS_W)) return NLR_NOT_READY;
    /* Four 512KiB calls stay below the original 0x88000 switch to the SMP
     * whole-cache path. Every byte belongs to this execution allocation. */
    for (uint32_t offset = 0; offset < bytes; offset += 0x80000u) {
        uint8_t *part = (uint8_t *)page + offset;
        if (!cacheable(part) || !cacheable(part + 0x7ffffu))
            return NLR_NOT_READY;
        clean(part, 0x80000u);
    }
    return NLR_OK;
}
static int32_t nlr_exec_icache(void *page, uint64_t bytes)
{
    void (*invalidate)(void *, uint64_t) = (void *)NLR_EXEC_ICACHE;
    uint32_t (*cacheable)(void *) = (void *)NLR_EXEC_CACHEABLE;
    const volatile uint8_t *cache = (void *)NLR_EXEC_CACHE_MANAGER;
    /* Keep every call strictly below the live manager threshold. Interior
     * boundaries are whole cache lines, so each original range operation
     * and its barriers complete before the following range begins. */
    uint32_t threshold = *(const volatile uint32_t *)(cache + 0x28);
    uint32_t iline = *(const volatile uint32_t *)(cache + 0x38);
    uint32_t unit = iline > 64u ? iline : 64u;
    if (!bytes || bytes > NLR_EXEC_REGION_BYTES ||
        (uintptr_t)page % 64u ||
        iline < 4u || iline > 4096u || (iline & (iline - 1u)) ||
        threshold <= unit || threshold > NLR_EXEC_REGION_BYTES ||
        !cacheable(page) || !cacheable((void *)((uintptr_t)page + bytes - 1u)) ||
        nlr_exec_audit(page, NLR_EXEC_REGION_BYTES, NLR_EXEC_FLAGS_X))
        return NLR_NOT_READY;
    uint64_t chunk = ((uint64_t)threshold - 1u) & ~((uint64_t)unit - 1u);
    for (uint64_t offset = 0; offset < bytes;) {
        uint64_t count = bytes - offset < chunk ? bytes - offset : chunk;
        uint8_t *part = (uint8_t *)page + offset;
        if (*(const volatile uint32_t *)(cache + 0x28) != threshold ||
            *(const volatile uint32_t *)(cache + 0x38) != iline ||
            !cacheable(part) || !cacheable(part + count - 1u))
            return NLR_NOT_READY;
        invalidate(part, count);
        offset += count;
    }
    return NLR_OK;
}
static uint64_t nlr_exec_call(void *entry, uint64_t challenge)
{
    uint64_t (*run)(uint64_t) = entry;
    return run(challenge);
}
/* Resource init shares the audited pinned-worker execution mechanism. It only
 * prepares loader RAM registrations; menu publication is deferred to the
 * owning page checkpoint, never dispatched synchronously from this worker. */
static int32_t nlr_exec_extension_call(void *entry, uint64_t api,
                                      int32_t *exit_code, uint32_t *started)
{
    if (!entry || !exit_code || !started)
        return NLR_NOT_READY;
    *started = 1;
    *exit_code = (int32_t)(uint32_t)nlr_exec_call(entry, api);
    return NLR_OK;
}
const struct nlr_exec_services nlr_exec_services = {
    .region_bytes = NLR_EXEC_REGION_BYTES,
    .flag_writable = NLR_EXEC_FLAGS_W,
    .flag_executable = NLR_EXEC_FLAGS_X,
    .program_budget_blocks = NLR_PROGRAM_BUDGET_BLOCKS,
    .program_max_resident = NLR_PROGRAM_MAX_RESIDENT,
    .allocate = nlr_exec_allocate,
    .release = nlr_exec_release,
    .audit = nlr_exec_audit,
    .protect = nlr_exec_protect,
    .clean = nlr_exec_clean,
    .invalidate_code = nlr_exec_icache,
    .call = nlr_exec_call,
    .extension_call = nlr_exec_extension_call,
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires clang on the host"]
    fn icache_chunks_cover_large_programs_and_stop_on_changed_native_state() {
        let adapter = ADAPTERS
            .split_once("static int32_t nlr_exec_icache(")
            .unwrap()
            .1
            .split_once("static uint64_t nlr_exec_call(")
            .unwrap()
            .0;
        let source = include_str!("../tests/fixtures/icache.c").replace(
            "/* ADAPTER_UNDER_TEST */",
            &format!("static int32_t nlr_exec_icache({adapter}"),
        );
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("icache.c");
        let binary = directory.path().join("icache");
        std::fs::write(&input, source).unwrap();
        let output = std::process::Command::new("clang")
            .args([
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=undefined",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new(&binary).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn execution_bindings_refuse_missing_family_or_services() {
        let mut profile = Profile::draft("synthetic", "test");
        assert!(generate(&profile)
            .unwrap_err()
            .to_string()
            .contains("abi.mmu"));
        profile.abi.mmu = Some(MmuFamily::Z8BlockV1);
        assert!(generate(&profile).is_err());
        let e = &mut profile.services.exec;
        e.manager = Some(0x1000);
        e.cache_manager = Some(0x2000);
        e.page_query = Some(0x3000);
        e.page_protect = Some(0x4000);
        e.tlb_sync = Some(0x5000);
        e.mmu_translate = Some(0x6000);
        e.icache_inval = Some(0x7000);
        e.cacheable = Some(0x8000);
        e.region_bytes = Some(0x200000);
        e.flag_writable = Some(0x21);
        e.flag_executable = Some(0x34);
        profile.services.dcache_inv_post = Some(0x9000);
        profile.services.mem_alloc = Some(0xa000);
        profile.services.mem_free = Some(0xb000);
        // The coexistence budget is required like the encodings: missing or
        // zero fails the build, and the values are injected verbatim.
        assert!(generate(&profile).is_err());
        profile.memory.program_budget_blocks = Some(2);
        assert!(generate(&profile).is_err());
        profile.memory.program_max_resident = Some(1);
        let generated = generate(&profile).unwrap();
        assert!(generated.contains("nlr_exec_protect"));
        assert!(generated.contains("#define NLR_EXEC_FLAGS_W 0x21u"));
        assert!(generated.contains("#define NLR_EXEC_FLAGS_X 0x34u"));
        assert!(generated.contains("#define NLR_PROGRAM_BUDGET_BLOCKS 2u"));
        assert!(generated.contains("#define NLR_PROGRAM_MAX_RESIDENT 1u"));
        assert!(generated.contains("NLR_RESIDENT_MAX"));
        assert!(generated.contains(".flag_writable = NLR_EXEC_FLAGS_W,"));
        assert!(generated.contains(".flag_executable = NLR_EXEC_FLAGS_X,"));
        assert!(generated.contains(".program_budget_blocks = NLR_PROGRAM_BUDGET_BLOCKS,"));
        assert!(generated.contains(".program_max_resident = NLR_PROGRAM_MAX_RESIDENT,"));
        assert!(generated.contains(".extension_call = nlr_exec_extension_call,"));
        assert!(generated.contains("nlr_exec_call(entry, api)"));
        profile.services.exec.flag_writable = None;
        assert!(generate(&profile).is_err());
        profile.services.exec.flag_writable = Some(0);
        assert!(generate(&profile).is_err());
        profile.services.exec.flag_writable = Some(0x34);
        assert!(generate(&profile).is_err());
        profile.services.exec.mmu_translate = None;
        assert!(generate(&profile).is_err());
        profile.services.exec.mmu_translate = Some(0x6000);
        profile.memory.program_budget_blocks = Some(0);
        assert!(generate(&profile).is_err());
        profile.memory.program_budget_blocks = Some(2);
        profile.memory.program_max_resident = Some(0);
        assert!(generate(&profile).is_err());
        profile.memory.program_max_resident = Some(1);
        profile.services.exec.flag_writable = Some(0x21);

        // The aligned entry: absent, the slot stays null; declared whole,
        // the adapter reads the handle word and calls the entry; declared
        // by halves or beside grant books, the build refuses.
        let generated = generate(&profile).unwrap();
        assert!(!generated.contains("allocate_aligned"));
        profile.services.exec.memalign = Some(0xc000);
        assert!(generate(&profile).is_err());
        profile.services.exec.memalign_heap = Some(0xd000);
        let generated = generate(&profile).unwrap();
        assert!(generated.contains("#define NLR_EXEC_MEMALIGN ((uintptr_t)0xc000ULL)"));
        assert!(generated.contains("#define NLR_EXEC_MEMALIGN_HEAP ((uintptr_t)0xd000ULL)"));
        assert!(generated.contains(".allocate_aligned = nlr_exec_allocate_aligned,"));
        profile.services.exec.memalign = None;
        assert!(generate(&profile).is_err());
        profile.services.exec.memalign = Some(0xc000);
        profile.services.heap = Some(Default::default());
        assert!(generate(&profile).is_err());
    }
}
