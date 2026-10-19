#include "nlr/exec.h"

static uint32_t read32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

int nlr_probe_validate(const uint8_t *file, uint32_t bytes,
                       uint32_t manifest_kind)
{
    if (!file || bytes != NLR_PROBE_FILE_SIZE || manifest_kind != 2u)
        return NLR_FORMAT;
    if (file[0] != 'N' || file[1] != 'P' || file[2] != 'L' || file[3] != 'D' ||
        read32(file + 4) != 0x00300002u ||
        read32(file + 8) != 1u || read32(file + 12) != 16u ||
        read32(file + 16) != 0u || read32(file + 20) != 0u ||
        read32(file + 24) != 1u || read32(file + 28) != 0x7f73ea87u ||
        read32(file + 32) != 2u || read32(file + 36) != 0u ||
        read32(file + 40) != 0u || read32(file + 44) != 0u)
        return NLR_FORMAT;
    /* Closed, independently audited code identity. Even a newly calculated
     * valid CRC cannot authorize a different program under this probe ABI. */
    if (read32(file + 48) != 0x93c04400u ||
        read32(file + 52) != 0xca003400u ||
        read32(file + 56) != 0x910c4400u ||
        read32(file + 60) != 0xd65f03c0u)
        return NLR_CHECKSUM;
    return NLR_OK;
}

uint64_t nlr_probe_response(uint64_t challenge)
{
    uint64_t rotated = (challenge >> 17) | (challenge << 47);
    return (rotated ^ (rotated << 13)) + 0x311u;
}

/* Acquire one allocation of `request` bytes, from `allocate` (given back
 * with `release`) under the books `svc` keeps, that really holds a complete
 * `region` starting at its first `region` boundary: the `needed` bytes from
 * that boundary must be inside what the allocator granted, and the boundary
 * must fall within the slack the request paid for.
 *
 * The allocator is asked for a region only in a size it can grant whole
 * (grant_probe). This is not politeness: a model's allocator may answer a
 * larger request with less memory and still apply its mapping to the whole
 * span it was asked for, which re-maps memory that belongs to something
 * else — a resident extension's code, for instance. When the probe says
 * something smaller is in the way, exactly that much is taken out of the
 * way and held: a request of its own size stays inside it, and holding it
 * (rather than releasing it, which would put it back where the next
 * request finds it again) moves the allocator's search on by one of its own
 * nodes. The held blocks go back when the acquisition ends; by then a
 * usable block, if one arrived, is out of the allocator's reach, so none of
 * them can be handed out in its place.
 *
 * Returns NLR_OK with the allocation and its aligned page, NLR_BOUNDS when
 * the alignment slack was the problem, NLR_NOT_READY when the allocator
 * refused or could not give a whole region, or NLR_EXEC_RESTORE when a
 * release failed — then the block that could not be released is handed back
 * as the allocation, so the caller's state records its exact owner and
 * refuses every later attempt.
 */
static int acquire_region(const struct nlr_exec_services *svc,
                          int32_t (*allocate)(uint32_t bytes, void **out),
                          int32_t (*release)(void *allocation),
                          uint32_t request, uint32_t region, uint32_t needed,
                          void **out_allocation, uint8_t **out_page)
{
    void *held[NLR_EXEC_GRANT_TRIES];
    uint32_t held_count = 0;
    int result = NLR_NOT_READY;
    *out_allocation = 0;
    *out_page = 0;
    for (uint32_t attempt = 0; attempt < NLR_EXEC_GRANT_TRIES; attempt++) {
        /* What the allocator can grant whole right now. A smaller answer is
         * taken out of the way first, in its own size, so nothing outside
         * it is touched; a zero answer means it cannot be asked at all. */
        uint32_t ask = request;
        if (svc->grant_probe) {
            uint32_t room = svc->grant_probe(request);
            if (!room) {
                result = NLR_NOT_READY;
                break;
            }
            ask = room < request ? room : request;
        }
        void *allocation = 0;
        if (allocate(ask, &allocation) != 0 || !allocation) {
            result = NLR_NOT_READY;
            break;
        }
        /* Whatever was asked for, the allocator maps the whole span: if
         * what it really granted is shorter, that mapping has just run
         * over memory it did not own. The obstacle is asked for in its own
         * size exactly so this cannot happen, but the size came from a
         * probe taken a moment earlier and the heap is not locked, so the
         * grant is read back here too — for the obstacle as much as for
         * the region, because the repair is the same repair. */
        uint64_t granted = svc->grant_end ? svc->grant_end(allocation) : 0;
        if (svc->grant_end &&
            (!granted || granted < (uint64_t)(uintptr_t)allocation + ask))
            nlr_exec_resident_recheck(svc);
        if (ask < request) {
            held[held_count++] = allocation;
            result = NLR_NOT_READY;
            continue;
        }
        uintptr_t base = (uintptr_t)allocation;
        if (base > UINTPTR_MAX - request) {
            if (release(allocation) != 0) {
                *out_allocation = allocation;
                return NLR_EXEC_RESTORE;
            }
            result = NLR_BOUNDS;
            break;
        }
        uintptr_t aligned = (base + region - 1u) & ~(uintptr_t)(region - 1u);
        if (aligned - base > request - needed) {
            /* The alignment slack this request paid for is not enough: a
             * different allowance may be, which is the caller's to try. The
             * block itself is whole, so it goes straight back. */
            if (release(allocation) != 0) {
                *out_allocation = allocation;
                return NLR_EXEC_RESTORE;
            }
            result = NLR_BOUNDS;
            break;
        }
        /* Only the bytes this region will really use have to be inside the
         * grant; the slack past them is never touched. A grant that does
         * not reach them is the probe having been overtaken — the resident
         * blocks were looked over above — and this one is held rather than
         * released, because a released node is what the next request would
         * find again. */
        if (svc->grant_end &&
            (!granted || (uint64_t)aligned + needed > granted)) {
            held[held_count++] = allocation;
            result = NLR_NOT_READY;
            continue;
        }
        *out_allocation = allocation;
        *out_page = (uint8_t *)aligned;
        result = NLR_OK;
        break;
    }
    for (uint32_t n = 0; n < held_count; n++)
        if (release(held[n]) != 0) {
            /* The usable block, if there was one, is already the caller's;
             * this one is the owner that cannot be given back. */
            *out_allocation = held[n];
            *out_page = 0;
            return NLR_EXEC_RESTORE;
        }
    return result;
}

/* One block of `bytes` outside a program's regions -- the API's mem_alloc,
 * the loader's spill -- under the regions' grant discipline: `books` lends
 * its grant_probe and grant_end, while `allocate` and `release` are the
 * caller's own, so the block goes back the way it came. A node too small
 * for the request is taken out of the way in its own size first, and
 * nothing is asked for that the allocator cannot grant whole. 0 when the
 * block cannot be had whole. */
void *nlr_exec_grant_alloc(const struct nlr_exec_services *books,
                           int32_t (*allocate)(uint32_t bytes, void **out),
                           int32_t (*release)(void *allocation),
                           uint32_t bytes)
{
    if (!books || !allocate || !release || !bytes)
        return 0;
    void *allocation = 0;
    uint8_t *page = 0;
    if (acquire_region(books, allocate, release, bytes, 16u, bytes,
                       &allocation, &page) != NLR_OK)
        return 0;
    return allocation;
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
extern const struct nlr_exec_services nlr_exec_services;
#endif

/* Every block core takes from the camera's heap comes through here (see
 * nlr/services.h). The books are the executor's and exist only in the
 * stages that run programs; where they say nothing (no grant_probe) the
 * allocator is taken at its word, as before. A block the allocator handed
 * over together with a failure is given back, so nothing stays held. */
void *nlr_alloc_whole(const struct nlr_services *services, uint32_t bytes)
{
    if (!services || !services->alloc || !services->release || !bytes)
        return 0;
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    if (nlr_exec_services.grant_probe)
        return nlr_exec_grant_alloc(&nlr_exec_services, services->alloc,
                                    services->release, bytes);
#endif
    void *block = 0;
    if (services->alloc(bytes, &block) != NLR_OK || !block) {
        if (block)
            (void)services->release(block);
        return 0;
    }
    return block;
}

static int finish(struct nlr_probe_state *state,
                   const struct nlr_exec_services *svc, int result)
{
    if (!state->allocation)
        return result;
    /* protect can fail after partially changing mappings; recovery is
     * mandatory even when the original transition reported an error. */
    if (state->permissions_touched &&
        (svc->protect(state->page, state->region_bytes, svc->flag_writable) != 0 ||
         svc->audit(state->page, state->region_bytes, svc->flag_writable) != 0))
        return NLR_EXEC_RESTORE;
    state->permissions_touched = 0;
    if (svc->release(state->allocation) != 0)
        return NLR_EXEC_RESTORE;
    state->allocation = 0;
    state->page = 0;
    return result;
}

int nlr_probe_run(struct nlr_probe_state *state,
                  const struct nlr_exec_services *svc,
                  const uint8_t *file, uint32_t bytes, uint32_t manifest_kind,
                  uint64_t challenge, uint32_t prepare_only)
{
    if (!state || !svc || !svc->allocate || !svc->release || !svc->audit ||
        !svc->protect || !svc->clean || !svc->invalidate_code || !svc->call)
        return NLR_NOT_READY;
    if (svc->region_bytes != NLR_EXEC_PAGE_SIZE &&
        svc->region_bytes != NLR_EXEC_BLOCK_SIZE)
        return NLR_NOT_READY;
    /* A missing or collapsed encoding can never name two permissions; refuse
     * it before any allocation so the neutral table stays unreachable. */
    if (!svc->flag_writable || !svc->flag_executable ||
        svc->flag_writable == svc->flag_executable)
        return NLR_NOT_READY;
    if (state->allocation)
        return NLR_BUSY;
    state->region_bytes = svc->region_bytes;
    state->phase = 'V';
    state->prepared = state->entry_started = state->returned = 0;
    state->permissions_touched = 0;
    state->challenge = challenge;
    state->expected = nlr_probe_response(challenge);
    state->response = 0;
    int result = nlr_probe_validate(file, bytes, manifest_kind);
    if (result != NLR_OK)
        return result;
    state->phase = 'A';
    uint32_t allocation_bytes = 2u * state->region_bytes - 1u;
    result = acquire_region(svc, svc->allocate, svc->release,
                            allocation_bytes, state->region_bytes,
                            state->region_bytes, &state->allocation,
                            &state->page);
    if (result != NLR_OK) {
        /* Nothing was kept unless a release failed, and then the block
         * stays owned and this state refuses every later attempt. */
        return result == NLR_EXEC_RESTORE ? result : finish(state, svc, result);
    }
    state->phase = 'U';
    if (svc->audit(state->page, state->region_bytes, svc->flag_writable) != 0)
        return finish(state, svc, NLR_NOT_READY);
    state->phase = 'W';
    state->permissions_touched = 1;
    if (svc->protect(state->page, state->region_bytes, svc->flag_writable) != 0 ||
        svc->audit(state->page, state->region_bytes, svc->flag_writable) != 0)
        return finish(state, svc, NLR_NOT_READY);
    state->phase = 'D';
    for (uint32_t i = 0; i < NLR_PROBE_IMAGE_SIZE; i++)
        state->page[i] = file[NLR_PROBE_HEADER_SIZE + i];
    state->phase = 'C';
    if (svc->clean(state->page, state->region_bytes) != 0)
        return finish(state, svc, NLR_NOT_READY);
    state->phase = 'X';
    if (svc->protect(state->page, state->region_bytes, svc->flag_executable) != 0 ||
        svc->audit(state->page, state->region_bytes, svc->flag_executable) != 0)
        return finish(state, svc, NLR_NOT_READY);
    state->phase = 'I';
    if (svc->invalidate_code(state->page, NLR_PROBE_IMAGE_SIZE) != 0)
        return finish(state, svc, NLR_NOT_READY);
    state->prepared = 1;
    if (prepare_only)
        return finish(state, svc, NLR_OK);
    state->phase = 'E';
    state->entry_started = 1;
    state->response = svc->call(state->page, challenge);
    state->returned = 1;
    state->phase = 'R';
    result = state->response == state->expected ? NLR_OK : NLR_EXEC_RESPONSE;
    return finish(state, svc, result);
}

/* ---- generic v2 programs (PLAN 6.3 M2-T4) -------------------------------- */

/* ADRP relocation: offset is the instruction's position in the image, target
 * its data-segment address. The page difference between the two blocks is
 * the new immediate; the ADD pairing keeps the link-time page offset and is
 * not part of the table (PLAN 6.3). After writing, the instruction is read
 * back: the fixed ADRP bits and the decoded difference must both match, so
 * a corrupted or non-ADRP instruction is rejected instead of executed. */
int nlr_program_patch_adrp(uint8_t *code_base, uint32_t offset,
                           const uint8_t *data_base, uint32_t target)
{
    uint8_t *at = code_base + offset;
    uint32_t original = read32(at);
    int64_t difference =
        (int64_t)(((uintptr_t)data_base + target) >> 12) -
        (int64_t)(((uintptr_t)code_base + offset) >> 12);
    /* The immediate is a signed 21-bit page count (±1 MiB pages, ±4 GiB). */
    if (difference < -(int64_t)(1u << 20) ||
        difference > (int64_t)((1u << 20) - 1))
        return NLR_BOUNDS;
    int32_t immediate = (int32_t)difference;
    uint32_t immlo = (uint32_t)immediate & 3u;
    uint32_t immhi = ((uint32_t)immediate >> 2) & 0x7ffffu;
    uint32_t patched = (original & ~((0x7ffffu << 5) | (3u << 29))) |
                       (immhi << 5) | (immlo << 29);
    /* Byte stores: the entry's offset needs no alignment promise. */
    at[0] = (uint8_t)patched;
    at[1] = (uint8_t)(patched >> 8);
    at[2] = (uint8_t)(patched >> 16);
    at[3] = (uint8_t)(patched >> 24);
    /* Read back: the fixed ADRP bits and the decoded difference must both
     * match, so a corrupted or non-ADRP instruction is rejected instead of
     * executed. */
    uint32_t read_back = read32(at);
    if ((read_back & 0x9f000000u) != 0x90000000u)
        return NLR_FORMAT;
    uint32_t field =
        (((read_back >> 5) & 0x7ffffu) << 2) | ((read_back >> 29) & 3u);
    /* Sign-extend the 21-bit field: bit 20 is the sign, replicated into
     * bits 31:21. */
    uint32_t extended = (field & 0x1fffffu) |
                        (field & (1u << 20) ? 0xffe00000u : 0u);
    if ((int32_t)extended != immediate)
        return NLR_FORMAT;
    return NLR_OK;
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)

/* ABS64 relocation: the code block address of `target` is written into the
 * data block at `offset` so the program can register pointers to its own
 * code with the firmware. The data block stays writable, so this runs
 * during the writable phase. */
static void patch_abs64(uint8_t *data_base, uint32_t offset,
                        const uint8_t *code_base, uint32_t target)
{
    uint64_t value = (uint64_t)((uintptr_t)code_base + target);
    uint8_t *at = data_base + offset;
    for (uint32_t n = 0; n < 8; n++)
        at[n] = (uint8_t)(value >> (8 * n));
}

static int program_finish(struct nlr_program_state *state,
                          const struct nlr_exec_services *svc, int result)
{
    /* A resident extension's blocks were handed over; the loader clears the
     * state after registering them. */
    if (state->kept)
        return result;
    if (!state->code_allocation)
        return result;
    if (state->returned && nlr_api_program_cleanup(state) != NLR_OK)
        return NLR_EXEC_RESTORE;
    /* protect can fail after partially changing mappings; recovery is
     * mandatory even when the original transition reported an error. */
    if (state->permissions_touched &&
        (svc->protect(state->code_page, state->region_bytes,
                      svc->flag_writable) != 0 ||
         svc->audit(state->code_page, state->region_bytes,
                    svc->flag_writable) != 0))
        return NLR_EXEC_RESTORE;
    state->permissions_touched = 0;
    /* Both complete regions belong to the same original allocation. Audit
     * the unchanged RW data region before releasing that owner exactly
     * once; a failed audit or release retains both regions. */
    if (state->data_allocation) {
        if (svc->audit(state->data_page, state->region_bytes,
                       svc->flag_writable) != 0)
            return NLR_EXEC_RESTORE;
    }
    if (svc->release(state->code_allocation) != 0)
        return NLR_EXEC_RESTORE;
    state->code_allocation = 0;
    state->data_allocation = 0;
    state->allocation_bytes = 0;
    state->code_page = 0;
    state->data_page = 0;
    return result;
}

int nlr_program_finish_stopped(struct nlr_program_state *state,
                               const struct nlr_exec_services *svc)
{
    if (!state || !svc || state->kept || !state->entry_started ||
        __atomic_load_n(&state->api_active, __ATOMIC_ACQUIRE))
        return NLR_EXEC_RESTORE;
    __atomic_store_n(&state->jump_armed, 0u, __ATOMIC_RELEASE);
    state->exit_requested = 1;
    state->exit_code = 0;
    state->returned = 1;
    state->phase = 'R';
    return program_finish(state, svc, NLR_OK);
}

/* The regions placed exactly: a filler block takes the bytes in front of
 * the next `region` boundary, so the regions' own allocation starts on it
 * and asks for `needed` and no more. A head node too small for filler and
 * regions together is held out of the way first, as acquire_region does.
 * Every grant is read back before it is trusted; the filler and the held
 * nodes go back at the end, so the program can have them. NLR_BOUNDS asks
 * the caller for the slack method instead; NLR_EXEC_RESTORE as in
 * acquire_region. */
static int acquire_exact(const struct nlr_exec_services *svc, uint32_t region,
                         uint32_t needed, void **out_allocation,
                         uint8_t **out_page)
{
    void *held[NLR_EXEC_GRANT_TRIES + 1];
    uint32_t held_count = 0;
    int result = NLR_BOUNDS;
    *out_allocation = 0;
    *out_page = 0;
    if (!svc->grant_next || !svc->grant_probe || !svc->grant_end)
        return NLR_BOUNDS;
    for (uint32_t attempt = 0; attempt < NLR_EXEC_GRANT_TRIES; attempt++) {
        uint64_t guard = 0;
        uint64_t next = svc->grant_next(&guard);
        uint32_t usable = svc->grant_probe(0xfffff000u);
        if (!next || !usable)
            break;
        uint64_t start = (next + region - 1u) & ~(uint64_t)(region - 1u);
        uint64_t front = start - next;
        /* A filler needs a page of its own besides its guard. */
        if (front && front < guard + NLR_EXEC_PAGE_SIZE) {
            start += region;
            front += region;
        }
        if (front + needed > usable) {
            /* Not enough in this node: hold it out of the way whole. */
            void *obstacle = 0;
            if (svc->allocate(usable, &obstacle) != 0 || !obstacle)
                break;
            held[held_count++] = obstacle;
            uint64_t end = svc->grant_end(obstacle);
            if (!end || end < (uint64_t)(uintptr_t)obstacle + usable) {
                nlr_exec_resident_recheck(svc);
                break;
            }
            continue;
        }
        if (front) {
            void *filler = 0;
            uint32_t bytes = (uint32_t)(front - guard);
            if (svc->allocate(bytes, &filler) != 0 || !filler)
                break;
            held[held_count++] = filler;
            uint64_t end = svc->grant_end(filler);
            if (!end || end < (uint64_t)(uintptr_t)filler + bytes) {
                nlr_exec_resident_recheck(svc);
                break;
            }
        }
        void *allocation = 0;
        if (svc->allocate(needed, &allocation) != 0 || !allocation)
            break;
        uint64_t granted = svc->grant_end(allocation);
        if ((uint64_t)(uintptr_t)allocation != start || !granted ||
            granted < start + needed) {
            if (!granted || granted < (uint64_t)(uintptr_t)allocation + needed)
                nlr_exec_resident_recheck(svc);
            /* Not where the books said: it goes back with the rest, and the
             * slack method runs. */
            held[held_count++] = allocation;
            break;
        }
        *out_allocation = allocation;
        *out_page = (uint8_t *)allocation;
        result = NLR_OK;
        break;
    }
    for (uint32_t n = 0; n < held_count; n++)
        if (svc->release(held[n]) != 0) {
            /* The regions, if they were had, are the caller's to record; a
             * block that cannot go back is the owner that stops later runs. */
            if (result != NLR_OK) {
                *out_allocation = held[n];
                *out_page = 0;
            }
            return NLR_EXEC_RESTORE;
        }
    return result;
}

static int allocate_program_regions(struct nlr_program_state *state,
                                     const struct nlr_exec_services *svc,
                                     uint32_t regions)
{
    uint32_t region = state->region_bytes;
    uint32_t needed = regions * region;
    if (svc->allocate_aligned) {
        /* The heap places the regions itself and keeps nothing in front of
         * the boundary or past the end: a resident holds its regions and no
         * more for its whole life. An answer that is not on the boundary
         * goes straight back; a refusal falls through to the methods below,
         * whose larger request a fragmented heap may still meet. */
        void *allocation = 0;
        if (svc->allocate_aligned(region, needed, &allocation) == 0 && allocation) {
            if (((uintptr_t)allocation & (uintptr_t)(region - 1u)) == 0) {
                state->code_allocation = allocation;
                state->code_page = (uint8_t *)allocation;
                state->allocation_bytes = needed;
                return NLR_OK;
            }
            if (svc->release(allocation) != 0) {
                state->code_allocation = allocation;
                state->allocation_bytes = needed;
                return NLR_EXEC_RESTORE;
            }
        }
    }
    int exact = acquire_exact(svc, region, needed, &state->code_allocation,
                              &state->code_page);
    if (exact == NLR_OK) {
        state->allocation_bytes = needed;
        return NLR_OK;
    }
    if (exact == NLR_EXEC_RESTORE)
        return exact;
    /* Books that can place a grant are the Z 6III heap's, and that heap
     * never merges a released block back into its neighbours: an unaligned
     * first answer given back splits the node it came from, and a larger
     * retry no longer fits anywhere. There the address-independent maximum
     * goes first. Elsewhere a smaller allowance first, then the maximum. Each
     * returned allocation is checked afresh: releasing the first does not
     * guarantee the next call returns the same address. No bytes or mapping
     * are touched until every complete region fits inside what the
     * allocator granted (see acquire_region). */
    for (uint32_t attempt = 0; attempt < 2u; attempt++) {
        uint32_t allowance = (attempt == 0u) == (svc->grant_next != 0)
                                 ? region : region / 2u;
        uint32_t request = needed + allowance - 1u;
        int result = acquire_region(svc, svc->allocate, svc->release,
                                    request, region, needed,
                                    &state->code_allocation,
                                    &state->code_page);
        if (state->code_allocation)
            state->allocation_bytes = request;
        if (result == NLR_OK)
            return NLR_OK;
        /* A failed release leaves the exact original owner recorded. Do not
         * feed it to program_finish or make a second release attempt. */
        if (result == NLR_EXEC_RESTORE)
            return result;
        state->allocation_bytes = 0;
        if (result != NLR_BOUNDS)
            return program_finish(state, svc, result);
    }
    return NLR_BOUNDS;
}

/* The flat layout (segments->flat): one region, the image at its start,
 * the data from the next page boundary -- so the low 12 bits the link fixed
 * for every data reference stay right -- and every relocation aimed into
 * that one region. Only a resident extension, only with no BSS: its data
 * ends up read-only with the code, which is what a loader built without
 * writable data (nlr/stage0.h) expects. */
static int program_run_flat(struct nlr_program_state *state,
                            const struct nlr_exec_services *svc,
                            const struct nlr_program_segments *segments,
                            const struct nlr_api *api)
{
    uint64_t data_offset = ((uint64_t)segments->image_size + NLR_EXEC_PAGE_SIZE - 1u) &
                           ~(uint64_t)(NLR_EXEC_PAGE_SIZE - 1u);
    if (segments->kind != 1u || !svc->extension_call || segments->bss_size ||
        segments->image_size < 4u || (segments->entry_offset & 3u) ||
        segments->entry_offset > segments->image_size - 4u ||
        data_offset + segments->data_size > svc->region_bytes ||
        segments->reloc_size % NLR_RELOC_ENTRY_SIZE != 0 ||
        (segments->reloc_size && !segments->reloc) ||
        (segments->data_size && !segments->data))
        return NLR_BOUNDS;
    state->region_bytes = svc->region_bytes;
    state->phase = 'A';
    state->prepared = state->entry_started = state->returned = 0;
    state->permissions_touched = state->kept = state->exit_requested = 0;
    state->exit_code = 0;
    __atomic_store_n(&state->jump_armed, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&state->api_active, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&state->stop_requested, 0u, __ATOMIC_RELAXED);
    state->code_allocation = state->data_allocation = 0;
    state->allocation_bytes = 0;
    state->code_page = state->data_page = 0;
    int allocated = allocate_program_regions(state, svc, 1u);
    if (allocated != NLR_OK)
        return allocated;
    state->phase = 'U';
    if (svc->audit(state->code_page, state->region_bytes, svc->flag_writable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'W';
    state->permissions_touched = 1;
    if (svc->protect(state->code_page, state->region_bytes, svc->flag_writable) != 0 ||
        svc->audit(state->code_page, state->region_bytes, svc->flag_writable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'D';
    uint8_t *data = state->code_page + data_offset;
    for (uint32_t i = 0; i < segments->image_size; i++)
        state->code_page[i] = segments->image[i];
    for (uint64_t i = segments->image_size; i < data_offset; i++)
        state->code_page[i] = 0;
    for (uint32_t i = 0; i < segments->data_size; i++)
        data[i] = segments->data[i];
    for (uint32_t n = 0; n < segments->reloc_size; n += NLR_RELOC_ENTRY_SIZE) {
        const uint8_t *entry = segments->reloc + n;
        uint32_t offset = nlr_le32(entry), target = nlr_le32(entry + 4);
        uint32_t kind = nlr_le32(entry + 8);
        if (kind == NLR_RELOC_ADRP) {
            int result = nlr_program_patch_adrp(state->code_page, offset, data, target);
            if (result != NLR_OK)
                return program_finish(state, svc, result);
        } else if (kind == NLR_RELOC_ABS64) {
            patch_abs64(data, offset, state->code_page, target);
        } else if (kind == NLR_RELOC_ABS64_DATA) {
            patch_abs64(data, offset, data, target);
        } else {
            return program_finish(state, svc, NLR_FORMAT);
        }
    }
    state->phase = 'C';
    if (svc->clean(state->code_page, state->region_bytes) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'X';
    if (svc->protect(state->code_page, state->region_bytes, svc->flag_executable) != 0 ||
        svc->audit(state->code_page, state->region_bytes, svc->flag_executable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'I';
    if (svc->invalidate_code(state->code_page, data_offset + segments->data_size) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->prepared = 1;
    if (segments->consumed)
        segments->consumed(segments->consumed_context);
    state->phase = 'E';
    state->entry_started = 1;
    uint32_t started = 0;
    int result = svc->extension_call(state->code_page + segments->entry_offset,
                                     (uint64_t)(uintptr_t)api, &state->exit_code, &started);
    state->entry_started = started != 0;
    if (result != NLR_OK || !started) {
        state->kept = state->entry_started;
        return program_finish(state, svc, result == NLR_OK ? NLR_NOT_READY : result);
    }
    state->returned = 1;
    state->phase = 'R';
    state->kept = 1;
    return state->exit_code == 0 ? NLR_OK : NLR_EXEC_APP;
}

int nlr_program_run(struct nlr_program_state *state,
                    const struct nlr_exec_services *svc,
                    const struct nlr_program_segments *segments,
                    const struct nlr_api *api, uint32_t prepare_only)
{
    if (!state || !segments || !api || !svc || !svc->allocate ||
        !svc->release || !svc->audit || !svc->protect || !svc->clean ||
        !svc->invalidate_code || !svc->call)
        return NLR_NOT_READY;
    if (svc->region_bytes != NLR_EXEC_PAGE_SIZE &&
        svc->region_bytes != NLR_EXEC_BLOCK_SIZE)
        return NLR_NOT_READY;
    /* A missing or collapsed encoding can never name two permissions; refuse
     * it before any allocation so the neutral table stays unreachable. */
    if (!svc->flag_writable || !svc->flag_executable ||
        svc->flag_writable == svc->flag_executable)
        return NLR_NOT_READY;
    if (state->code_allocation)
        return NLR_BUSY;
    if (segments->flat)
        return prepare_only ? NLR_FORMAT : program_run_flat(state, svc, segments, api);
    if (segments->kind != 1u && segments->kind != 2u)
        return NLR_FORMAT;
    if (segments->kind == 1u && !prepare_only && !svc->extension_call)
        return NLR_NOT_READY;
    if (segments->image_size < 4u || (segments->entry_offset & 3u) ||
        segments->entry_offset > segments->image_size - 4u)
        return NLR_BOUNDS;
    if (segments->image_size > svc->region_bytes ||
        segments->reloc_size % NLR_RELOC_ENTRY_SIZE != 0 ||
        (segments->reloc_size && !segments->reloc))
        return NLR_FORMAT;
    uint64_t data_total =
        (uint64_t)segments->data_size + segments->bss_size;
    if (data_total > svc->region_bytes ||
        (segments->data_size && !segments->data))
        return NLR_BOUNDS;
    if (!data_total && segments->reloc_size)
        /* Without a data block no relocation can point anywhere legal. */
        return NLR_BOUNDS;

    state->region_bytes = svc->region_bytes;
    state->phase = 'A';
    state->prepared = state->entry_started = state->returned = 0;
    state->permissions_touched = state->kept = state->exit_requested = 0;
    state->exit_code = 0;
    __atomic_store_n(&state->jump_armed, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&state->api_active, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&state->stop_requested, 0u, __ATOMIC_RELAXED);
    state->code_allocation = state->data_allocation = 0;
    state->allocation_bytes = 0;
    state->code_page = state->data_page = 0;

    /* The allocator owns the complete adjacent regions and unused edges;
     * neither permission granule shares storage with an unrelated owner. */
    uint32_t regions = data_total ? 2u : 1u;
    int allocated = allocate_program_regions(state, svc, regions);
    if (allocated != NLR_OK)
        return allocated;
    state->phase = 'U';
    if (svc->audit(state->code_page, state->region_bytes,
                   svc->flag_writable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    if (data_total) {
        state->data_allocation = state->code_allocation;
        state->data_page = state->code_page + state->region_bytes;
        if (svc->audit(state->data_page, state->region_bytes,
                       svc->flag_writable) != 0)
            return program_finish(state, svc, NLR_NOT_READY);
    }
    state->phase = 'W';
    state->permissions_touched = 1;
    if (svc->protect(state->code_page, state->region_bytes,
                     svc->flag_writable) != 0 ||
        svc->audit(state->code_page, state->region_bytes,
                   svc->flag_writable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'D';
    for (uint32_t i = 0; i < segments->image_size; i++)
        state->code_page[i] = segments->image[i];
    /* ADRP entries are patched while the code block is writable; their
     * targets can name initialized data and BSS alike. */
    for (uint32_t n = 0; n < segments->reloc_size;
         n += NLR_RELOC_ENTRY_SIZE) {
        const uint8_t *entry = segments->reloc + n;
        uint32_t offset = nlr_le32(entry);
        uint32_t target = nlr_le32(entry + 4);
        uint32_t kind = nlr_le32(entry + 8);
        if (kind == NLR_RELOC_ADRP) {
            int result = nlr_program_patch_adrp(state->code_page, offset,
                                                state->data_page, target);
            if (result != NLR_OK)
                return program_finish(state, svc, result);
        }
    }
    if (data_total) {
        for (uint32_t i = 0; i < segments->data_size; i++)
            state->data_page[i] = segments->data[i];
        /* BSS is zeroed here: a fresh allocation holds arbitrary bytes. */
        for (uint32_t i = 0; i < segments->bss_size; i++)
            state->data_page[segments->data_size + i] = 0;
        /* ABS64 entries write into the data block after its contents are
         * in place, while it is still writable: kind 1 a code address,
         * kind 2 an address in the data block itself. */
        for (uint32_t n = 0; n < segments->reloc_size;
             n += NLR_RELOC_ENTRY_SIZE) {
            const uint8_t *entry = segments->reloc + n;
            uint32_t kind = nlr_le32(entry + 8);
            if (kind == NLR_RELOC_ABS64)
                patch_abs64(state->data_page, nlr_le32(entry),
                            state->code_page, nlr_le32(entry + 4));
            else if (kind == NLR_RELOC_ABS64_DATA)
                patch_abs64(state->data_page, nlr_le32(entry),
                            state->data_page, nlr_le32(entry + 4));
        }
    }
    state->phase = 'C';
    if (svc->clean(state->code_page, state->region_bytes) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    if (state->data_page &&
        svc->clean(state->data_page, state->region_bytes) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'X';
    if (svc->protect(state->code_page, state->region_bytes,
                     svc->flag_executable) != 0 ||
        svc->audit(state->code_page, state->region_bytes,
                   svc->flag_executable) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->phase = 'I';
    if (svc->invalidate_code(state->code_page, segments->image_size) != 0)
        return program_finish(state, svc, NLR_NOT_READY);
    state->prepared = 1;
    if (prepare_only)
        return program_finish(state, svc, NLR_OK);
    if (segments->consumed)
        segments->consumed(segments->consumed_context);
    if (state->data_allocation) {
        /* The data block stays writable for the whole run (PLAN 6.3): only
         * the code block changes permission. */
        state->phase = 'B';
        if (svc->audit(state->data_page, state->region_bytes,
                       svc->flag_writable) != 0)
            return program_finish(state, svc, NLR_NOT_READY);
    }
    state->phase = 'E';
    /* x0 carries the API table address for both entry kinds; the probe's
     * challenge slot of the call service carries it through. */
    uint64_t argument = (uint64_t)(uintptr_t)api;
    if (segments->kind == 2u) {
        state->entry_started = 1;
        /* Foreground: api->exit must abort the application without
         * returning into it (PLAN 5.1). The context is armed only for this
         * call; a resource extension's exit request is recorded and
         * ignored, never followed. */
        __atomic_store_n(&state->jump_armed, 1u, __ATOMIC_RELEASE);
        if (nlr_program_setjmp(state->context) == 0) {
            /* x0 carries the int32_t result; the upper half is unspecified. */
            state->exit_code =
                (int32_t)(uint32_t)svc->call(
                    state->code_page + segments->entry_offset, argument);
            state->returned = 1;
        } else {
            /* Arrived through api->exit; the code is already recorded and
             * the application's frames are abandoned. */
            state->returned = 1;
        }
        __atomic_store_n(&state->jump_armed, 0u, __ATOMIC_RELEASE);
    } else {
        /* Expose the worker's init window to the registration API. The
         * injected call reports whether it actually started before return. */
        state->entry_started = 1;
        uint32_t started = 0;
        int result = svc->extension_call(
            state->code_page + segments->entry_offset, argument,
            &state->exit_code, &started);
        state->entry_started = started != 0;
        if (result != NLR_OK || !started) {
            /* Refused before entry: safe cleanup. An uncertain started call
             * retains its blocks; neither rollback nor another init is safe. */
            state->kept = state->entry_started;
            return program_finish(state, svc,
                                  result == NLR_OK ? NLR_NOT_READY : result);
        }
        state->returned = 1;
    }
    state->phase = 'R';
    if (segments->kind == 1u) {
        /* Initialization has ended either way: the blocks stay resident —
         * code still executable, data still writable — and the loader
         * registers their ownership; a nonzero result only marks the record
         * (possibly partially effective). Nothing is restored or released. */
        state->kept = 1;
        return state->exit_code == 0 ? NLR_OK : NLR_EXEC_APP;
    }
    return program_finish(state, svc,
                          state->exit_code == 0 ? NLR_OK : NLR_EXEC_APP);
}

#endif
