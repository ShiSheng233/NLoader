#include "nlr/text.h"
#include "nlr/runtime.h"

extern const struct nlr_services nlr_services;

#if defined(NLR_STAGE_PAGE) || defined(NLR_STAGE_LOAD_ONLY) || \
    defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
#define PRIVATE_TEXT_DYNAMIC 1
#endif

static int valid_style(uint32_t style)
{
    return style == 3u || style == 4u;
}

static int rom_label_valid(const char *text)
{
    if (!text || !text[0])
        return 0;
    for (uint32_t n = 1; n < NLR_PRIVATE_TEXT_BYTES; n++)
        if (!text[n])
            return 1;
    return 0;
}

int nlr_private_text_token(uint32_t token, uint32_t *index)
{
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    if (s->count != NLR_PRIVATE_TEXT_COUNT || s->token_base < 65535u ||
        s->token_base > INT32_MAX - NLR_PRIVATE_TEXT_COUNT ||
        token - s->token_base >= NLR_PRIVATE_TEXT_COUNT)
        return 0;
    if (index)
        *index = token - s->token_base;
    return 1;
}

int nlr_private_text_services_ready(void)
{
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    return nlr_private_text_token(s->token_base, 0) &&
        s->title_index == 64u && s->status_index == 65u && s->entry_index == 66u &&
        s->apps_index == 67u && rom_label_valid(s->rom_apps) &&
        valid_style(s->row_style) && valid_style(s->title_style) &&
        valid_style(s->entry_style) && s->native_getter && s->native_ascii &&
        s->ascii_copy && s->low_get && s->low_set &&
        rom_label_valid(s->rom_entry) && rom_label_valid(s->rom_title) &&
        rom_label_valid(s->rom_status) && rom_label_valid(s->rom_failure) &&
        s->current_task && s->task_name;
}

static int gui_owner(void)
{
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    uint32_t id = 0;
    if (!s->current_task || !s->task_name || !nlr_services.registry_lookup ||
        s->current_task(&id) != 0 || id == 0 || id > NLR_REGISTRY_IDS)
        return 0;
    void *object = 0;
    nlr_services.registry_lookup(NLR_REGISTRY_TYPE_TASK, id, &object);
    if (!object || ((uintptr_t)object & 7u))
        return 0;
    const volatile uint8_t *task = object;
    if (*(const volatile uint32_t *)(task + NLR_WORKER_ID_OFFSET) != id)
        return 0;
    for (uint32_t n = 0; n < NLR_TASK_NAME_SIZE; n++)
        if (task[NLR_WORKER_NAME_OFFSET + n] != (uint8_t)s->task_name[n])
            return 0;
    return *(const volatile uint64_t *)(task + NLR_WORKER_SELF_OFFSET) ==
        (uintptr_t)object;
}

static uint32_t initial_style(uint32_t index)
{
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    return index == s->title_index ? s->title_style :
           index == s->entry_index || index == s->apps_index ? s->entry_style :
           s->row_style;
}

static const char *initial_text(uint32_t index)
{
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    return index == s->title_index ? s->rom_title :
           index == s->status_index ? s->rom_status :
           index == s->entry_index ? s->rom_entry :
           index == s->apps_index ? s->rom_apps : s->rom_failure;
}

static int descriptor_valid(const struct nlr_private_text_pool *pool,
                             uint32_t index)
{
    const struct nlr_private_text_descriptor *d = &pool->descriptors[index];
    return d->buffer == pool->buffers[index] &&
        d->length < NLR_PRIVATE_TEXT_BYTES && valid_style(d->style) &&
        !d->buffer[d->length] && !d->reserved && !d->reserved_tail;
}

int nlr_private_text_pool_prepare(struct nlr_runtime *r,
                                  const struct nlr_services *svc)
{
#if NLR_HAS_PRIVATE_TEXT
    if (!r || !svc || !svc->release || r->private_text ||
        !nlr_private_text_services_ready() || !gui_owner())
        return NLR_NOT_READY;
    void *memory = nlr_alloc_whole(svc, sizeof(struct nlr_private_text_pool));
    if (!memory || ((uintptr_t)memory & 7u)) {
        if (memory)
            svc->release(memory);
        return NLR_NOT_READY;
    }
    struct nlr_private_text_pool *pool = memory;
    for (size_t n = 0; n < sizeof *pool; n++)
        ((uint8_t *)pool)[n] = 0;
    pool->owner = r;
    pool->services = &nlr_private_text_services;
    pool->last_result = NLR_NOT_READY;
    for (uint32_t index = 0; index < NLR_PRIVATE_TEXT_COUNT; index++) {
        pool->descriptors[index].buffer = pool->buffers[index];
        nlr_private_text_services.ascii_copy(initial_text(index), index,
            initial_style(index), pool->descriptors);
        if (!descriptor_valid(pool, index)) {
            svc->release(pool);
            return NLR_NOT_READY;
        }
    }
    /* The runtime owns even an unpublished/partial pool. Getter cannot use
     * it until task registration succeeds and ready is release-published. */
    r->private_text = pool;
    return NLR_OK;
#else
    (void)r;
    (void)svc;
    return NLR_NOT_READY;
#endif
}

void nlr_private_text_pool_publish(struct nlr_runtime *r)
{
#if NLR_HAS_PRIVATE_TEXT
    if (r && r->private_text && r->private_text->owner == r &&
        r->private_text->services == &nlr_private_text_services &&
        nlr_runtime_find(&nlr_services, 0) == r &&
        !__atomic_load_n(&r->private_text->failed, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&r->load.ready, __ATOMIC_ACQUIRE)) {
        r->private_text->last_result = NLR_OK;
        __atomic_store_n(&r->private_text->ready, 1u, __ATOMIC_RELEASE);
    }
#else
    (void)r;
#endif
}

int nlr_private_text_pool_ready(const struct nlr_runtime *r)
{
#if NLR_HAS_PRIVATE_TEXT
    if (!r || !r->private_text || !nlr_private_text_services_ready() ||
        !__atomic_load_n(&r->load.ready, __ATOMIC_ACQUIRE))
        return 0;
    const struct nlr_private_text_pool *pool = r->private_text;
    if (pool->owner != r || pool->services != &nlr_private_text_services ||
        !__atomic_load_n(&pool->ready, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&pool->failed, __ATOMIC_ACQUIRE))
        return 0;
    for (uint32_t index = 0; index < NLR_PRIVATE_TEXT_COUNT; index++)
        if (!descriptor_valid(pool, index))
            return 0;
    return 1;
#else
    (void)r;
    return 0;
#endif
}

static struct nlr_runtime *text_owner(void)
{
#if defined(PRIVATE_TEXT_DYNAMIC)
    return nlr_runtime_find(&nlr_services, 0);
#else
    return 0;
#endif
}

static int32_t record_failure(struct nlr_runtime *r, int32_t result)
{
#if NLR_HAS_PRIVATE_TEXT
    if (r && r->private_text && r->private_text->owner == r &&
        r->private_text->services == &nlr_private_text_services) {
        if (!__atomic_load_n(&r->private_text->failed, __ATOMIC_ACQUIRE))
            __atomic_store_n(&r->private_text->last_result, result, __ATOMIC_RELAXED);
        __atomic_add_fetch(&r->private_text->rejected_calls, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&r->private_text->failed, 1u, __ATOMIC_RELEASE);
    }
#else
    (void)r;
#endif
    return result;
}

static void rom_result(uint32_t index, char **buffer,
                        uint32_t *length, uint32_t *style)
{
    static const char unavailable[] = "Loader text unavailable";
    const struct nlr_private_text_services *s = &nlr_private_text_services;
    const char *text = rom_label_valid(s->rom_failure) ? s->rom_failure : unavailable;
    uint32_t format = index == 64u ? 3u : 4u;
    if (index == s->entry_index && rom_label_valid(s->rom_entry)) {
        text = s->rom_entry;
        format = valid_style(s->entry_style) ? s->entry_style : 4u;
    }
    /* Setup's other row: before any pool exists it must still read its own
     * label, never the failure text. */
    else if (index == s->apps_index && rom_label_valid(s->rom_apps)) {
        text = s->rom_apps;
        format = valid_style(s->entry_style) ? s->entry_style : 4u;
    }
#ifndef PRIVATE_TEXT_DYNAMIC
    else if (nlr_private_text_services_ready()) {
        text = index < 64u ? s->rom_status : initial_text(index);
        format = initial_style(index);
    }
#endif
    uint32_t bytes = 0;
    while (text[bytes] && bytes + 1u < NLR_PRIVATE_TEXT_BYTES)
        bytes++;
    *buffer = (char *)text; /* Original getter ABI is char**, renderer reads. */
    *length = bytes;
    *style = format;
}

void nlr_private_text_getter(uint32_t *token, char **buffer,
                            uint32_t *length, uint32_t *style)
{
    if (!token || !buffer || !length || !style)
        return;
    uint32_t index;
    if (!nlr_private_text_token(*token, &index)) {
        if (nlr_private_text_services.native_getter)
            nlr_private_text_services.native_getter(token, buffer, length, style);
        return;
    }
#if NLR_HAS_PRIVATE_TEXT && defined(PRIVATE_TEXT_DYNAMIC)
    struct nlr_runtime *r = text_owner();
    if (nlr_private_text_pool_ready(r)) {
        const struct nlr_private_text_descriptor *d = &r->private_text->descriptors[index];
        *buffer = d->buffer;
        *length = d->length;
        *style = d->style;
        return;
    }
#endif
    rom_result(index, buffer, length, style);
}

int32_t nlr_private_text_writer(const char *text, uint32_t token, uint32_t style)
{
    uint32_t index;
    if (!nlr_private_text_token(token, &index)) {
        if (nlr_private_text_services.native_ascii)
            nlr_private_text_services.native_ascii(text, token, style);
        return NLR_OK; /* Preserve the original non-private void writer. */
    }
    struct nlr_runtime *r = text_owner();
    if (!text || !valid_style(style))
        return record_failure(r, NLR_BOUNDS);
    if (!gui_owner())
        return record_failure(r, NLR_REFUSED);
    if (!nlr_private_text_pool_ready(r))
        return record_failure(r, NLR_NOT_READY);
#if NLR_HAS_PRIVATE_TEXT
    nlr_private_text_services.ascii_copy(text, index, style, r->private_text->descriptors);
    if (!descriptor_valid(r->private_text, index) ||
        !nlr_private_text_pool_ready(r))
        return record_failure(r, NLR_NOT_READY);
    return NLR_OK;
#else
    (void)index;
    return NLR_NOT_READY;
#endif
}

int32_t nlr_private_text_reject(uint32_t token, uint32_t kind)
{
    if (!nlr_private_text_token(token, 0))
        return NLR_REFUSED;
    (void)kind; /* This build supports only private ASCII, never type 4. */
    return record_failure(text_owner(), NLR_REFUSED);
}

int nlr_private_text_bind(void *widget, uint32_t token)
{
    if (!widget || !nlr_private_text_token(token, 0) ||
        !nlr_private_text_services_ready())
        return NLR_NOT_READY;
    if (!gui_owner())
        return record_failure(text_owner(), NLR_REFUSED);
    uint32_t type = 0, previous = 0;
    nlr_private_text_services.low_get(widget, &type, &previous);
    if (type != 3u)
        return record_failure(text_owner(), NLR_REFUSED);
    /* Always invoke the native setter: it invalidates a cached text object
     * before comparing tokens, including an unchanged private token. */
    if (nlr_private_text_services.low_set(widget, 3u, token) != 1)
        return record_failure(text_owner(), NLR_NOT_READY);
    return NLR_OK;
}

void nlr_private_text_seed(const char *text, uint32_t style)
{
    if (!text || !valid_style(style) || !nlr_private_text_services_ready())
        return;
    char buffer[NLR_PRIVATE_TEXT_BYTES];
    struct nlr_private_text_descriptor descriptor = {0, 0, buffer, 0, 0};
    nlr_private_text_services.ascii_copy(text, 0, style, &descriptor);
}
