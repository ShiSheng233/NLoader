#include "nlr/paint.h"
#include "nlr/runtime.h"

extern const struct nlr_services nlr_services;
extern const struct nlr_paint_services nlr_paint_services;

static uint32_t word(const uint8_t *p, uint32_t at)
{
    uint32_t value = 0;
    for (uint32_t n = 0; n < 4; n++) value |= (uint32_t)p[at + n] << (n * 8);
    return value;
}
static uint64_t wide(const uint8_t *p, uint32_t at)
{
    uint64_t value = 0;
    for (uint32_t n = 0; n < 8; n++) value |= (uint64_t)p[at + n] << (n * 8);
    return value;
}
static void put(uint8_t *p, uint32_t at, uint64_t value, uint32_t bytes)
{
    for (uint32_t n = 0; n < bytes; n++) p[at + n] = (uint8_t)(value >> (n * 8));
}

static struct nlr_paint_probe *probe(struct nlr_runtime *r)
{
    if (r->paint_probe) return r->paint_probe;
    void *allocation = nlr_alloc_whole(&nlr_services, sizeof(struct nlr_paint_probe) + 63u);
    if (!allocation)
        return 0;
    struct nlr_paint_probe *p = (void *)(((uintptr_t)allocation + 63u) & ~(uintptr_t)63u);
    uint8_t *data = (void *)p;
    for (uint32_t n = 0; n < sizeof *p; n++) data[n] = 0;
    p->magic = NLR_PAINT_MAGIC; p->allocation = allocation;
    for (uint32_t y = 0; y < 16; y++) for (uint32_t x = 0; x < 16; x++) {
        uint32_t pixel = ((x / 4u + y / 4u) & 1u) ? UINT32_C(0x88888888) : UINT32_MAX;
        if (nlr_paint_services.pattern == 2u)
            /* Native format 1 consumes bytes R,G,B,A on this little-endian
             * family; the integer spelling must preserve that byte order. */
            pixel = x < 5 ? UINT32_C(0xff0000ff) : x < 11 ? UINT32_C(0xff00ff00) : UINT32_C(0xffff0000);
        p->pixels[y * 16u + x] = pixel;
    }
    if (nlr_paint_services.pattern) nlr_paint_services.clean_source(p->pixels, sizeof p->pixels);
    r->paint_probe = p;
    return p;
}

int32_t nlr_paint_text_observe(void *widget, void *draw, uint32_t a, uint32_t b)
{
    const struct nlr_paint_services *s = &nlr_paint_services;
    uint32_t task = 0;
    int32_t task_result = s->current_task(&task);
    void *object = 0;
    if (!task_result && task) nlr_services.registry_lookup(0, task, &object);
    uint32_t matched = 0;
    if (object && !((uintptr_t)object & 7u)) {
        const uint8_t *w = object;
        while (matched < 8u && w[NLR_WORKER_NAME_OFFSET + matched] == (uint8_t)s->task_name[matched]) matched++;
        if (word(w, 0) != task || wide(w, NLR_WORKER_SELF_OFFSET) != (uintptr_t)object) matched = 0;
    }
    /* One verified GUI task owns this record and its immutable source. */
    struct nlr_runtime *r = matched == 8u ? nlr_runtime_find(&nlr_services, 0) : 0;
    struct nlr_paint_probe *p = r ? probe(r) : 0;
    void *window = s->current_window();
    void *root = widget ? s->widget_root(widget) : 0;
    uint32_t type = root ? word(root, 0x108) : UINT32_MAX;
    uint32_t group = root ? word(root, 0x10c) : 0;
    uint32_t index = root ? word(root, 0x110) : UINT32_MAX;
    /* The original root selector indexes a group table without a full bound.
     * Only the exact checked group is queried; trace may leave it unknown. */
    const uint8_t *record = root && type <= 2u && group && group == s->surface_group && index <= 4u ?
        s->surface_record(type, group, index) : 0;
    uint64_t target = record ? wide(record, 0x28) : 0;
    if (p) {
        p->calls++; p->nloader_calls += window == s->window;
        p->task = task; p->task_result = task_result; p->task_object = (uintptr_t)object;
        p->window_object = (uintptr_t)window; p->widget = (uintptr_t)widget; p->draw = (uintptr_t)draw;
        p->root = (uintptr_t)root; p->root_type = type; p->root_group = group; p->root_index = index;
        p->record = (uintptr_t)record; p->target = target; p->a = a; p->b = b;
    }
    int32_t result = s->text_draw(widget, draw, a, b);
    if (!p) return result;
    uint64_t surface = 0;
    int32_t surface_result = s->current_surface(0, &surface);
    uint32_t after_task = 0;
    int32_t after_task_result = s->current_task(&after_task);
    uint32_t graphics_index = s->current_index();
    p->original_result = result; p->surface_result = surface_result;
    p->after_surface = surface; p->index = graphics_index;
    if (!s->pattern || s->pattern > 2u || task_result || after_task_result || task != after_task ||
        window != s->window || s->current_window() != window ||
        !target || surface_result || surface != target || graphics_index >= 33u ||
        s->widget_root(widget) != root || type != 1u || group != 1u || index != 1u ||
        word(root, 0x108) != type || word(root, 0x10c) != group || word(root, 0x110) != index ||
        s->surface_record(type, group, index) != record || wide(record, 0x28) != target ||
        (word(record, 8u) & 0xffffu) < 148u || (word(record, 8u) >> 16) < 148u)
        return result;
    uint8_t bitmap[0x58] = {0};
    put(bitmap, 0, 1, 4); put(bitmap, 8, (uintptr_t)p->pixels, 8);
    put(bitmap, 0x10, 16, 2); put(bitmap, 0x12, 16, 2); put(bitmap, 0x18, target, 8);
    /* The target setup consumes the whole surface's dimensions. Source crop
     * and destination rectangle are distinct from that target geometry. */
    put(bitmap, 0x20, word(record, 8u) & 0xffffu, 2);
    put(bitmap, 0x22, word(record, 8u) >> 16, 2);
    put(bitmap, 0x2c, 16, 2); put(bitmap, 0x2e, 16, 2);
    uint32_t target_width = word(record, 8u) & 0xffffu;
    uint32_t target_height = word(record, 8u) >> 16;
    put(bitmap, 0x30, s->full_screen ? 0u : 20u, 2);
    put(bitmap, 0x32, s->full_screen ? 0u : 20u, 2);
    put(bitmap, 0x34, s->full_screen ? target_width : 128u, 2);
    put(bitmap, 0x36, s->full_screen ? target_height : 128u, 2);
    put(bitmap, 0x3c, 255, 4);
    p->submitted++; s->blit(bitmap); p->completed++;
    return result;
}
