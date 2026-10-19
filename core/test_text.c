/* Host-only private namespace/owner integration. The real Core allocator,
 * registry discovery, lifetime and page paths are exercised through explicit
 * native-service models; this is not firmware or LCD acceptance. */
#include "nlr/runtime.h"
#include "nlr/text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_BASE (((uint32_t)'N' << 24) | ((uint32_t)'L' << 16))
#define TOKEN(index) (TOKEN_BASE + (index))
#define GUI_ID 55u /* deliberately synthetic; no model-specific task ID */

static uint32_t failures, allocations, releases, starts, copies, low_sets;
static uint32_t stock_gets, stock_writes, last_stock_token, task_queries;
static uint32_t current_id = GUI_ID, next_id = 100;
static int32_t current_status;
static int fail_allocation = -1, partial_worker, low_set_status = 1;
static void *memory[64];
static uint32_t memory_count;
static void *registry[NLR_REGISTRY_IDS + 1];
static _Alignas(8) uint8_t gui[NLR_WORKER_SIZE];
static uint8_t original_descriptors[300 * 24], original_buffers[300 * 51];
static uint8_t descriptor_baseline[sizeof original_descriptors];
static uint8_t buffer_baseline[sizeof original_buffers];

#define CHECK(value) do { if (!(value)) { \
    printf("FAIL %d: %s\n", __LINE__, #value); failures++; \
} } while (0)

static int32_t allocate(uint32_t bytes, void **out)
{
    allocations++;
    if (fail_allocation == 0) { *out = 0; return NLR_NOT_READY; }
    if (fail_allocation > 0)
        fail_allocation--;
    *out = calloc(1, bytes);
    CHECK(memory_count < 64);
    if (*out)
        memory[memory_count++] = *out;
    return *out ? NLR_OK : NLR_NOT_READY;
}

static int32_t release(void *object)
{
    CHECK(object != 0);
    for (uint32_t n = 0; n < memory_count; n++)
        if (memory[n] == object) { free(object); memory[n] = 0; releases++; return 0; }
    CHECK(0);
    return -1;
}

static void lookup(uint32_t type, uint32_t id, void **out)
{
    *out = type == NLR_REGISTRY_TYPE_TASK && id <= NLR_REGISTRY_IDS
               ? registry[id] : 0;
}

static void worker_init(void *worker, void (*callback)(void *, uint32_t),
                         uint32_t mask, struct nlr_task_config *config)
{
    CHECK(mask == NLR_LOAD_RUN_EVENT);
    uint32_t id = next_id++, flag = partial_worker ? 0 : id + 1;
    uintptr_t self = (uintptr_t)worker, function = (uintptr_t)callback;
    memcpy((uint8_t *)worker + NLR_WORKER_ID_OFFSET, &id, 4);
    memcpy((uint8_t *)worker + NLR_WORKER_FLAG_OFFSET, &flag, 4);
    memcpy((uint8_t *)worker + NLR_WORKER_NAME_OFFSET, config->name, 8);
    memcpy((uint8_t *)worker + NLR_WORKER_SELF_OFFSET, &self, 8);
    memcpy((uint8_t *)worker + NLR_WORKER_CALLBACK_OFFSET, &function, 8);
    registry[id] = worker;
}

static void worker_start(void *worker) { CHECK(worker != 0); starts++; }
static int32_t flag_set(void *flag, uint32_t value)
{ (void)flag; (void)value; CHECK(0); return -1; }
static int32_t get_task(uint32_t *id)
{ task_queries++; *id = current_id; return current_status; }

const struct nlr_services nlr_services = {
    .abi = 1, .alloc = allocate, .release = release,
    .worker_init = worker_init, .worker_start = worker_start,
    .registry_lookup = lookup, .flag_set = flag_set,
};
const struct nlr_task_config nlr_task_config = {
    .core = 3, .priority = 20, .stack_bytes = 32768,
    .name = {'N','L','O','A','D','E','R',0},
};
const struct nlr_identity nlr_identity = {"host", "test"};
const struct nlr_exec_services nlr_exec_services = {0};

static void native_get(uint32_t *token, char **buffer, uint32_t *length,
                        uint32_t *style)
{
    stock_gets++; last_stock_token = *token;
    /* Model the actual signed clamp; preserve negative native arguments. */
    if ((int32_t)*token >= 65535)
        *token = 0;
    *buffer = "stock"; *length = 5; *style = 4;
}

static void native_write(const char *text, uint32_t token, uint32_t style)
{ CHECK(text != 0); (void)style; stock_writes++; last_stock_token = token; }

static void copy_ascii(const char *text, uint32_t index, uint32_t style,
                        struct nlr_private_text_descriptor *base)
{
    CHECK(text && base && (style == 3 || style == 4));
    CHECK(index < NLR_PRIVATE_TEXT_COUNT);
    uint32_t bytes = (uint32_t)strlen(text);
    if (bytes > 50)
        bytes = 50;
    memcpy(base[index].buffer, text, bytes);
    base[index].buffer[bytes] = 0;
    base[index].length = bytes;
    base[index].style = style;
    copies++;
}

struct widget { uint32_t type, token, invalidations; };
static struct widget title = {3, 0, 0}, row = {3, TOKEN(0), 0};
static void low_get(const void *object, uint32_t *type, uint32_t *token)
{ const struct widget *w = object; *type = w->type; *token = w->token; }
static int32_t low_set(void *object, uint32_t type, uint32_t token)
{
    struct widget *w = object;
    CHECK(w->type == 3 && type == 3);
    if (low_set_status != 1)
        return low_set_status;
    w->type = type; w->token = token; w->invalidations++; low_sets++;
    return 1;
}

const struct nlr_private_text_services nlr_private_text_services = {
    .token_base = TOKEN_BASE, .count = 68, .row_first_item = 700,
    .entry_item_id = 800, .title_index = 64, .status_index = 65, .entry_index = 66,
    .row_style = 4, .title_style = 3, .entry_style = 4,
    .native_getter = native_get, .native_ascii = native_write,
    .ascii_copy = copy_ascii, .low_get = low_get, .low_set = low_set,
    .rom_entry = "NLoader", .rom_title = "NLoader", .rom_status = "Private page",
    .rom_failure = "Loader memory unavailable", .current_task = get_task,
    .task_name = "GUIHOST", /* injected eight bytes, including NUL */
    .apps_index = 67, .apps_item_id = 801, .rom_apps = "Apps",
};

static void *find_widget(uint32_t id, void *container)
{ CHECK(container != 0); return id == 600 ? &title : id == 700 ? &row : 0; }
static void old_store(const char *text, uint32_t token, uint32_t style)
{ (void)text; (void)token; (void)style; CHECK(0); }
static void old_bind(void *object, uint32_t token)
{ (void)object; (void)token; CHECK(0); }
static uint32_t shown, hidden;
static void show_widget(void *object, uint32_t visible)
{ CHECK(object == &title); shown = visible; }
static void hide_row(void *window, uint32_t index, uint32_t hide)
{ CHECK(window && index < 64); if (index == 0) hidden = hide; }

const struct nlr_menu_page nlr_menu_page = {
    .title_widget = 600, .title_slot = TOKEN(64), .title_format = 3,
    .row_widget = 700, .row_slot = TOKEN(0), .row_style = 4,
    .container_offset = 24, .title_text = "NLoader", .row_text = "Private page",
    .widget_find = find_widget, .text_store = old_store, .text_bind = old_bind,
    .widget_show = show_widget, .row_count = 64, .selected_offset = 50,
    .row_hide = hide_row,
};
const struct nlr_menu_prefill nlr_menu_prefill = {
    .text = "NLoader", .page_text = "Private page", .apps_text = "Apps",
    .entry_style = 4, .page_style = 4, .apps_style = 4, .text_store = old_store,
};
/* The Setup page as bindings name it: no Apps-first layout and no cursor
 * mapping here (menu_page.c's Setup cursor entries read it). */
const struct nlr_menu_setup nlr_menu_setup = { 0 };

static void original_pool_unchanged(void)
{
    CHECK(memcmp(original_descriptors, descriptor_baseline, sizeof descriptor_baseline) == 0);
    CHECK(memcmp(original_buffers, buffer_baseline, sizeof buffer_baseline) == 0);
}

static void boot_reset(void)
{
    /* Test end-of-boot cleanup, never a page exit/recovery operation. */
    for (uint32_t n = 0; n < memory_count; n++)
        free(memory[n]);
    memset(memory, 0, sizeof memory); memory_count = 0;
    memset(registry, 0, sizeof registry);
    memset(gui, 0, sizeof gui);
    uint32_t id = GUI_ID; uintptr_t self = (uintptr_t)gui;
    memcpy(gui + NLR_WORKER_ID_OFFSET, &id, 4);
    memcpy(gui + NLR_WORKER_SELF_OFFSET, &self, 8);
    memcpy(gui + NLR_WORKER_NAME_OFFSET, "GUIHOST", 8);
    registry[GUI_ID] = gui;
    current_id = GUI_ID; current_status = 0; next_id = 100;
    fail_allocation = -1; partial_worker = 0; low_set_status = 1;
    allocations = releases = starts = copies = low_sets = task_queries = 0;
    stock_gets = stock_writes = 0;
    memset(original_descriptors, 0x73, sizeof original_descriptors);
    memset(original_buffers, 0x49, sizeof original_buffers);
    memcpy(descriptor_baseline, original_descriptors, sizeof descriptor_baseline);
    memcpy(buffer_baseline, original_buffers, sizeof buffer_baseline);
}

static char *get(uint32_t token, uint32_t *length, uint32_t *style)
{
    char *buffer = 0; uint32_t original = token;
    nlr_private_text_getter(&token, &buffer, length, style);
    if (original >= TOKEN_BASE && original < TOKEN(68))
        CHECK(token == original);
    CHECK(buffer != 0);
    return buffer;
}

#ifdef NLR_STAGE_HOOK_ONLY
int main(void)
{
    boot_reset(); uint32_t length = 0, style = 0;
    nlr_menu_prefill_body();
    CHECK(copies == 4 && allocations == 0 && starts == 0 && task_queries == 0);
    CHECK(strcmp(get(TOKEN(66), &length, &style), "NLoader") == 0 && style == 4);
    CHECK(strcmp(get(TOKEN(67), &length, &style), "Apps") == 0 && style == 4);
    CHECK(strcmp(get(TOKEN(64), &length, &style), "NLoader") == 0 && style == 3);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Private page") == 0 && style == 4);
    CHECK(allocations == 0 && task_queries == 0);
    CHECK(strcmp(get(299, &length, &style), "stock") == 0);
    CHECK(stock_gets == 1 && last_stock_token == 299);
    CHECK(nlr_private_text_writer("stock", 0, 4) == NLR_OK);
    CHECK(stock_writes == 1 && last_stock_token == 0);
    _Alignas(8) uint8_t window[96] = {0};
    nlr_page_enter(window);
    CHECK(shown == 1 && title.token == TOKEN(64) && hidden == 0);
    CHECK(allocations == 0 && starts == 0 && copies == 4);
    uint32_t before = task_queries;
    get(TOKEN(0), &length, &style);
    CHECK(task_queries == before && nlr_runtime_find(&nlr_services, 0) == 0);
    original_pool_unchanged();
    boot_reset();
    if (failures) return 1;
    puts("private text HookOnly ROM tests passed");
    return 0;
}
#else
int main(void)
{
    boot_reset(); uint32_t length = 0, style = 0;
    CHECK(nlr_private_text_services_ready());
    CHECK(strcmp(get(TOKEN(66), &length, &style), "NLoader") == 0 && style == 4);
    /* Before any pool, the Apps row reads its own ROM label, not the failure. */
    CHECK(strcmp(get(TOKEN(67), &length, &style), "Apps") == 0 && style == 4 && length == 4);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
    CHECK(allocations == 0 && starts == 0 && task_queries == 0);
    uint32_t outside[] = {0, 299, 65534, 65535, UINT32_MAX, TOKEN_BASE - 1, TOKEN(68)};
    for (uint32_t n = 0; n < sizeof outside / sizeof outside[0]; n++) {
        uint32_t token = outside[n]; char *buffer = 0;
        nlr_private_text_getter(&token, &buffer, &length, &style);
        CHECK(last_stock_token == outside[n]);
        CHECK(token == ((int32_t)outside[n] >= 65535 ? 0 : outside[n]));
    }
    CHECK(stock_gets == 7);
    CHECK(nlr_private_text_writer("stock path", TOKEN(68), 99) == NLR_OK);
    CHECK(stock_writes == 1 && last_stock_token == TOKEN(68));
    nlr_private_text_seed("NLoader", 3);
    nlr_private_text_seed("NLoader", 4);
    CHECK(copies == 2 && allocations == 0 && starts == 0 && task_queries == 0);
    nlr_menu_prefill_body();
    CHECK(copies == 6 && allocations == 0 && starts == 0 && task_queries == 0);
    original_pool_unchanged();

    _Alignas(8) uint8_t window[96] = {0};
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r && nlr_private_text_pool_ready(r));
    CHECK(allocations == 4 && starts == 1 && shown == 1 && hidden == 0);
    CHECK(r && r->directory.count == 0 && r->load.state == 0);
    CHECK(r && !r->load.program.entry_started && !r->load.program.prepared);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Private page W") == 0);
    uint32_t before = allocations;
    nlr_page_enter(window);
    CHECK(allocations == before && nlr_runtime_find(&nlr_services, 0) == r);
    CHECK(releases == 0);
    CHECK(nlr_private_text_writer("abcdefghijklmnopqrst", TOKEN(0), 4) == NLR_OK);
    CHECK(nlr_private_text_bind(&row, TOKEN(0)) == NLR_OK);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "abcdefghijklmnopqrst") == 0);
    uint32_t invalidations = row.invalidations;
    CHECK(nlr_private_text_writer("short", TOKEN(0), 4) == NLR_OK);
    CHECK(nlr_private_text_bind(&row, TOKEN(0)) == NLR_OK);
    CHECK(row.invalidations == invalidations + 1 && row.token == TOKEN(0));
    CHECK(strcmp(get(TOKEN(0), &length, &style), "short") == 0 && length == 5);
    before = task_queries;
    get(TOKEN(64), &length, &style);
    CHECK(task_queries == before && allocations == 4 && releases == 0);
    for (uint32_t index = 0; index < 68; index++) {
        char text[16];
        snprintf(text, sizeof text, "token %u", index);
        CHECK(nlr_private_text_writer(text, TOKEN(index), index == 64 ? 3 : 4) == NLR_OK);
        CHECK(strcmp(get(TOKEN(index), &length, &style), text) == 0);
        CHECK(r->private_text->descriptors[index].buffer == r->private_text->buffers[index]);
    }
    char long_text[81]; memset(long_text, 'L', 80); long_text[80] = 0;
    CHECK(nlr_private_text_writer(long_text, TOKEN(0), 4) == NLR_OK);
    CHECK(length != 0);
    char *actual = get(TOKEN(0), &length, &style);
    CHECK(length == 50 && actual[50] == 0 && memcmp(actual, long_text, 50) == 0);
    char *saved_buffer = r->private_text->descriptors[0].buffer;
    r->private_text->descriptors[0].buffer = "ROM is never writable pool storage";
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
    r->private_text->descriptors[0].buffer = saved_buffer;
    original_pool_unchanged();

    current_status = -1;
    CHECK(nlr_private_text_writer("forbidden", TOKEN(0), 4) == NLR_REFUSED);
    CHECK(r->private_text->failed && r->private_text->last_result == NLR_REFUSED);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_NOT_READY);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
    current_status = 0;
    before = allocations;
    uint32_t failed_copies = copies, failed_invalidations = row.invalidations;
    nlr_page_enter(window);
    CHECK(shown == 0 && hidden == 0 && allocations == before);
    CHECK(copies == failed_copies && row.invalidations == failed_invalidations + 1);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_NOT_READY);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
    CHECK(releases == 0); original_pool_unchanged();

    boot_reset(); r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_OK);
    low_set_status = 0; shown = 1;
    nlr_page_enter(window);
    CHECK(shown == 0 && r->private_text->failed);
    CHECK(r->private_text->last_result == NLR_NOT_READY);
    CHECK(strcmp(get(TOKEN(64), &length, &style), "Loader memory unavailable") == 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_NOT_READY);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
    original_pool_unchanged();

    boot_reset(); r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_OK);
    struct widget image = {1, TOKEN(0), 0}, unchanged = image;
    before = low_sets;
    CHECK(nlr_private_text_bind(&image, TOKEN(0)) == NLR_REFUSED);
    CHECK(low_sets == before && memcmp(&image, &unchanged, sizeof image) == 0);
    CHECK(r->private_text->failed && r->private_text->rejected_calls == 1);
    original_pool_unchanged();

    boot_reset(); r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_OK);
    before = copies;
    CHECK(nlr_private_text_reject(TOKEN(0), 4) == NLR_REFUSED);
    CHECK(copies == before && r->private_text->failed);
    original_pool_unchanged();

    boot_reset(); r = 0; partial_worker = 1;
    CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_PARTIAL);
    CHECK(r && r->private_text && !r->private_text->ready);
    before = allocations;
    CHECK(nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0) == r);
    CHECK(!nlr_private_text_pool_ready(r));
    CHECK(allocations == before && releases == 0 && starts == 0);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);

    boot_reset(); r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_OK);
    struct nlr_runtime *other = 0;
    CHECK(nlr_runtime_create(&other, &nlr_services, NLR_ARENA_BYTES) == NLR_OK);
    before = allocations;
    CHECK(nlr_runtime_find(&nlr_services, 0) == 0);
    CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
    CHECK(allocations == before && releases == 0);

    for (int fail = 0; fail < 4; fail++) {
        boot_reset(); fail_allocation = fail; r = 0;
        CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_NOT_READY);
        CHECK(!r && releases == (uint32_t)fail && starts == 0);
        before = allocations;
        CHECK(strcmp(get(TOKEN(0), &length, &style), "Loader memory unavailable") == 0);
        CHECK(allocations == before);
    }
    for (uint32_t bad = 0; bad < 4; bad++) {
        boot_reset(); r = 0;
        if (bad == 0) current_status = 1;
        if (bad == 1) current_id = NLR_REGISTRY_IDS + 1;
        if (bad == 2) gui[NLR_WORKER_NAME_OFFSET] = 'X';
        if (bad == 3) memset(gui + NLR_WORKER_SELF_OFFSET, 0, 8);
        CHECK(nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) == NLR_NOT_READY);
        CHECK(!r && starts == 0 && releases == 3);
        original_pool_unchanged();
    }
    boot_reset();
    if (failures) { printf("%u failures\n", failures); return 1; }
    puts("private text namespace tests passed");
    return 0;
}
#endif
