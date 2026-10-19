#ifndef NLR_PRIVATE_TEXT_H
#define NLR_PRIVATE_TEXT_H

#include <stddef.h>
#include <stdint.h>

/* Rows 0..63, title 64, status 65, Setup entry 66, Setup Apps 67. */
#define NLR_PRIVATE_TEXT_COUNT 68u
#define NLR_PRIVATE_TEXT_BYTES 51u

struct nlr_runtime;
struct nlr_services;
struct nlr_private_text_services;

/* Same 24-byte descriptor consumed by the original ASCII writer/getter.
 * Its buffer always belongs to this boot's runtime; ROM fallbacks are
 * returned separately and never installed as writable buffer pointers. */
struct nlr_private_text_descriptor {
    uint32_t length;
    uint32_t reserved;
    char *buffer;
    uint32_t style;
    uint32_t reserved_tail;
};
_Static_assert(sizeof(struct nlr_private_text_descriptor) == 24,
               "native text descriptor size");
_Static_assert(offsetof(struct nlr_private_text_descriptor, buffer) == 8,
               "native text buffer offset");
_Static_assert(offsetof(struct nlr_private_text_descriptor, style) == 16,
               "native text style offset");

struct nlr_private_text_pool {
    const struct nlr_runtime *owner;
    const struct nlr_private_text_services *services;
    struct nlr_private_text_descriptor descriptors[NLR_PRIVATE_TEXT_COUNT];
    char buffers[NLR_PRIVATE_TEXT_COUNT][NLR_PRIVATE_TEXT_BYTES];
    uint32_t ready; /* release-published only after the owner is registered */
    uint32_t failed; /* retained error; this boot must not resume checks */
    int32_t last_result;
    uint32_t rejected_calls;
};

/* Exact namespace/model values and original functions are injected by the
 * checked profile. ascii_copy is the relocated original writer, with its
 * explicit private descriptor-base argument; it still uses native fonts. */
struct nlr_private_text_services {
    uint32_t token_base;
    uint32_t count;
    uint32_t row_first_item;
    uint32_t entry_item_id;
    uint32_t title_index;
    uint32_t status_index;
    uint32_t entry_index;
    uint32_t row_style;
    uint32_t title_style;
    uint32_t entry_style;
    void (*native_getter)(uint32_t *token, char **buffer,
                          uint32_t *length, uint32_t *style);
    void (*native_ascii)(const char *text, uint32_t token, uint32_t style);
    void (*ascii_copy)(const char *text, uint32_t index, uint32_t style,
                       struct nlr_private_text_descriptor *base);
    void (*low_get)(const void *widget, uint32_t *type, uint32_t *token);
    int32_t (*low_set)(void *widget, uint32_t type, uint32_t token);
    const char *rom_entry;
    const char *rom_title;
    const char *rom_status;
    const char *rom_failure;
    int32_t (*current_task)(uint32_t *task_id);
    const char *task_name; /* profile-verified eight-byte GUI worker name */
    /* The Setup Apps row's label. Appended so the earlier members keep
     * their offsets; a profile without that row still injects index 67 and
     * a valid ROM label, and no item then binds the token. */
    uint32_t apps_index;
    uint32_t apps_item_id;
    const char *rom_apps;
};

extern const struct nlr_private_text_services nlr_private_text_services;

int nlr_private_text_services_ready(void);
int nlr_private_text_token(uint32_t token, uint32_t *index);
int nlr_private_text_pool_prepare(struct nlr_runtime *runtime,
                                  const struct nlr_services *services);
void nlr_private_text_pool_publish(struct nlr_runtime *runtime);
int nlr_private_text_pool_ready(const struct nlr_runtime *runtime);

/* Routed original ABIs: only exact private tokens use our descriptors.
 * Getter never creates an owner, allocates, waits, or reads the card. */
void nlr_private_text_getter(uint32_t *token, char **buffer,
                            uint32_t *length, uint32_t *style);
int32_t nlr_private_text_writer(const char *text, uint32_t token, uint32_t style);
int32_t nlr_private_text_reject(uint32_t token, uint32_t kind);
int nlr_private_text_bind(void *widget, uint32_t token);

/* Constructor-tail font seed: stack output only, never registered or
 * returned. No runtime/task/card operations are allowed on this path. */
void nlr_private_text_seed(const char *text, uint32_t style);

#endif
