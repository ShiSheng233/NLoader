#include "nlr/menu.h"
#include "nlr/text.h"
#include "nlr/card.h"

/* The generated bindings carry the platform addresses and the label text. */
extern const struct nlr_menu_prefill nlr_menu_prefill;

/* The original writer owns the RAM buffer, descriptor and font conversion.
 * Static font records are not byte-compatible with the runtime cache, and
 * font selection depends on the initialized language. The profile's hook
 * must run after the text platform and language have both been initialized. */
void nlr_menu_prefill_body(void)
{
    const struct nlr_menu_prefill *p = &nlr_menu_prefill;
#if NLR_HAS_PRIVATE_TEXT
    /* Language/cache registration is complete here, but task/registry
     * creation is not a constructor-tail responsibility. Seed native fonts
     * with stack-only output; private getter supplies the ROM entry label. */
    nlr_private_text_seed(p->text, nlr_private_text_services.entry_style);
    nlr_private_text_seed(p->text, nlr_private_text_services.title_style);
    if (p->page_text)
        nlr_private_text_seed(p->page_text, nlr_private_text_services.row_style);
    /* The Apps label has glyphs the other labels lack. */
    if (p->apps_text)
        nlr_private_text_seed(p->apps_text, nlr_private_text_services.entry_style);
#else
    p->text_store(p->text, p->entry_slot, p->entry_style);
    /* The NLoader page's row label lives in a slot of its own, written in
     * the same pass so the page has its text before it can be opened. */
    if (p->page_text)
        p->text_store(p->page_text, p->page_slot, p->page_style);
    /* The Apps row's label, in the same pass. */
    if (p->apps_text)
        p->text_store(p->apps_text, p->apps_slot, p->apps_style);
#endif
}
