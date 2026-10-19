#ifndef NLR_GRAPHICS_RUNTIME_H
#define NLR_GRAPHICS_RUNTIME_H
struct nlr_runtime;
void nlr_graphics_runtime_init(struct nlr_runtime *runtime);
int nlr_graphics_runtime_cleanup(struct nlr_runtime *runtime);
void nlr_graphics_runtime_checkpoint(struct nlr_runtime *runtime);
/* A program published a list: wake the menu's task so its checkpoint can
 * show the list when the page no longer follows the program. */
void nlr_graphics_runtime_list_published(struct nlr_runtime *runtime);
void *nlr_graphics_page_install(void *window);
void *nlr_graphics_page_leave(void *window);
#endif
