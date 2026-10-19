#include "nlr/native_graphics.h"
#include "nlr/services.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static _Alignas(8) uint8_t window_record[0x60], canvas[0x180], root[0x118];
static _Alignas(8) uint8_t task_object[NLR_WORKER_SIZE], record[0x40], rows[4][0x40];
static _Alignas(64) uint8_t pixels[NLR_GRAPHICS_BYTES];
static uint8_t target[64];
static struct nlr_graphics graphics;
static struct nlr_native_graphics provider;
static nlr_native_canvas_draw callback;
static uint32_t gui_state, task_valid, window_valid, callbacks, display_calls, blits, fences, submits;
static uint32_t skip_callback, skip_submit, abort_draw, bad_surface, move_after_blit, missing_row, context_missing, drop_queue;
static int32_t blit_result, submit_result;
static int32_t queued_task;
static uint32_t row_children_visible[4], row_children_dirty[4], row_raster_visible[4], row_hide_calls;
static uint8_t menu_raster[180];
static uint32_t overlapping_rows;
static uint32_t dynamic_rows, page_row_count, actual_row_widgets;
static _Alignas(8) uint8_t replacement_row[0x40];
static uint32_t swap_row, count_changes, count_reads;

static void put(void *memory, uint32_t at, uint64_t value, uint32_t size)
{
    uint8_t *p = memory;
    for (uint32_t n = 0; n < size; n++) p[at+n] = (uint8_t)(value >> (8*n));
}
static uint64_t get(const void *memory, uint32_t at, uint32_t size)
{
    const uint8_t *p = memory;
    uint64_t result = 0;
    for (uint32_t n = 0; n < size; n++) result |= (uint64_t)p[at+n] << (8*n);
    return result;
}
static int32_t current_task(uint32_t *out) { *out = 77; return task_valid ? 0 : -1; }
static void registry_lookup(uint32_t type, uint32_t id, void **out)
{
    assert(type == 0 && id == 77); *out = task_object;
}
static void *current_window(void) { return window_valid ? window_record : 0; }
static void *widget_find(uint32_t id, void *container)
{
    assert(container == window_record+0x18);
    if (id == 0x7f70) return canvas;
    if (id == 0x7f81 && swap_row) return replacement_row;
    if (id >= 0x7f80 && id < 0x7f80 + actual_row_widgets && !(missing_row && id == 0x7f81)) return rows[id-0x7f80];
    return 0;
}
static void *widget_root(void *widget) { assert(widget == canvas); return root; }
static nlr_native_canvas_draw get_draw(void *widget) { assert(widget == canvas); return callback; }
static void set_draw(void *widget, nlr_native_canvas_draw value) { assert(widget == canvas); callback=value; }
static int32_t set_dirty(void *widget,uint32_t dirty) { ((uint8_t *)widget)[0x3c]=(uint8_t)dirty; return 1; }
static uint32_t get_visible(void *widget) { return ((uint8_t *)widget)[0x28]; }
static void set_visible(void *widget,uint32_t visible) { ((uint8_t *)widget)[0x28]=(uint8_t)visible; }
static void row_hide(void *window,uint32_t row,uint32_t hidden)
{
    assert(window==window_record && row<actual_row_widgets && hidden<=1);
    row_children_visible[row]=hidden^1u;
    row_children_dirty[row]=hidden^1u;
    set_visible(rows[row],hidden^1u);
    row_hide_calls++;
}
static void row_dirty(void *row,uint32_t dirty)
{
    uint32_t index=(uint32_t)(((uint8_t *)row-(uint8_t *)rows)/sizeof rows[0]);
    assert(index<4 && row==rows[index] && dirty<=1);
    row_children_dirty[index]=dirty;
}
static int32_t original_draw(void *widget,void *rectangle,void *abort_callback)
{
    assert(widget==canvas && !get_visible(canvas));
    (void)rectangle; (void)abort_callback;
    for (uint32_t n=0;n<actual_row_widgets;n++) row_raster_visible[n]=0;
    callbacks++;
    return 17;
}
static int32_t foreign_draw(void *widget,void *rectangle,void *abort_callback)
{ (void)widget; (void)rectangle; (void)abort_callback; return 0; }
static int32_t abort_callback(void) { return (int32_t)abort_draw; }
static void window_render(void *window)
{
    assert(window==window_record);
    for (uint32_t n=0;n<actual_row_widgets;n++) {
        if (provider.rows_hidden) {
            assert(!get_visible(rows[n]));
            assert(!row_children_visible[n]);
        }
        if (row_children_dirty[n]) {
            if (overlapping_rows) {
                uint32_t top=(uint32_t)get(rows[n],0x12,2);
                uint32_t bottom=(uint32_t)get(rows[n],0x16,2);
                assert(top<=bottom && bottom<=sizeof menu_raster);
                for (uint32_t y=top;y<bottom;y++)
                    menu_raster[y]=(uint8_t)row_children_visible[n];
            }
            row_raster_visible[n]=row_children_visible[n];
            row_children_dirty[n]=0;
        }
        assert(row_raster_visible[n]==row_children_visible[n]);
    }
    assert(!get_visible(canvas));
    assert(callback(canvas,0,(void *)abort_callback)==1);
}
static int32_t render_widget(void *widget,void *rectangle,void *abort_fn)
{
    assert(widget==canvas);
    assert(get_visible(canvas) || callback==original_draw);
    return skip_callback ? 1 : callback(widget,rectangle,abort_fn);
}
static int32_t submit(uint32_t mask,void *request)
{ assert(mask==3 && request==target); submits++; return submit_result; }
static void display_refresh(int32_t (*abort_fn)(void),uint32_t mode,uint32_t flags)
{
    assert(abort_fn==abort_callback && mode==3 && flags==7);
    display_calls++;
    if (!skip_submit) {
        /* the platform's commit observer: the stock call, then the canvas
         * is told what it returned */
        struct nlr_native_graphics *c = nlr_native_graphics_context();
        int32_t result = submit(3,target);
        assert(result==submit_result);
        assert(nlr_native_graphics_commit_seen(c,result)==(c && c->rendering));
    }
}
static void fence(void) { fences++; }
static int32_t queue_task(void) { return queued_task; }
static int32_t blit(void *descriptor)
{
    assert(get(descriptor,0,4)==1 && get(descriptor,8,8)==(uintptr_t)pixels);
    assert(get(descriptor,0x10,2)==320 && get(descriptor,0x12,2)==200);
    assert(get(descriptor,0x18,8)==(uintptr_t)target);
    assert(get(descriptor,0x20,2)==640 && get(descriptor,0x22,2)==422);
    assert(get(descriptor,0x30,2)==0 && get(descriptor,0x32,2)==0);
    assert(get(descriptor,0x34,2)==632 && get(descriptor,0x36,2)==395);
    assert(get(descriptor,0x3c,4)==255);
    assert(provider.started && *provider.started==1);
    blits++;
    if (move_after_blit) window_valid=0;
    if (drop_queue) queued_task=0;
    return blit_result;
}
static uint32_t current_index(void) { return 4; }
static int32_t current_surface(uint32_t selector,uint64_t *out)
{ assert(selector==0); *out=(uintptr_t)target+(bad_surface?1u:0u); return 0; }
static const uint8_t *surface_record(uint32_t type,uint32_t group,uint32_t index)
{ assert(type==1 && group==1 && index==2); return record; }

const struct nlr_native_graphics_services nlr_native_graphics_services={
    .window=window_record,.window_id=1493,.canvas_id=0x7f70,.row_first=0x7f80,.row_count=4,
    .destination_x=0,.destination_y=0,.destination_width=632,.destination_height=395,
    .surface_type=1,.surface_group=1,.surface_index=2,.surface_record_address=record,
    .gui_task_name="APPMENU",.gui_state=&gui_state,.current_task=current_task,
    .registry_lookup=registry_lookup,.current_window=current_window,.widget_find=widget_find,
    .widget_root=widget_root,.get_draw=get_draw,.set_draw=set_draw,.set_dirty=set_dirty,
    .get_visible=get_visible,.set_visible=set_visible,.original_draw=original_draw,
    .window_render=window_render,.render_widget=render_widget,.display_refresh=display_refresh,.display_abort=abort_callback,
    .submit=submit,.queue_task=queue_task,.fence=fence,.blit=blit,.current_index=current_index,
    .current_surface=current_surface,.surface_record=surface_record,
    .row_hide=row_hide,.row_dirty=row_dirty,
    .surface_width=640,.surface_height=422,
};
uint32_t nlr_native_graphics_row_count(void *window)
{
    assert(window == window_record);
    if (!dynamic_rows) return nlr_native_graphics_services.row_count;
    count_reads++;
    return page_row_count + (count_changes && count_reads > 1u ? 1u : 0u);
}
struct nlr_native_graphics *nlr_native_graphics_context(void)
{ return context_missing ? 0 : &provider; }

static void fixture(void)
{
    memset(&graphics,0,sizeof graphics); memset(&provider,0,sizeof provider);
    memset(window_record,0,sizeof window_record); memset(canvas,0,sizeof canvas);
    memset(root,0,sizeof root); memset(record,0,sizeof record); memset(task_object,0,sizeof task_object);
    put(window_record,0,2u|(1493u<<16),4);
    put(window_record,0x20,(uintptr_t)root,8);
    put(canvas,0,0x7f70,4); put(canvas,4,4,2); put(canvas,0xc,1,4);
    put(canvas,0x10,0,4); put(canvas,0x14,632u|(395u<<16),4);
    put(root,0x108,1,4);put(root,0x10c,1,4);put(root,0x110,2,4);
    put(record,8,640u|(422u<<16),4); put(record,0x28,(uintptr_t)target,8);
    put(task_object,0,77,4); put(task_object,NLR_WORKER_SELF_OFFSET,(uintptr_t)task_object,8);
    memcpy(task_object+NLR_WORKER_NAME_OFFSET,"APPMENU",8);
    for (uint32_t n=0;n<4;n++) { memset(rows[n],0,sizeof rows[n]); put(rows[n],0,0x7f80+n,4);set_visible(rows[n],n&1u);row_children_visible[n]=row_raster_visible[n]=n&1u;row_children_dirty[n]=0; }
    dynamic_rows=0; page_row_count=actual_row_widgets=4;
    swap_row=count_changes=count_reads=0;
    memset(replacement_row,0,sizeof replacement_row); put(replacement_row,0,0x7f81,4);
    gui_state=task_valid=window_valid=1;
    callbacks=display_calls=blits=fences=submits=0;
    row_hide_calls=0;
    overlapping_rows=0;
    memset(menu_raster,0,sizeof menu_raster);
    skip_callback=skip_submit=abort_draw=bad_surface=move_after_blit=missing_row=context_missing=drop_queue=0;
    blit_result=0;submit_result=1;queued_task=18;callback=original_draw;
    provider.graphics=&graphics;
    graphics.owner=99;graphics.phase=NLR_GRAPHICS_DRAWING;
    graphics.gui_active=graphics.waiter_active=1;
    graphics.frame=(struct nlr_graphics_frame){pixels,320,200,1280,NLR_GRAPHICS_RGBA8,1};
}

static void success_and_restore(void)
{
    fixture();
    assert(nlr_native_graphics_install(&provider,window_record)==0);
    assert(nlr_native_graphics_install(&provider,window_record)==0);
    assert(callback==nlr_native_graphics_canvas && !get_visible(canvas));
    assert(callback(canvas,0,0)==1 && callbacks==0);
    for (uint32_t n=1;n<=3;n++) {
        graphics.frame.sequence=n;
        uint32_t started=0;
        assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==0);
        assert(started==1 && provider.draws==1 && provider.submits==1);
        assert(provider.submit_calls==1 && provider.callback_calls==1);
        assert(blits==n && display_calls==n && fences==n*2u);
        assert(row_hide_calls==4);
        assert(!provider.rendering && !provider.frame && !provider.started);
    }
    assert(nlr_native_graphics_restore(&provider,window_record)==0);
    assert(callback==original_draw && !get_visible(canvas));
    assert(callbacks==1);
    for (uint32_t n=0;n<4;n++) {
        assert(get_visible(rows[n])==(n&1u));
        assert(row_children_visible[n]==(n&1u));
        assert(row_children_dirty[n]==(n&1u));
    }
    assert(row_hide_calls==8);
    /* A completed native refresh may leave every row clean after the
     * canvas erase. The explicit final menu repaint must recover content
     * without showing originally hidden rows or invoking that erase again. */
    for (uint32_t n=0;n<4;n++) row_children_dirty[n]=0;
    assert(nlr_native_graphics_redraw_menu(&provider,window_record)==0);
    for (uint32_t n=0;n<4;n++) {
        assert(get_visible(rows[n])==(n&1u));
        assert(row_raster_visible[n]==(n&1u));
    }
    assert(callbacks==1 && callback==nlr_native_graphics_canvas);
    assert(nlr_native_graphics_install(&provider,window_record)==0);
    assert(nlr_native_graphics_restore(&provider,window_record)==0);
}

static void hidden_old_rectangle_cannot_erase_restored_row(void)
{
    fixture();
    overlapping_rows=1;
    for (uint32_t n=0;n<4;n++) {
        uint32_t top=n<2 ? 58u : 116u;
        put(rows[n],0x10,top<<16,4);
        put(rows[n],0x14,632u|((top+56u)<<16),4);
        row_hide(window_record,n,n!=0);
        row_children_dirty[n]=0;
        row_raster_visible[n]=0;
    }
    assert(nlr_native_graphics_redraw_menu(&provider,window_record)==0);
    /* The old hidden detail row has exactly the visible list row's
     * rectangle. Redrawing its background last would turn this black. */
    assert(get(rows[0],0x10,8)==get(rows[1],0x10,8));
    assert(get_visible(rows[0])==1 && get_visible(rows[1])==0);
    for (uint32_t y=58;y<114;y++) assert(menu_raster[y]==1);
    for (uint32_t n=1;n<4;n++) assert(row_children_dirty[n]==0);
    assert(callbacks==0 && blits==0 && display_calls==1);
}

static void dynamic_rows_preserve_exact_membership(void)
{
    fixture();
    dynamic_rows=1; page_row_count=actual_row_widgets=2;
    assert(nlr_native_graphics_install(&provider,window_record)==0);
    assert(provider.built_rows==2 && provider.rows[0]==rows[0] && !provider.rows[2]);
    uint32_t untouched[2]={get_visible(rows[2]),get_visible(rows[3])};
    uint32_t started=0;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==0 && started==1);
    assert(row_hide_calls==2 && blits==1 && provider.draws==1 && provider.submits==1);
    assert(get_visible(rows[2])==untouched[0] && get_visible(rows[3])==untouched[1]);
    graphics.frame.sequence=2;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==0);
    assert(row_hide_calls==2 && blits==2);
    swap_row=1; /* Same ID cannot substitute a different captured object. */
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==NLR_GRAPHICS_OWNER);
    assert(nlr_native_graphics_restore(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(!started && row_hide_calls==2 && provider.rows_hidden);
    swap_row=0;
    page_row_count=3;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==NLR_GRAPHICS_OWNER);
    assert(!started && row_hide_calls==2 && blits==2 && provider.built_rows==2);
    assert(nlr_native_graphics_restore(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(provider.rows_hidden && callback==nlr_native_graphics_canvas);
    page_row_count=2;
    assert(nlr_native_graphics_restore(&provider,window_record)==0);
    assert(row_hide_calls==4 && !provider.built_rows && !provider.rows_hidden);
    assert(get_visible(rows[0])==0 && get_visible(rows[1])==1);
    assert(get_visible(rows[2])==untouched[0] && get_visible(rows[3])==untouched[1]);
    /* A new original GUI build establishes a fresh, separately checked set. */
    page_row_count=actual_row_widgets=3;
    assert(nlr_native_graphics_redraw_menu(&provider,window_record)==0);
    assert(provider.built_rows==3 && provider.rows[2]==rows[2] && !provider.rows[3]);
    assert(nlr_native_graphics_restore(&provider,window_record)==0);

    fixture(); page_row_count=2; /* fixed pages still require all four rows */
    assert(nlr_native_graphics_install(&provider,window_record)==0 && provider.built_rows==4);
    fixture(); dynamic_rows=1; page_row_count=2; /* old extra row objects remain */
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==original_draw && !provider.canvas && !row_hide_calls);
    fixture(); dynamic_rows=1; page_row_count=actual_row_widgets=2; missing_row=1;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==original_draw && !provider.canvas && !row_hide_calls);
    fixture(); dynamic_rows=1; page_row_count=0;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    fixture(); dynamic_rows=1; page_row_count=5;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    fixture(); dynamic_rows=1; page_row_count=actual_row_widgets=2; count_changes=1;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==original_draw && !provider.canvas && !row_hide_calls);
}

static void actual_calls_are_required(void)
{
    for (uint32_t mode=0;mode<8;mode++) {
        fixture();assert(nlr_native_graphics_install(&provider,window_record)==0);
        if (mode==0) skip_callback=1;
        if (mode==1) skip_submit=1;
        if (mode==2) blit_result=-7;
        if (mode==3) submit_result=0;
        if (mode==4) bad_surface=1;
        if (mode==5) abort_draw=1;
        if (mode==6) move_after_blit=1;
        if (mode==7) drop_queue=1;
        uint32_t started=0;
        assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)!=0);
        assert(started==((mode==1||mode==2||mode==3||mode==6||mode==7)?1u:0u));
        assert(!provider.frame && !provider.started && !provider.rendering);
    }
    /* Stock commits outside the loader's own render are not the canvas's:
     * they are left to the platform hold, uncounted. */
    fixture();
    assert(!nlr_native_graphics_commit_seen(&provider,1) && !provider.submit_calls);
    assert(!nlr_native_graphics_commit_seen(&provider,0) && !provider.submit_calls);
    assert(!nlr_native_graphics_commit_seen(0,1));
}

static void wrong_objects_are_untouched(void)
{
    fixture();task_valid=0;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==original_draw);
    fixture();callback=foreign_draw;
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==foreign_draw);
    fixture();put(canvas,0x10,1,4);
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_NOT_READY);
    fixture();put(window_record,0x20,(uintptr_t)canvas,8);
    assert(nlr_native_graphics_install(&provider,window_record)==NLR_GRAPHICS_NOT_READY);
    fixture();assert(nlr_native_graphics_install(&provider,window_record)==0);
    uint32_t started=0;
    assert(nlr_native_graphics_render(&provider,100,&graphics.frame,&started)==NLR_GRAPHICS_OWNER);
    queued_task=0;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==NLR_GRAPHICS_NOT_READY);
    assert(!started && !blits);
    queued_task=18;
    struct nlr_graphics_frame forged=graphics.frame;forged.pixels=pixels+64;
    assert(nlr_native_graphics_render(&provider,99,&forged,&started)==NLR_GRAPHICS_OWNER);
    assert(!started && !blits && !display_calls);
    missing_row=1;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==NLR_GRAPHICS_OWNER);
    assert(!row_hide_calls);
    for (uint32_t n=0;n<4;n++) assert(get_visible(rows[n])==(n&1u));
    missing_row=0;
    assert(nlr_native_graphics_render(&provider,99,&graphics.frame,&started)==0);
    missing_row=1;
    assert(nlr_native_graphics_restore(&provider,window_record)==NLR_GRAPHICS_OWNER);
    assert(callback==nlr_native_graphics_canvas);
    missing_row=0;
    assert(nlr_native_graphics_restore(&provider,window_record)==0);
}

int main(void)
{
    success_and_restore();hidden_old_rectangle_cannot_erase_restored_row();
    actual_calls_are_required();wrong_objects_are_untouched();
    dynamic_rows_preserve_exact_membership();
    puts("native graphics callback and submit checks passed");
    return 0;
}
