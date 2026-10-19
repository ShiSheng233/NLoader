#ifndef NLR_CARD_H
#define NLR_CARD_H

/* The build supplies the validated profile root. Core has no fallback card
 * or directory: all file services and API boundaries use this same root. */
#include "nlr/card_config.h"

#define NLR_PROGRAM_ROOT NLR_CARD_ROOT
/* The disable flag check is the first card operation of every load. */
#define NLR_SAFE_MODE_PATH NLR_CARD_ROOT "SAFE_MODE"
#define NLR_MANIFEST_PATH NLR_CARD_ROOT "MANIFEST"
#define NLR_ENABLED_PATH NLR_CARD_ROOT "ENABLED"
#define NLR_AUTOLOAD_PENDING_PATH NLR_CARD_ROOT "AUTOLOAD_PENDING"
/* The NLoader switch: "off" loads nothing at the
 * next power-on, as SAFE_MODE does; "on", or no file, loads as always. */
#define NLR_MASTER_PATH NLR_CARD_ROOT "MASTER"
/* The program the boot starts (runtime.c boot_read): its id, or nothing. */
#define NLR_BOOT_PATH NLR_CARD_ROOT "BOOT"

#endif
