#ifndef NLR_LIBC_SYS_STAT_H
#define NLR_LIBC_SYS_STAT_H
#include <sys/types.h>
struct stat { off_t st_size; mode_t st_mode; };
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & 0170000) == S_IFDIR)
int stat(const char *path, struct stat *st);
int mkdir(const char *path, mode_t mode);
#endif
