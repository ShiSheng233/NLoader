#ifndef NLR_LIBC_UNISTD_H
#define NLR_LIBC_UNISTD_H
#include <stddef.h>
#include <sys/types.h>
int access(const char *path, int mode);
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
int usleep(unsigned usec);
unsigned sleep(unsigned sec);
int close(int fd);
int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
off_t lseek(int fd, off_t off, int whence);
int unlink(const char *path);
int isatty(int fd);
char *getcwd(char *buf, size_t n);
#endif
