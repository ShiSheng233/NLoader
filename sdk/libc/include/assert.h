#ifndef NLR_LIBC_ASSERT_H
#define NLR_LIBC_ASSERT_H
void nlr_assert_fail(const char *expr, const char *file, int line) __attribute__((noreturn));
#define assert(e) ((e) ? (void)0 : nlr_assert_fail(#e, __FILE__, __LINE__))
#endif
