/* Pre-included into every file of the program (-include): every symbol,
 * declared or defined, is local to the program. Without it an `extern`
 * declaration is reached through a GOT, which a loaded program does not
 * have; with it every reference is PC-relative. */
#pragma GCC visibility push(hidden)
