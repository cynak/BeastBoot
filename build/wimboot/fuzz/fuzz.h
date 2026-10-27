/* Shared declarations for the wimboot host harnesses (see README.md) */
#ifndef _FUZZ_H
#define _FUZZ_H

#include <stdint.h>
#include <stddef.h>

/* wimboot's headers are freestanding; declare the few host functions used */
extern void *malloc ( size_t len );
extern void free ( void *ptr );

/* die() resumes here (__builtin_setjmp buffer) */
extern void *fuzz_jmp[5];

/* Report a bug the sanitizers cannot see (saves the input, aborts) */
extern void fuzz_crash ( const char *msg ) __attribute__ (( noreturn ));

/* One input */
extern int fuzz_one ( const uint8_t *data, size_t len );

#endif /* _FUZZ_H */
