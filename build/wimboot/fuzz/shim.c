/*
 * Host shims for compiling wimboot's parsers outside the firmware.
 *
 * Compiled with wimboot's own headers (-nostdinc -I src -fshort-wchar), so
 * wchar_t is 16 bits as in wimboot. Provides what the parsers link against
 * (die, the 16-bit wide string helpers, the command line flags and the
 * vdisk file table) without pulling in wimboot's freestanding libc.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include "wimboot.h"
#include "cmdline.h"
#include "vdisk.h"
#include "fuzz.h"

int cmdline_rawbcd;
int cmdline_rawwim;
int cmdline_quiet = 1;
int cmdline_gui;
int cmdline_pause;
int cmdline_pause_quiet;
int cmdline_linear;
unsigned int cmdline_index;

struct vdisk_file vdisk_files[VDISK_MAX_FILES];

void *fuzz_jmp[5];

extern void __asan_handle_no_return ( void );

void die ( const char *fmt __attribute__ (( unused )), ... ) {
	/* wimboot halts here; the harness resumes with the next input */
	__asan_handle_no_return();
	__builtin_longjmp ( fuzz_jmp, 1 );
}

size_t wcslen ( const wchar_t *str ) {
	size_t len = 0;
	while ( str[len] )
		len++;
	return len;
}

static wchar_t wup ( wchar_t c ) {
	return ( ( c >= L'a' && c <= L'z' ) ? ( c - L'a' + L'A' ) : c );
}

int wcscasecmp ( const wchar_t *a, const wchar_t *b ) {
	for ( ; ; a++, b++ ) {
		int d = ( wup ( *a ) - wup ( *b ) );
		if ( d || ! *a )
			return d;
	}
}

wchar_t * wcschr ( const wchar_t *str, wchar_t c ) {
	for ( ; *str ; str++ ) {
		if ( *str == c )
			return ( ( wchar_t * ) str );
	}
	return NULL;
}
