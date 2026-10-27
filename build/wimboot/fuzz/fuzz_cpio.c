/* CPIO (newc) initrd parser (cpio.c), as patch 0001 uses it for the
 * LoadFile2 initrd: the callback does what efi_add_initrd_file() does
 * with the name (strlen) and touches both ends of the file data. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "wimboot.h"
#include "cpio.h"
#include "fuzz.h"

static const uint8_t *cpio_start;
static size_t cpio_len;

static int file ( const char *name, void *data, size_t len ) {
	volatile uint8_t sink;
	const uint8_t *p = data;

	sink = strlen ( name );
	if ( len ) {
		if ( ( p < cpio_start ) ||
		     ( ( size_t ) ( p - cpio_start ) > cpio_len ) ||
		     ( len > ( cpio_len - ( p - cpio_start ) ) ) )
			fuzz_crash ( "CPIO: file data outside the archive" );
		sink = p[0];
		sink = p[ len - 1 ];
	}
	( void ) sink;
	return 0;
}

int fuzz_one ( const uint8_t *data, size_t len ) {
	cpio_start = data;
	cpio_len = len;
	cpio_extract ( ( void * ) data, len, file );
	return 0;
}
