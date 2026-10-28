/* LZX chunk decompressor (lzx.c, huffman.c), used as wim.c uses it:
 * a sizing pass without an output buffer, then the real pass into a
 * buffer of exactly the reported size. The input is a heap copy of
 * exactly the input length, so any over-read is an ASan report. */
#include <stdint.h>
#include <stddef.h>
#include "wimboot.h"
#include "lzx.h"
#include "fuzz.h"

int fuzz_one ( const uint8_t *data, size_t len ) {
	ssize_t out_len;
	ssize_t again;
	void *buf;

	out_len = lzx_decompress ( data, len, NULL );
	if ( ( out_len <= 0 ) || ( out_len > ( 2 * 32768 ) ) )
		return 0;
	buf = malloc ( out_len );
	again = lzx_decompress ( data, len, buf );
	free ( buf );
	if ( again != out_len )
		fuzz_crash ( "LZX: second pass length differs" );
	return 0;
}
