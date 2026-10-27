/*
 * WIM parsing and patching (wim.c, wimpatch.c, lzx.c, xca.c, huffman.c,
 * sha1.c) on an attacker-supplied boot.wim, the way wimboot uses them on
 * UEFI:
 *
 *  - wimfile.c: find \Windows\Boot\EFI\bootmgfw.efi in the boot image (and
 *    in images 1 and 2) and read the whole file;
 *  - wimpatch.c: build the patched WIM (index= and file injection into
 *    \Windows\System32) and read every byte of it through patch_wim(), as
 *    vdisk.c does when bootmgr reads the virtual disk.
 *
 * The WIM is the input itself, served by a read callback that refuses (and
 * reports) any read outside the file: in wimboot that read is a memcpy()
 * from the initrd, so reading outside it reads other memory.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include "wimboot.h"
#include "vdisk.h"
#include "cmdline.h"
#include "wim.h"
#include "wimpatch.h"
#include "fuzz.h"

#define READ_CAP ( 1 << 20 )
#define PIECE 12345 /* odd size: reads straddle chunks and regions */

static const uint8_t inject_data[100] = "injected file";

static void read_wim ( struct vdisk_file *file, void *data, size_t offset,
		       size_t len ) {
	if ( ( offset > file->len ) || ( len > ( file->len - offset ) ) )
		fuzz_crash ( "WIM: read outside the WIM file" );
	memcpy ( data, ( file->opaque + offset ), len );
}

static void read_inject ( struct vdisk_file *file, void *data,
			  size_t offset, size_t len ) {
	if ( ( offset > file->len ) || ( len > ( file->len - offset ) ) )
		fuzz_crash ( "WIM: read outside the injected file" );
	memcpy ( data, ( file->opaque + offset ), len );
}

/* A different vdisk_file each time, so that wim_read()'s chunk cache and
 * patch_wim()'s cached patch (both keyed by the file pointer) never carry
 * state from one input to the next. */
static struct vdisk_file * new_wim ( const uint8_t *data, size_t len ) {
	static unsigned int slot;
	struct vdisk_file *file = &vdisk_files[ 1 + ( slot++ % 2 ) ];

	memset ( file, 0, sizeof ( *file ) );
	memcpy ( file->name, "boot.wim", sizeof ( "boot.wim" ) );
	file->filename = file->name;
	file->opaque = ( void * ) data;
	file->len = len;
	file->xlen = len;
	file->read = read_wim;
	/* The other slot is not a file this time */
	vdisk_files[ 1 + ( slot % 2 ) ].read = NULL;
	return file;
}

static void read_resource ( struct vdisk_file *file,
			    struct wim_header *header,
			    struct wim_resource_header *resource ) {
	size_t len = resource->len;
	size_t offset;
	size_t frag;
	uint8_t *buf;

	if ( len > READ_CAP )
		len = READ_CAP;
	for ( offset = 0 ; offset < len ; offset += frag ) {
		frag = ( len - offset );
		if ( frag > PIECE )
			frag = PIECE;
		buf = malloc ( frag );
		if ( wim_read ( file, header, resource, buf, offset,
				frag ) != 0 ) {
			free ( buf );
			return;
		}
		free ( buf );
	}
}

static void read_patched ( struct vdisk_file *file ) {
	size_t len = file->xlen;
	size_t offset;
	size_t frag;
	uint8_t *buf;

	if ( len > READ_CAP )
		len = READ_CAP;
	for ( offset = 0 ; offset < len ; offset += frag ) {
		frag = ( len - offset );
		if ( frag > PIECE )
			frag = PIECE;
		buf = malloc ( frag );
		memset ( buf, 0, frag );
		patch_wim ( file, buf, offset, frag );
		free ( buf );
	}
}

int fuzz_one ( const uint8_t *data, size_t len ) {
	static const struct {
		unsigned int index;
		int rawwim;
	} configs[] = { { 0, 0 }, { 1, 1 }, { 2, 0 } };
	struct wim_directory_entry direntry;
	struct wim_resource_header meta;
	struct wim_resource_header resource;
	struct wim_header header;
	struct vdisk_file *file;
	volatile unsigned int i;
	unsigned int count;
	size_t offset;
	size_t dir_len;

	/* A small file to inject (wimpatch.c adds it to System32) */
	memset ( &vdisk_files[0], 0, sizeof ( vdisk_files[0] ) );
	memcpy ( vdisk_files[0].name, "inject.txt", sizeof ( "inject.txt" ) );
	vdisk_files[0].filename = vdisk_files[0].name;
	vdisk_files[0].opaque = ( void * ) inject_data;
	vdisk_files[0].len = vdisk_files[0].xlen = sizeof ( inject_data );
	vdisk_files[0].read = read_inject;

	/* wimfile.c: find and read bootmgfw.efi */
	file = new_wim ( data, len );
	if ( __builtin_setjmp ( fuzz_jmp ) == 0 ) {
		if ( wim_header ( file, &header ) != 0 )
			return 0;
		wim_count ( file, &header, &count );
		for ( i = 0 ; i < 3 ; i++ ) {
			if ( wim_metadata ( file, &header, i, &meta ) != 0 )
				continue;
			if ( wim_file ( file, &header, &meta,
					L"\\Windows\\Boot\\EFI\\bootmgfw.efi",
					&resource ) == 0 )
				read_resource ( file, &header, &resource );
			if ( wim_path ( file, &header, &meta,
					L"\\Windows\\System32", &offset,
					&direntry ) == 0 )
				wim_dir_len ( file, &header, &meta,
					      direntry.subdir, &dir_len );
		}
	}

	/* wimpatch.c: construct and read the patched WIM */
	for ( i = 0 ; i < ( sizeof ( configs ) / sizeof ( configs[0] ) ) ;
	      i++ ) {
		cmdline_index = configs[i].index;
		cmdline_rawwim = configs[i].rawwim;
		file = new_wim ( data, len );
		if ( __builtin_setjmp ( fuzz_jmp ) == 0 )
			read_patched ( file );
	}
	return 0;
}
