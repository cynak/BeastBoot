/*
 * Minimal coverage-guided fuzzer for the wimboot host harnesses.
 *
 * libFuzzer needs clang, and the build machine only has gcc, so this is a
 * small AFL-style loop instead: gcc's -fsanitize-coverage=trace-pc calls
 * __sanitizer_cov_trace_pc() on every basic block of the code under test,
 * which we hash into an edge bitmap. Inputs that reach new edges join the
 * corpus; each round picks a corpus entry and applies a stack of havoc
 * mutations. ASan/UBSan report the bugs; the death callback saves the input
 * that triggered them.
 *
 * Usage:
 *   fuzz_X -time SECONDS -corpus DIR -crashes DIR [-max_len N] [-seed N]
 *          [-current FILE] [SEEDDIR...]
 *   fuzz_X FILE...          replay files once each (reproduce a crash)
 *
 * -current FILE holds a copy of the input being run, so that run.sh can save
 * it when the process dies without the death callback (SIGKILL from the
 * cgroup memory cap, or an ASan RSS-limit abort between inputs).
 *
 * The harness provides: int fuzz_one ( const uint8_t *data, size_t len );
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int fuzz_one ( const uint8_t *data, size_t len );
extern void __sanitizer_set_death_callback ( void ( * cb ) ( void ) );
extern void __sanitizer_print_stack_trace ( void );

#define MAP_SIZE ( 1 << 16 )

static uint8_t cov_map[MAP_SIZE];
static uint8_t virgin[MAP_SIZE];
static __thread uintptr_t cov_prev;
static int cov_on;

void __sanitizer_cov_trace_pc ( void ) {
	uintptr_t pc = ( uintptr_t ) __builtin_return_address ( 0 );
	uintptr_t cur;

	if ( ! cov_on )
		return;
	cur = ( ( pc >> 4 ) ^ ( pc << 8 ) ) & ( MAP_SIZE - 1 );
	cov_map[ cur ^ cov_prev ]++;
	cov_prev = ( cur >> 1 );
}

/* Bucket hit counts like AFL (1, 2, 3, 4-7, 8-15, ...) */
static uint8_t bucket ( uint8_t n ) {
	if ( n <= 3 ) return n;
	if ( n <= 7 ) return 4;
	if ( n <= 15 ) return 8;
	if ( n <= 31 ) return 16;
	if ( n <= 127 ) return 32;
	return 128;
}

struct entry {
	uint8_t *data;
	size_t len;
};

static struct entry *corpus;
static size_t corpus_count;
static size_t corpus_alloc;
static const char *corpus_dir;
static const char *crash_dir;
static size_t max_len = 65536;
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

/* Current input, for the death callback */
static const uint8_t *cur_data;
static size_t cur_len;
static const char *cur_kind = "crash";
static int cur_fd = -1;

static uint64_t rnd ( void ) {
	uint64_t x = rng_state;
	x ^= x << 13; x ^= x >> 7; x ^= x << 17;
	return ( rng_state = x );
}
static size_t rndn ( size_t n ) { return n ? ( rnd() % n ) : 0; }

static uint64_t fnv ( const uint8_t *d, size_t n ) {
	uint64_t h = 1469598103934665603ULL;
	while ( n-- ) { h ^= *d++; h *= 1099511628211ULL; }
	return h;
}

static void save ( const char *dir, const char *prefix,
		   const uint8_t *d, size_t n, char *path, size_t plen ) {
	FILE *f;
	snprintf ( path, plen, "%s/%s-%016llx", dir, prefix,
		   ( unsigned long long ) fnv ( d, n ) );
	if ( ( f = fopen ( path, "wb" ) ) ) {
		fwrite ( d, 1, n, f );
		fclose ( f );
	}
}

static void on_death ( void ) {
	char path[4096];
	if ( ! ( cur_data && crash_dir ) )
		return;
	save ( crash_dir, cur_kind, cur_data, cur_len, path, sizeof ( path ) );
	fprintf ( stderr, "\n==fuzz== input saved to %s\n", path );
}

/* Called by the harnesses for bugs the sanitizers cannot see */
void fuzz_crash ( const char *msg ) {
	fprintf ( stderr, "\n==fuzz== BUG: %s\n", msg );
	__sanitizer_print_stack_trace();
	abort();
}

/* gcc links UBSan as its own runtime, which does not run the ASan death
 * callback: run.sh makes it abort (UBSAN_OPTIONS=abort_on_error=1) and
 * this handler saves the input */
static void on_abort ( int sig ) {
	on_death();
	signal ( sig, SIG_DFL );
	raise ( sig );
}

static void on_alarm ( int sig ) {
	( void ) sig;
	cur_kind = "timeout";
	fprintf ( stderr, "\n==fuzz== timeout (one input ran > 10 s)\n" );
	on_death();
	_exit ( 70 );
}

static void add_entry ( const uint8_t *d, size_t n ) {
	if ( corpus_count == corpus_alloc ) {
		corpus_alloc = ( corpus_alloc ? ( 2 * corpus_alloc ) : 256 );
		corpus = realloc ( corpus, corpus_alloc * sizeof ( *corpus ) );
	}
	corpus[corpus_count].data = malloc ( n ? n : 1 );
	memcpy ( corpus[corpus_count].data, d, n );
	corpus[corpus_count].len = n;
	corpus_count++;
}

/* Run one input; return number of new coverage bytes */
static int run ( const uint8_t *d, size_t n ) {
	uint8_t *copy = malloc ( n ? n : 1 );
	int fresh = 0;
	size_t i;

	memcpy ( copy, d, n );
	if ( cur_fd >= 0 && ( pwrite ( cur_fd, d, n, 0 ) != ( ssize_t ) n ||
			      ftruncate ( cur_fd, n ) != 0 ) ) {
		perror ( "-current" );
		exit ( 2 );
	}
	memset ( cov_map, 0, sizeof ( cov_map ) );
	cov_prev = 0;
	cur_data = copy;
	cur_len = n;
	alarm ( 10 );
	cov_on = 1;
	fuzz_one ( copy, n );
	cov_on = 0;
	alarm ( 0 );
	cur_data = NULL;
	for ( i = 0 ; i < MAP_SIZE ; i++ ) {
		uint8_t b;
		if ( ! cov_map[i] )
			continue;
		b = bucket ( cov_map[i] );
		if ( ( virgin[i] | b ) != virgin[i] ) {
			virgin[i] |= b;
			fresh++;
		}
	}
	free ( copy );
	return fresh;
}

static void load_dir ( const char *dir, int keep_all ) {
	DIR *dh = opendir ( dir );
	struct dirent *de;
	char path[4096];

	if ( ! dh )
		return;
	while ( ( de = readdir ( dh ) ) ) {
		struct stat st;
		FILE *f;
		uint8_t *buf;
		if ( de->d_name[0] == '.' )
			continue;
		snprintf ( path, sizeof ( path ), "%s/%s", dir, de->d_name );
		if ( stat ( path, &st ) != 0 || ! S_ISREG ( st.st_mode ) )
			continue;
		if ( ( size_t ) st.st_size > max_len )
			st.st_size = max_len;
		buf = malloc ( st.st_size + 1 );
		f = fopen ( path, "rb" );
		if ( f ) {
			size_t n = fread ( buf, 1, st.st_size, f );
			fclose ( f );
			if ( run ( buf, n ) || keep_all )
				add_entry ( buf, n );
		}
		free ( buf );
	}
	closedir ( dh );
}

static const uint64_t interesting[] = {
	0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
	0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff,
	0x100000000ULL, 0x7fffffffffffffffULL, 0x8000000000000000ULL,
	0xffffffffffffffffULL, 32767, 32768, 32769, 65536, 0xfffffffe,
	0x00ffffffffffffffULL, 0x0400000000000000ULL, 0x0200000000000000ULL,
	0x0600000000000000ULL, 0xfffffffffffffff0ULL, 0xffffffffffff8000ULL,
};

static size_t mutate ( uint8_t *d, size_t n, size_t cap ) {
	unsigned int ops = 1 + rndn ( 8 );

	while ( ops-- ) {
		size_t pos, len, width;
		uint64_t v;
		switch ( rndn ( 11 ) ) {
		case 0: /* bit flip */
			if ( n ) d[ rndn ( n ) ] ^= ( 1 << rndn ( 8 ) );
			break;
		case 1: /* random byte */
			if ( n ) d[ rndn ( n ) ] = rnd();
			break;
		case 2: /* interesting value, 1/2/4/8 bytes LE */
		case 3:
			width = ( 1 << rndn ( 4 ) );
			if ( n < width ) break;
			pos = rndn ( n - width + 1 );
			v = interesting[ rndn ( sizeof ( interesting ) /
					       sizeof ( interesting[0] ) ) ];
			if ( rndn ( 2 ) ) v = -v;
			memcpy ( d + pos, &v, width );
			break;
		case 4: /* arithmetic on 1/2/4/8 bytes */
			width = ( 1 << rndn ( 4 ) );
			if ( n < width ) break;
			pos = rndn ( n - width + 1 );
			v = 0;
			memcpy ( &v, d + pos, width );
			v += ( rndn ( 2 ) ? 1 : -1 ) * ( 1 + rndn ( 35 ) );
			memcpy ( d + pos, &v, width );
			break;
		case 5: /* delete block */
			if ( n < 2 ) break;
			len = 1 + rndn ( ( n > 64 && rndn ( 4 ) ) ? 64 : n - 1 );
			pos = rndn ( n - len + 1 );
			memmove ( d + pos, d + pos + len, n - pos - len );
			n -= len;
			break;
		case 6: /* insert copy of a block */
			if ( ! n || n >= cap ) break;
			len = 1 + rndn ( n < 128 ? n : 128 );
			if ( len > ( cap - n ) ) len = ( cap - n );
			{
				size_t src = rndn ( n - ( len > n ? n : len ) + 1 );
				uint8_t tmp[128];
				pos = rndn ( n + 1 );
				memcpy ( tmp, d + src, len );
				memmove ( d + pos + len, d + pos, n - pos );
				memcpy ( d + pos, tmp, len );
				n += len;
			}
			break;
		case 7: /* overwrite block with another part */
			if ( n < 2 ) break;
			len = 1 + rndn ( n / 2 );
			memmove ( d + rndn ( n - len + 1 ), d + rndn ( n - len + 1 ),
				  len );
			break;
		case 8: /* splice from another corpus entry */
			if ( corpus_count ) {
				struct entry *e = &corpus[ rndn ( corpus_count ) ];
				if ( ! e->len || ! n ) break;
				len = 1 + rndn ( e->len < 512 ? e->len : 512 );
				if ( len > n ) len = n;
				memcpy ( d + rndn ( n - len + 1 ),
					 e->data + rndn ( e->len - len + 1 ), len );
			}
			break;
		case 9: /* truncate */
			if ( n > 1 ) n = 1 + rndn ( n );
			break;
		case 10: /* fill run with one byte */
			if ( ! n ) break;
			len = 1 + rndn ( n < 32 ? n : 32 );
			memset ( d + rndn ( n - len + 1 ),
				 ( rndn ( 2 ) ? 0 : rnd() ), len );
			break;
		}
	}
	return n;
}

int main ( int argc, char **argv ) {
	double seconds = 60;
	unsigned long long execs = 0;
	unsigned long long last_new = 0;
	char path[4096];
	time_t start, last_report;
	int i;

	__sanitizer_set_death_callback ( on_death );
	signal ( SIGALRM, on_alarm );
	signal ( SIGABRT, on_abort );

	/* Replay mode: plain file arguments */
	if ( argc > 1 && argv[1][0] != '-' ) {
		for ( i = 1 ; i < argc ; i++ ) {
			FILE *f = fopen ( argv[i], "rb" );
			static uint8_t buf[ 16 << 20 ];
			size_t n;
			if ( ! f ) { perror ( argv[i] ); return 1; }
			n = fread ( buf, 1, sizeof ( buf ), f );
			fclose ( f );
			fprintf ( stderr, "replay %s (%zu bytes)\n", argv[i], n );
			run ( buf, n );
		}
		fprintf ( stderr, "replay: no crash\n" );
		return 0;
	}

	for ( i = 1 ; i < argc ; i++ ) {
		if ( ! strcmp ( argv[i], "-time" ) && i + 1 < argc )
			seconds = atof ( argv[++i] );
		else if ( ! strcmp ( argv[i], "-corpus" ) && i + 1 < argc )
			corpus_dir = argv[++i];
		else if ( ! strcmp ( argv[i], "-crashes" ) && i + 1 < argc )
			crash_dir = argv[++i];
		else if ( ! strcmp ( argv[i], "-max_len" ) && i + 1 < argc )
			max_len = strtoul ( argv[++i], NULL, 0 );
		else if ( ! strcmp ( argv[i], "-seed" ) && i + 1 < argc )
			rng_state = strtoull ( argv[++i], NULL, 0 ) | 1;
		else if ( ! strcmp ( argv[i], "-current" ) && i + 1 < argc ) {
			cur_fd = open ( argv[++i], O_RDWR | O_CREAT | O_TRUNC,
					0644 );
			if ( cur_fd < 0 ) { perror ( argv[i] ); return 2; }
		}
		else if ( argv[i][0] == '-' ) {
			fprintf ( stderr, "unknown option %s\n", argv[i] );
			return 2;
		} else {
			break;
		}
	}
	if ( ! corpus_dir || ! crash_dir ) {
		fprintf ( stderr, "need -corpus DIR and -crashes DIR\n" );
		return 2;
	}
	mkdir ( corpus_dir, 0755 );
	mkdir ( crash_dir, 0755 );

	/* Seeds: the corpus directory, then any extra directories */
	load_dir ( corpus_dir, 1 );
	for ( ; i < argc ; i++ )
		load_dir ( argv[i], 0 );
	if ( ! corpus_count ) {
		static const uint8_t empty[1];
		add_entry ( empty, 0 );
	}

	start = last_report = time ( NULL );
	{
		uint8_t *buf = malloc ( max_len );
		while ( difftime ( time ( NULL ), start ) < seconds ) {
			struct entry *e = &corpus[ rndn ( corpus_count ) ];
			size_t n = ( e->len > max_len ? max_len : e->len );
			memcpy ( buf, e->data, n );
			n = mutate ( buf, n, max_len );
			execs++;
			if ( run ( buf, n ) ) {
				add_entry ( buf, n );
				save ( corpus_dir, "c", buf, n, path,
				       sizeof ( path ) );
				last_new = execs;
			}
			if ( time ( NULL ) - last_report >= 30 ) {
				last_report = time ( NULL );
				fprintf ( stderr, "#%llu corpus %zu last-new #%llu "
					  "exec/s %.0f\n", execs, corpus_count,
					  last_new, execs / ( difftime (
					  last_report, start ) + 1e-9 ) );
			}
		}
		free ( buf );
	}
	{
		size_t edges = 0;
		for ( i = 0 ; i < MAP_SIZE ; i++ )
			edges += ( virgin[i] != 0 );
		fprintf ( stderr, "DONE execs %llu corpus %zu edges %zu "
			  "seconds %.0f\n", execs, corpus_count, edges,
			  difftime ( time ( NULL ), start ) );
	}
	return 0;
}
