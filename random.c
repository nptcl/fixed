#include "random.h"
#include "sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/***********************************************************************
 *  xorshift
 ***********************************************************************/
#define FIXRANDOM_MASK64BIT		0xFFFFFFFFFFFFFFFFULL
#define NUMBER_TIMES_FIXRANDOM	((256 / 64) * 4)
#define SEED_TIMES_FIXRANDOM	4

static int fixed_random_enable = 0;
static struct fixed_random fixed_random_seed;

static uint64_t xorshift128p64bit_fixrandom(uint64_t *s0, uint64_t *s1)
{
	/*
	 *  Further scramblings of Marsaglia's xorshift generators
	 *  Sebastiano Vigna, Universit`a degli Studi di Milano, Italy,
	 *  arXiv:1404.0390v3 [cs.DS] 23 May 2016.
	 *  https://arxiv.org/abs/1404.0390
	 *  http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf
	 *
	 *  Table I.
	 *  a23-b17-c26: s34-r30+64-w61 (failures)
	 *  a23-b18-c5 : s38-r20+70-w65 (weight)
	 */
	uint64_t x, y, z;

	x = *s0;
	y = *s1;
	z = x + y;
	*s0 = y;
	x ^= x << 23/*a*/;
	*s1 = x ^ y ^ (x >> 18/*b*/) ^ (y >> 5/*c*/);

	return z;
}

uint64_t number64_fixrandom(struct fixed_random *state)
{
	return xorshift128p64bit_fixrandom(&state->seed.u64[0], &state->seed.u64[1]);
}

uint64_t equal64_call_fixrandom(struct fixed_random *state, uint64_t value,
		uint64_t (*call)(struct fixed_random *))
{
	int shift;
	uint64_t check, result;

	/* shift */
	if (value == 0ULL)
		return 0ULL;
	check = (value >> 1ULL);
	for (shift = 1; check; shift++)
		check >>= 1ULL;

	/* generate */
	check = (64 <= shift)? FIXRANDOM_MASK64BIT: (1ULL << shift) - 1ULL;
	do {
		result = check & (*call)(state);
	} while (value < result);

	return result;
}

uint64_t equal64_fixrandom(struct fixed_random *state, uint64_t value)
{
	return equal64_call_fixrandom(state, value, number64_fixrandom);
}

uint64_t number64_sha_fixrandom(struct fixed_random *state)
{
	uint8_t x[BYTE_SHA256ENCODE];
	int i;
	uint64_t v;
	struct sha32encode hash;

	init_sha256encode(&hash);
	for (i = 0; i < NUMBER_TIMES_FIXRANDOM; i++) {
		v = number64_fixrandom(state);
		read_sha256encode(&hash, &v, sizeof(v));
	}
	calc_sha256encode(&hash, x);
	memcpy(&v, x, sizeof(uint64_t));

	return v;
}

uint64_t equal64_sha_fixrandom(struct fixed_random *state, uint64_t value)
{
	return equal64_call_fixrandom(state, value, number64_sha_fixrandom);
}


#ifdef FIXED_WINDOWS
#include <windows.h>
#include <ntsecapi.h>

static int call_fixrandom(void *ptr, size_t size)
{
	typedef BOOLEAN (WINAPI *apicalltype)(PVOID, ULONG);
	HMODULE hModule;
	BOOLEAN result;
	apicalltype call;

	hModule = LoadLibraryA("Advapi32.dll");
	if (hModule == NULL) {
		fprintf(stderr, "LoadLibrary Advapi32 error");
		return 1;
	}
	call = (apicalltype)GetProcAddress(hModule, "SystemFunction036");
	if (call == NULL) {
		fprintf(stderr, "GetProcAddress SystemFunction036 error");
		FreeLibrary(hModule);
		return 1;
	}
	result = (*call)((PVOID)ptr, (ULONG)size);
	FreeLibrary(hModule);

	return result == FALSE;
}
#endif

#ifdef FIXED_UNIX
static int call_fixrandom(void *ptr, size_t size)
{
	FILE *file;
	size_t check;

	file = fopen("/dev/random", "rb");
	if (file == NULL) {
		fprintf(stderr, "fopen /dev/random error.\n");
		return 1;
	}
	check = fread(ptr, 1, size, file);
	if (check != size) {
		fprintf(stderr, "fread /dev/random error.\n");
		return 1;
	}

	return 0;
}
#endif

#ifdef FIXED_DEFAULT
static int call_fixrandom(void *ptr, size_t size)
{
	FILE *file;
	size_t check;

	file = fopen("/dev/random", "rb");
	if (file) {
		check = fread(ptr, 1, size, file);
		if (check != size) {
			fprintf(stderr, "fread /dev/random error.\n");
			return 1;
		}
	}

	return 0;
}
#endif

void seed_fixrandom(const void *ptr, size_t size)
{
	uint8_t x[BYTE_SHA256ENCODE];
	struct sha32encode hash;

	init_sha256encode(&hash);
	read_sha256encode(&hash, &fixed_random_seed, sizeof(fixed_random_seed));
	read_sha256encode(&hash, ptr, size);
	calc_sha256encode(&hash, x);
	memcpy(&fixed_random_seed, x, sizeof(fixed_random_seed));
}

#define SEED_SIZE_FIXRANDOM		(sizeof(fixed_random_seed) * SEED_TIMES_FIXRANDOM)
int update_fixrandom(void)
{
	uint8_t x[SEED_SIZE_FIXRANDOM];

	if (call_fixrandom(x, SEED_SIZE_FIXRANDOM))
		return 1;
	seed_fixrandom(x, SEED_SIZE_FIXRANDOM);

	return 0;
}

void init_fixrandom(void)
{
	if (! fixed_random_enable) {
		if (update_fixrandom()) {
			fprintf(stderr, "call_fixrandom error.\n");
			exit(1);
		}
		fixed_random_enable = 1;
	}
}

int make_fixrandom(struct fixed_random *ptr)
{
	if (fixed_random_enable == 0) {
		fprintf(stderr, "fixed_random_enable error.\n");
		return 1;
	}
	ptr->seed.u64[0] = number64_sha_fixrandom(&fixed_random_seed);
	ptr->seed.u64[1] = number64_sha_fixrandom(&fixed_random_seed);
	return 0;
}

