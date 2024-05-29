/*
 *  SHA-1, SHA-2, SHA-3
 */
#ifndef __SHA_HEADER__
#define __SHA_HEADER__

#include <stddef.h>
#include <stdint.h>

#define BYTE_SHA128ENCODE		(128 / 8)
#define BYTE_SHA160ENCODE		(160 / 8)
#define BYTE_SHA224ENCODE		(224 / 8)
#define BYTE_SHA256ENCODE		(256 / 8)
#define BYTE_SHA384ENCODE		(384 / 8)
#define BYTE_SHA512ENCODE		(512 / 8)

struct sha32encode {
	unsigned i, dbyte;
	uint32_t h[8], w[16];
	size_t s;
};

struct sha64encode {
	unsigned i, dbyte;
	uint64_t h[8], w[16];
	size_t s;
};


/*
 *  SHA-1
 */
void init_sha1encode(struct sha32encode *);
void byte_sha1encode(struct sha32encode *, uint8_t);
void read_sha1encode(struct sha32encode *, const void *, size_t);
void calc_sha1encode(struct sha32encode *, void *);
void sequence_sha1encode(const void *, size_t, void *);
void string_sha1encode(const char *, void *);


/*
 *  SHA-2: SHA-256
 */
void init_sha256encode(struct sha32encode *);
void byte_sha256encode(struct sha32encode *, uint8_t);
void read_sha256encode(struct sha32encode *, const void *, size_t);
void calc_sha256encode(struct sha32encode *, void *);
void sequence_sha256encode(const void *, size_t, void *);
void string_sha256encode(const char *, void *);


/*
 *  SHA-2: SHA-512
 */
void init_sha512encode(struct sha64encode *);
void byte_sha512encode(struct sha64encode *, uint8_t);
void read_sha512encode(struct sha64encode *, const void *, size_t);
void calc_sha512encode(struct sha64encode *, void *);
void sequence_sha512encode(const void *, size_t, void *);
void string_sha512encode(const char *, void *);


/*
 *  SHA-3
 */
/* #define FIXED_LITTLE_ENDIAN */
/* #define FIXED_BIG_ENDIAN */
/* #define FIXED_IGNORE_ENDIAN_CHECK */

enum tail_sha3encode {
	sha3encode_01,
	sha3encode_11,
	sha3encode_1111
};

struct sha3encode {
	enum tail_sha3encode tail;
	unsigned c, dbyte, r, i, rbyte;
	uint64_t a[25];
};

void init_sha3_224_encode(struct sha3encode *);
void init_sha3_256_encode(struct sha3encode *);
void init_sha3_384_encode(struct sha3encode *);
void init_sha3_512_encode(struct sha3encode *);
void init_shake_128_encode(struct sha3encode *);
void init_shake_256_encode(struct sha3encode *);

void byte_sha3encode(struct sha3encode *, uint8_t);
void read_sha3encode(struct sha3encode *, const void *, size_t);
void result_sha3encode(struct sha3encode *, void *, size_t /* byte */);
void calc_sha3encode(struct sha3encode *, void *);

#endif

