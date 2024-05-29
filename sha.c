#include "sha.h"
#include <stdint.h>
#include <string.h>

#define sha_ch(x,y,z)			(((x) & (y)) ^ ((~(x)) & (z)))
#define sha_parity(x,y,z)		((x) ^ (y) ^ (z))
#define sha_maj(x,y,z)			(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/*
 *  SHA 32bit
 */
#define sha32_clear_w(w)		memset(w, 0, sizeof(uint32_t) * 16);

static inline uint32_t sha32_rotl(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32 - n));
}

static inline uint32_t sha32_rotr(uint32_t x, uint32_t n)
{
	return (x << (32 - n)) | (x >> n);
}

static void init_sha32encode(struct sha32encode *ptr,
		const uint32_t *h, unsigned dbyte)
{
	ptr->i = 0;
	ptr->dbyte = dbyte;
	ptr->s = 0;
	memcpy(ptr->h, h, sizeof(uint32_t) * 8);
	sha32_clear_w(ptr->w);
}

static void byte_sha32encode(void (*next)(struct sha32encode *),
		struct sha32encode *ptr, uint8_t v)
{
	unsigned i, x, y;

	/* push */
	i = ptr->i;
	x = i / sizeof(uint32_t);
	y = i % sizeof(uint32_t);
	y = sizeof(uint32_t) - y - 1UL;
	ptr->w[x] |= ((uint32_t)v) << (y * 8UL);
	i++;

	/* next */
	if (64 <= i) {
		(*next)(ptr);
		i = 0;
	}
	ptr->i = i;
	ptr->s += 8;
}

static void read_sha32encode(void (*byte)(struct sha32encode *, uint8_t),
		struct sha32encode *ptr, const void *pvoid, size_t size)
{
	const uint8_t *p;
	size_t i;

	p = (const uint8_t *)pvoid;
	for (i = 0; i < size; i++)
		(*byte)(ptr, p[i]);
}

static void finish_sha32encode(void (*next)(struct sha32encode *),
		struct sha32encode *ptr)
{
	unsigned i;
	uint32_t s1, s2;
	uint64_t s;

	s = (uint64_t)ptr->s;
	s1 = (uint32_t)(s >> 32);
	s2 = (uint32_t)(s & 0xFFFFFFFFUL);

	/* need 64bit -> 8byte */
	byte_sha32encode(next, ptr, 0x80);
	i = ptr->i;
	if ((64 - 8) <= i) {
		(*next)(ptr);
		i = 0;
	}
	ptr->w[16 - 2] = s1;
	ptr->w[16 - 1] = s2;
	(*next)(ptr);
}

void calc_sha32encode(void (*next)(struct sha32encode *),
		struct sha32encode *ptr, void *pvoid, int size)
{
	int x, y, z, k;
	uint8_t *p;
	uint32_t *h, v;

	finish_sha32encode(next, ptr);
	p = (uint8_t *)pvoid;
	h = ptr->h;
	k = 0;
	for (x = 0; x < size; x++) {
		v = h[x];
		for (y = 0; y < sizeof(uint32_t); y++) {
			z = sizeof(uint32_t) - y - 1UL;
			p[k++] = (v >> (z * 8)) & 0xFFU;
		}
	}
}


/*
 *  SHA-1
 */
#define SHA1_K0 0x5a827999UL
#define SHA1_K1 0x6ed9eba1UL
#define SHA1_K2 0x8f1bbcdcUL
#define SHA1_K3 0xca62c1d6UL

static const uint32_t sha1_h[8] = {
	0x67452301UL, 0xefcdab89UL, 0x98badcfeUL, 0x10325476UL,
	0xc3d2e1f0UL, 0x00000000UL, 0x00000000UL, 0x00000000UL
};

void init_sha1encode(struct sha32encode *ptr)
{
	init_sha32encode(ptr, sha1_h, BYTE_SHA160ENCODE);
}

static inline uint32_t sha1_w(const uint32_t *w, int s)
{
	return sha32_rotl(
			w[(s + 13) & 0x0F] ^
			w[(s + 8) & 0x0F] ^
			w[(s + 2) & 0x0F] ^
			w[s],
			1);
}

#define sha1_abcde(a, b, c, d, e, t) { \
	e = d; \
	d = c; \
	c = sha32_rotl(b, 30); \
	b = a; \
	a = t; \
}

static void next_sha1encode(struct sha32encode *ptr)
{
	unsigned i, s;
	uint32_t a, b, c, d, e, t;
	uint32_t *w;

	a = ptr->h[0];
	b = ptr->h[1];
	c = ptr->h[2];
	d = ptr->h[3];
	e = ptr->h[4];
	w = ptr->w;

	/* 0 - 15 */
	for (i = 0; i < 16; i++) {
		t = sha32_rotl(a, 5) + sha_ch(b, c, d) + e + SHA1_K0 + w[i];
		sha1_abcde(a, b, c, d, e, t);
	}
	/* 16 - 19 */
	for (i = 16; i < 20; i++) {
		s = i & 0x0F;
		w[s] = sha1_w(w, s);
		t = sha32_rotl(a, 5) + sha_ch(b, c, d) + e + SHA1_K0 + w[s];
		sha1_abcde(a, b, c, d, e, t);
	}
	/* 20 - 39 */
	for (i = 20; i < 40; i++) {
		s = i & 0x0F;
		w[s] = sha1_w(w, s);
		t = sha32_rotl(a, 5) + sha_parity(b, c, d) + e + SHA1_K1 + w[s];
		sha1_abcde(a, b, c, d, e, t);
	}
	/* 40 - 59 */
	for (i = 40; i < 60; i++) {
		s = i & 0x0F;
		w[s] = sha1_w(w, s);
		t = sha32_rotl(a, 5) + sha_maj(b, c, d) + e + SHA1_K2 + w[s];
		sha1_abcde(a, b, c, d, e, t);
	}
	/* 60 - 79 */
	for (i = 60; i < 80; i++) {
		s = i & 0x0F;
		w[s] = sha1_w(w, s);
		t = sha32_rotl(a, 5) + sha_parity(b, c, d) + e + SHA1_K3 + w[s];
		sha1_abcde(a, b, c, d, e, t);
	}

	/* add */
	ptr->h[0] += a;
	ptr->h[1] += b;
	ptr->h[2] += c;
	ptr->h[3] += d;
	ptr->h[4] += e;

	/* clear w */
	sha32_clear_w(w);
}

void byte_sha1encode(struct sha32encode *ptr, uint8_t v)
{
	byte_sha32encode(next_sha1encode, ptr, v);
}

void read_sha1encode(struct sha32encode *ptr, const void *pvoid, size_t size)
{
	read_sha32encode(byte_sha1encode, ptr, pvoid, size);
}

void finish_sha1encode(struct sha32encode *ptr)
{
	finish_sha32encode(next_sha1encode, ptr);
}

void calc_sha1encode(struct sha32encode *ptr, void *pvoid)
{
	calc_sha32encode(next_sha1encode, ptr, pvoid, 5);
}

void sequence_sha1encode(const void *from, size_t len, void *result)
{
	struct sha32encode sha1;

	init_sha1encode(&sha1);
	read_sha1encode(&sha1, from, len);
	calc_sha1encode(&sha1, result);
}

void string_sha1encode(const char *from, void *result)
{
	sequence_sha1encode(from, strlen(from), result);
}


/*
 *  SHA-2: SHA-256
 */
static const uint32_t sha32_k[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static const uint32_t sha256_h[8] = {
	0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
	0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

void init_sha256encode(struct sha32encode *ptr)
{
	init_sha32encode(ptr, sha256_h, BYTE_SHA256ENCODE);
}

static inline uint32_t sigma32_upper_0(uint32_t x)
{
	return sha32_rotr(x, 2) ^ sha32_rotr(x, 13) ^ sha32_rotr(x, 22);
}

static inline uint32_t sigma32_upper_1(uint32_t x)
{
	return sha32_rotr(x, 6) ^ sha32_rotr(x, 11) ^ sha32_rotr(x, 25);
}

static inline uint32_t sigma32_lower_0(uint32_t x)
{
	return sha32_rotr(x, 7) ^ sha32_rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma32_lower_1(uint32_t x)
{
	return sha32_rotr(x, 17) ^ sha32_rotr(x, 19) ^ (x >> 10);
}

static inline uint32_t sha256_w(const uint32_t *w, int s)
{
	return sigma32_lower_1(w[(s + 14) & 0x0F]) +
			w[(s + 9) & 0x0F] +
			sigma32_lower_0(w[(s + 1) & 0x0F]) +
			w[s];
}

#define sha256_abcdefgh(a, b, c, d, e, f, g, h, t1, t2) { \
	h = g; \
	g = f; \
	f = e; \
	e = d + t1; \
	d = c; \
	c = b; \
	b = a; \
	a = t1 + t2; \
}

static void next_sha256encode(struct sha32encode *ptr)
{
	int i, s;
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	uint32_t *w;

	a = ptr->h[0];
	b = ptr->h[1];
	c = ptr->h[2];
	d = ptr->h[3];
	e = ptr->h[4];
	f = ptr->h[5];
	g = ptr->h[6];
	h = ptr->h[7];
	w = ptr->w;

	/* 0 - 15 */
	for (i = 0; i < 16; i++) {
		t1 = h + sigma32_upper_1(e) + sha_ch(e, f, g) + sha32_k[i] + w[i];
		t2 = sigma32_upper_0(a) + sha_maj(a, b, c);
		sha256_abcdefgh(a, b, c, d, e, f, g, h, t1, t2);
	}

	/* 16 - 63 */
	for (i = 16; i < 64; i++) {
		s = i & 0x0F;
		w[s] = sha256_w(w, s);
		t1 = h + sigma32_upper_1(e) + sha_ch(e, f, g) + sha32_k[i] + w[s];
		t2 = sigma32_upper_0(a) + sha_maj(a, b, c);
		sha256_abcdefgh(a, b, c, d, e, f, g, h, t1, t2);
	}

	/* add */
	ptr->h[0] += a;
	ptr->h[1] += b;
	ptr->h[2] += c;
	ptr->h[3] += d;
	ptr->h[4] += e;
	ptr->h[5] += f;
	ptr->h[6] += g;
	ptr->h[7] += h;

	/* clear w */
	sha32_clear_w(w);
}

void byte_sha256encode(struct sha32encode *ptr, uint8_t v)
{
	byte_sha32encode(next_sha256encode, ptr, v);
}

void read_sha256encode(struct sha32encode *ptr, const void *pvoid, size_t size)
{
	read_sha32encode(byte_sha256encode, ptr, pvoid, size);
}

void finish_sha256encode(struct sha32encode *ptr)
{
	finish_sha32encode(next_sha256encode, ptr);
}

void calc_sha256encode(struct sha32encode *ptr, void *pvoid)
{
	calc_sha32encode(next_sha256encode, ptr, pvoid, 8);
}

void sequence_sha256encode(const void *from, size_t len, void *result)
{
	struct sha32encode sha256;

	init_sha256encode(&sha256);
	read_sha256encode(&sha256, from, len);
	calc_sha256encode(&sha256, result);
}

void string_sha256encode(const char *from, void *result)
{
	sequence_sha256encode(from, strlen(from), result);
}


/*
 *  SHA 64bit
 */
#define sha64_clear_w(w)		memset(w, 0, sizeof(uint64_t) * 16);

static const uint64_t sha64_k[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static inline uint64_t sha64_rotl(uint64_t x, uint64_t n)
{
	return (x << n) | (x >> (64ULL - n));
}

static inline uint64_t sha64_rotr(uint64_t x, uint64_t n)
{
	return (x << (64ULL - n)) | (x >> n);
}

static void init_sha64encode(struct sha64encode *ptr,
		const uint64_t *h, unsigned dbyte)
{
	ptr->i = 0;
	ptr->dbyte = dbyte;
	ptr->s = 0;
	memcpy(ptr->h, h, sizeof(uint64_t) * 8);
	sha64_clear_w(ptr->w);
}

static void byte_sha64encode(void (*next)(struct sha64encode *),
		struct sha64encode *ptr, uint8_t v)
{
	unsigned i, x, y;

	/* push */
	i = ptr->i;
	x = i / sizeof(uint64_t);
	y = i % sizeof(uint64_t);
	y = sizeof(uint64_t) - y - 1UL;
	ptr->w[x] |= ((uint64_t)v) << (y * 8ULL);
	i++;

	/* next */
	if (128 <= i) {
		(*next)(ptr);
		i = 0;
	}
	ptr->i = i;
	ptr->s += 8;
}

static void read_sha64encode(void (*byte)(struct sha64encode *, uint8_t),
		struct sha64encode *ptr, const void *pvoid, size_t size)
{
	const uint8_t *p;
	size_t i;

	p = (const uint8_t *)pvoid;
	for (i = 0; i < size; i++)
		(*byte)(ptr, p[i]);
}

static void finish_sha64encode(void (*next)(struct sha64encode *),
		struct sha64encode *ptr)
{
	unsigned i;
	uint64_t s1, s2;
	size_t s;

	s = ptr->s;
#if UINT64_MAX < SIZE_MAX
	s1 = (uint64_t)(s >> 64ULL);
	s2 = (uint64_t)(s & 0xFFFFFFFFFFFFFFFFULL);
#else
	s1 = 0;
	s2 = (uint64_t)s;
#endif

	/* need 128bit -> 16byte */
	byte_sha64encode(next, ptr, 0x80);
	i = ptr->i;
	if ((128 - 16) <= i) {
		(*next)(ptr);
		i = 0;
	}
	ptr->w[16 - 2] = s1;
	ptr->w[16 - 1] = s2;
	(*next)(ptr);
}

void calc_sha64encode(void (*next)(struct sha64encode *),
		struct sha64encode *ptr, void *pvoid, int size)
{
	int x, y, z, k;
	uint8_t *p;
	uint64_t *h, v;

	finish_sha64encode(next, ptr);
	p = (uint8_t *)pvoid;
	h = ptr->h;
	k = 0;
	for (x = 0; x < size; x++) {
		v = h[x];
		for (y = 0; y < sizeof(uint64_t); y++) {
			z = sizeof(uint64_t) - y - 1UL;
			p[k++] = (v >> (z * 8ULL)) & 0xFFU;
		}
	}
}


/*
 *  SHA-2 : SHA-512
 */
static const uint64_t sha512_h[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

void init_sha512encode(struct sha64encode *ptr)
{
	init_sha64encode(ptr, sha512_h, BYTE_SHA512ENCODE);
}

static inline uint64_t sigma64_upper_0(uint64_t x)
{
	return sha64_rotr(x, 28) ^ sha64_rotr(x, 34) ^ sha64_rotr(x, 39);
}

static inline uint64_t sigma64_upper_1(uint64_t x)
{
	return sha64_rotr(x, 14) ^ sha64_rotr(x, 18) ^ sha64_rotr(x, 41);
}

static inline uint64_t sigma64_lower_0(uint64_t x)
{
	return sha64_rotr(x, 1) ^ sha64_rotr(x, 8) ^ (x >> 7);
}

static inline uint64_t sigma64_lower_1(uint64_t x)
{
	return sha64_rotr(x, 19) ^ sha64_rotr(x, 61) ^ (x >> 6);
}

static inline uint64_t sha512_w(const uint64_t *w, int s)
{
	return sigma64_lower_1(w[(s + 14) & 0x0F]) +
			w[(s + 9) & 0x0F] +
			sigma64_lower_0(w[(s + 1) & 0x0F]) +
			w[s];
}

#define sha512_abcdefgh(a, b, c, d, e, f, g, h, t1, t2) { \
	h = g; \
	g = f; \
	f = e; \
	e = d + t1; \
	d = c; \
	c = b; \
	b = a; \
	a = t1 + t2; \
}

static void next_sha512encode(struct sha64encode *ptr)
{
	int i, s;
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	uint64_t *w;

	a = ptr->h[0];
	b = ptr->h[1];
	c = ptr->h[2];
	d = ptr->h[3];
	e = ptr->h[4];
	f = ptr->h[5];
	g = ptr->h[6];
	h = ptr->h[7];
	w = ptr->w;

	/* 0 - 15 */
	for (i = 0; i < 16; i++) {
		t1 = h + sigma64_upper_1(e) + sha_ch(e, f, g) + sha64_k[i] + w[i];
		t2 = sigma64_upper_0(a) + sha_maj(a, b, c);
		sha512_abcdefgh(a, b, c, d, e, f, g, h, t1, t2);
	}

	/* 16 - 63 */
	for (i = 16; i < 80; i++) {
		s = i & 0x0F;
		w[s] = sha512_w(w, s);
		t1 = h + sigma64_upper_1(e) + sha_ch(e, f, g) + sha64_k[i] + w[s];
		t2 = sigma64_upper_0(a) + sha_maj(a, b, c);
		sha512_abcdefgh(a, b, c, d, e, f, g, h, t1, t2);
	}

	/* add */
	ptr->h[0] += a;
	ptr->h[1] += b;
	ptr->h[2] += c;
	ptr->h[3] += d;
	ptr->h[4] += e;
	ptr->h[5] += f;
	ptr->h[6] += g;
	ptr->h[7] += h;

	/* clear w */
	sha64_clear_w(w);
}

void byte_sha512encode(struct sha64encode *ptr, uint8_t v)
{
	byte_sha64encode(next_sha512encode, ptr, v);
}

void read_sha512encode(struct sha64encode *ptr, const void *pvoid, size_t size)
{
	read_sha64encode(byte_sha512encode, ptr, pvoid, size);
}

void finish_sha512encode(struct sha64encode *ptr)
{
	finish_sha64encode(next_sha512encode, ptr);
}

void calc_sha512encode(struct sha64encode *ptr, void *pvoid)
{
	calc_sha64encode(next_sha512encode, ptr, pvoid, 8);
}

void sequence_sha512encode(const void *from, size_t len, void *result)
{
	struct sha64encode sha512;

	init_sha512encode(&sha512);
	read_sha512encode(&sha512, from, len);
	calc_sha512encode(&sha512, result);
}

void string_sha512encode(const char *from, void *result)
{
	sequence_sha512encode(from, strlen(from), result);
}


/*
 *  SHA-3: keccak
 */
#if defined(FIXED_LITTLE_ENDIAN)
#undef FIXED_BIG_ENDIAN
#elif defined(FIXED_BIG_ENDIAN)
#undef FIXED_LITTLE_ENDIAN
#else
/* default -> LITTLE_ENDIAN */
#define FIXED_LITTLE_ENDIAN
#undef FIXED_BIG_ENDIAN
#endif

#define sha3_xy(x, y)			(5*(y) + (x))

#ifdef FIXED_LITTLE_ENDIAN
#define sha3_load64(a,n)		((a)[n])
#define sha3_store64(a,n,v)		((a)[n] = (v))
#define sha3_xor64(a,n,v)		((a)[n] ^= (v))
#else
#define sha3_cast8(a,n)			((uint8_t *)((a) + (n)))
#define sha3_load64(a,n)		sha3_swap_load64(sha3_cast8((a), (n)))
#define sha3_store64(a,n,v)		sha3_swap_store64(sha3_cast8((a), (n)), (v))
#define sha3_xor64(a,n,v)		sha3_swap_xor64(sha3_cast8((a), (n)), (v))

static inline uint64_t sha3_swap_load64(const uint8_t *a)
{
	int i, k;
	uint64_t v;

	v = 0;
	for (i = 0; i < sizeof(uint64_t); i++) {
		k = sizeof(uint64_t) - i - 1;
		v |= ((uint64_t)a[k]) << (i * 8ULL);
	}

	return v;
}

static inline void sha3_swap_store64(uint8_t *a, uint64_t v)
{
	int i;

	for (i = 0; i < sizeof(uint64_t); i++)
		a[i] = (uint8_t)((v >> (i * 8U)) & 0xFFU);
}

static inline void sha3_swap_xor64(uint8_t *a, uint64_t v)
{
	int i;

	for (i = 0; i < sizeof(uint64_t); i++)
		a[i] ^= (uint8_t)((v >> (i * 8U)) & 0xFFU);
}
#endif

static const unsigned rho_sha3encode[25] = {
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14
};

static const uint64_t rc_sha3encode[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

static void round_sha3encode(struct sha3encode *ptr, int i)
{
	unsigned x, y, xy, x1, x2, p, q;
	uint64_t *a, b[25], c[5];
	uint64_t v, v1, v2, v3;

	/* theta */
	a = ptr->a;
	for (x = 0; x < 5; x++) {
		c[x] = sha3_load64(a, sha3_xy(x, 0)) ^
			sha3_load64(a, sha3_xy(x, 1)) ^
			sha3_load64(a, sha3_xy(x, 2)) ^
			sha3_load64(a, sha3_xy(x, 3)) ^
			sha3_load64(a, sha3_xy(x, 4));
	}
	for (x = 0; x < 5; x++) {
		x1 = x? (x - 1): 4;
		x2 = (x + 1) % 5;
		v = c[x1] ^ sha64_rotl(c[x2], 1);
		for (y = 0; y < 5; y++)
			sha3_xor64(a, sha3_xy(x, y), v);
	}

	/* rho, pi */
	for (x = 0; x < 5; x++) {
		for (y = 0; y < 5; y++) {
			xy = (2 * x + 3 * y) % 5;
			p = sha3_xy(x, y);
			q = sha3_xy(y, xy);
			v = sha3_load64(a, p);
			v = sha64_rotl(v, rho_sha3encode[p]);
			sha3_store64(b, q, v);
		}
	}

	/* chi */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++)
			c[x] = sha3_load64(b, sha3_xy(x, y));
		for (x = 0; x < 5; x++) {
			v1 = c[x];
			v2 = c[(x + 1) % 5];
			v3 = c[(x + 2) % 5];
			v = v1 ^ ((~v2) & v3);
			sha3_store64(a, sha3_xy(x, y), v);
		}
	}

	/* iota */
	sha3_xor64(a, sha3_xy(0, 0), rc_sha3encode[i]);
}

static void keccak_sha3encode(struct sha3encode *ptr)
{
	int i;

	for (i = 0; i < 24; i++)
		round_sha3encode(ptr, i);
}


/*
 *  SHA-3: sha3encode
 */
static void next_sha3encode(struct sha3encode *ptr)
{
	ptr->i = 0;
	keccak_sha3encode(ptr);
}

void byte_sha3encode(struct sha3encode *ptr, uint8_t v)
{
	uint8_t *a;

	a = (uint8_t *)ptr->a;
	a[ptr->i] ^= v;
	ptr->i++;
	if (ptr->i < ptr->rbyte)
		return;
	next_sha3encode(ptr);
}

void read_sha3encode(struct sha3encode *ptr, const void *pvoid , size_t size)
{
	const uint8_t *p;
	size_t i;

	p = (const uint8_t *)pvoid;
	for (i = 0; i < size; i++)
		byte_sha3encode(ptr, p[i]);
}

static uint8_t finish_tail_sha3encode(struct sha3encode *ptr)
{
	switch (ptr->tail) {
		case sha3encode_01:
			return 0x06;  /* 0110 0000 -> 0000 0110 */
		case sha3encode_11:
			return 0x07;  /* 1110 0000 -> 0000 0111 */
		case sha3encode_1111:
			return 0x1F;  /* 1111 1000 -> 0001 1111 */
		default:
			return 0x06;  /* 0110 0000 -> 0000 0110 */
	}
}

static void finish_sha3encode(struct sha3encode *ptr)
{
	uint8_t v, *a;

	v = finish_tail_sha3encode(ptr);
	a = (uint8_t *)ptr->a;
	a[ptr->i] ^= v;
	a[ptr->rbyte - 1] ^= 0x80;
	next_sha3encode(ptr);
}

void result_sha3encode(struct sha3encode *ptr, void *pvoid, size_t byte)
{
	uint8_t *p;
	uint64_t *a;
	size_t x, y, z, k, rbyte;

	finish_sha3encode(ptr);
	rbyte = ptr->rbyte;
	p = (uint8_t *)pvoid;
	y = byte / rbyte;
	z = byte % rbyte;
	a = ptr->a;

	/* y */
	k = 0;
	for (x = 0; x < y; x++) {
		if (k)
			next_sha3encode(ptr);
		memcpy(p + k, a, rbyte);
		k += rbyte;
	}

	/* z */
	if (z == 0)
		return;
	if (k)
		next_sha3encode(ptr);
	memcpy(p + k, a, z);
}

void calc_sha3encode(struct sha3encode *ptr, void *pvoid)
{
	result_sha3encode(ptr, pvoid, ptr->dbyte);
}


/*
 *  SHA-3: init
 */
#ifndef FIXED_IGNORE_ENDIAN_CHECK
#include <stdio.h>
#include <stdlib.h>

static void endian_check_sha3encode(void)
{
	union sha3_endian_check {
		unsigned char x[sizeof(int)];
		int y;
	} u;

	u.y = 1;
#ifdef FIXED_LITTLE_ENDIAN
	if (u.x[0] == 0) {
		fprintf(stderr, "endian error, Add #define FIXED_BIG_ENDIAN.\n");
		exit(1);
	}
#else
	if (u.x[0] != 0) {
		fprintf(stderr, "endian error, Add #define FIXED_LITTLE_ENDIAN.\n");
		exit(1);
	}
#endif
}
#endif

static void init_sha3encode(struct sha3encode *ptr,
		unsigned cbit, unsigned dbit, enum tail_sha3encode tail)
{
#ifndef FIXED_IGNORE_ENDIAN_CHECK
	endian_check_sha3encode();
#endif
	memset(ptr->a, 0, sizeof(uint64_t) * 25);
	ptr->i = 0;
	ptr->c = cbit;  /* capacity bit */
	ptr->dbyte = dbit / 8;  /* output byte */
	ptr->r = 1600 - ptr->c;  /* rate bit */
	ptr->rbyte = ptr->r / 8;  /* rate byte */;
	ptr->tail = tail;
}

void init_sha3_224_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 448, 224, sha3encode_01);
}
void init_sha3_256_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 512, 256, sha3encode_01);
}
void init_sha3_384_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 768, 384, sha3encode_01);
}
void init_sha3_512_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 1024, 512, sha3encode_01);
}
void init_shake_128_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 256, 128, sha3encode_1111);
}
void init_shake_256_encode(struct sha3encode *ptr)
{
	init_sha3encode(ptr, 512, 256, sha3encode_1111);
}


/*
 *  EXAMPLE
 *
 *  SHA-3:
 *    $ echo -n "Hello" | openssl dgst -sha3-512
 *    $ echo -n "Hello" | openssl dgst -shake-256 -xoflen=100
 *
 *  #include <stdio.h>
 *  #include "sha.h"
 *
 *  int main_sha3_512(void)
 *  {
 *      int i;
 *      uint8_t x[100];
 *      struct sha3encode sha;
 *
 *      init_sha3_512_encode(&sha);
 *      read_sha3encode(&sha, "Hello", 5);
 *      calc_sha3encode(&sha, x);
 *      for (i = 0; i < sha.dbyte; i++)
 *          printf("%02x", x[i]);
 *      printf("\n");
 *
 *      return 0;
 *  }
 *
 *  int main_sha3_shake_256(void)
 *  {
 *      int i;
 *      uint8_t x[100];
 *      struct sha3encode sha;
 *
 *      init_shake_256_encode(&sha);
 *      read_sha3encode(&sha, "Hello", 5);
 *      result_sha3encode(&sha, x, 100);
 *      for (i = 0; i < 100; i++)
 *          printf("%02x", x[i]);
 *      printf("\n");
 *
 *      return 0;
 *  }
 */

