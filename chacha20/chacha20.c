/*
 *  RFC8439
 *  ChaCha20 and Poly1305 for IETF Protocols
 *  https://datatracker.ietf.org/doc/html/rfc8439
 */
#include "chacha20.h"
#include <string.h>

#ifdef CHACHA20_ENDIAN
#undef CHACHA20_ENDIAN
#define CHACHA20_ENDIAN 1
#endif

static const uint32_t header_chacha20[] = {
	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static void chacha20_receive1(uint32_t *dst, const uint8_t *src,
		unsigned size, unsigned allsize)
{
	unsigned space;

	if (allsize < size)
		size = allsize;
	memcpy(dst, src, size);
	space = allsize - size;
	if (space)
		memset(size + (char *)dst, 0, space);
}

static void chacha20_receive2(uint32_t *dst, const uint8_t *src,
		unsigned size, unsigned allsize)
{
	unsigned m, n, i, k, diff;
	uint32_t v;

	if (allsize < size)
		size = allsize;
	n = size / 4;
	m = size % 4;
	for (k = 0; k < n; k++) {
		v = 0;
		for (i = 0; i < 4; i++)
			v |= (*(src++) << (i * 8UL));
		*(dst++) = v;
	}
	if (m == 0) {
		diff = allsize - size;
		if (diff)
			memset(dst, 0, diff);
		return;
	}

	/* m */
	v = 0;
	for (i = 0; i < m; i++)
		v |= (*(src++) << (i * 8UL));
	*(dst++) = v;

	/* allsize */
	size = (n + 1) * 4;
	if (size < allsize) {
		diff = allsize - size;
		memset(dst, 0, diff);
	}
}

typedef void (*chacha20_receivetype)(uint32_t *, const uint8_t *, unsigned, unsigned);
#ifdef CHACHA20_ENDIAN
static chacha20_receivetype chacha20_receive0 = chacha20_receive2;
#else
static chacha20_receivetype chacha20_receive0 = chacha20_receive1;
#endif


/*
 *  key
 */
void chacha20_key(struct chacha20 *c, const void *ptr32byte, unsigned size)
{
	(*chacha20_receive0)(c->key, (const uint8_t *)ptr32byte, size, 32);
}


/*
 *  nonce
 */
void chacha20_nonce(struct chacha20 *c, const void *ptr12byte, unsigned size)
{
	(*chacha20_receive0)(c->nonce, (const uint8_t *)ptr12byte, size, 12);
	c->counter = 1;
}


/*
 *  round
 */
static void chacha20_rotl(uint32_t *s, uint32_t n)
{
	*s = (*s << n) | (*s >> (32UL - n));
}

static void chacha20_quater_round(uint32_t *s, int a, int b, int c, int d)
{
	s[a] += s[b]; s[d] ^= s[a]; chacha20_rotl(s + d, 16);
	s[c] += s[d]; s[b] ^= s[c]; chacha20_rotl(s + b, 12);
	s[a] += s[b]; s[d] ^= s[a]; chacha20_rotl(s + d, 8);
	s[c] += s[d]; s[b] ^= s[c]; chacha20_rotl(s + b, 7);
}

static void chacha20_round(uint32_t *state)
{
	int i;

	for (i = 0; i < 10; i++) {
		chacha20_quater_round(state, 0, 4, 8, 12);
		chacha20_quater_round(state, 1, 5, 9, 13);
		chacha20_quater_round(state, 2, 6, 10, 14);
		chacha20_quater_round(state, 3, 7, 11, 15);
		chacha20_quater_round(state, 0, 5, 10, 15);
		chacha20_quater_round(state, 1, 6, 11, 12);
		chacha20_quater_round(state, 2, 7, 8, 13);
		chacha20_quater_round(state, 3, 4, 9, 14);
	}
}


/*
 *  block
 */
void chacha20_block(struct chacha20 *c)
{
	int i;
	uint32_t init[4*4], *state;

	/* copy */
	memcpy(init, header_chacha20, 4*4);
	memcpy(init + 4, c->key, 8*4);
	memcpy(init + 12, &c->counter, 1*4);
	memcpy(init + 13, c->nonce, 3*4);

	/* round */
	state = c->state;
	memcpy(state, init, 4*4*4);
	chacha20_round(init);

	/* add */
	for (i = 0; i < 4*4; i++)
		state[i] += init[i];

	/* counter */
	c->counter++;
}

static void chacha20_merge1(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size)
{
	unsigned i, n, m;
	uint8_t *out8;
	const uint8_t *in8, *state8;
	uint32_t *out32;
	const uint32_t *in32, *state32;

	n = size / 4;
	m = size % 4;
	state32 = c->state;
	in32 = (const uint32_t *)in64byte;
	out32 = (uint32_t *)out64byte;

	/* n */
	for (i = 0; i < n; i++)
		out32[i] = state32[i] ^ in32[i];

	/* m */
	if (m) {
		state8 = (const uint8_t *)(state32 + n);
		in8 = (const uint8_t *)(in32 + n);
		out8 = (uint8_t *)(out32 + n);
		for (i = 0; i < m; i++)
			out8[i] = state8[i] ^ in8[i];
	}
}

static void chacha20_merge2(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size)
{
	unsigned i, k, n, m;
	uint8_t *out8, x8;
	const uint8_t *in8;
	uint32_t x32;
	const uint32_t *state32;

	n = size / 4;
	m = size % 4;
	state32 = c->state;
	in8 = (const uint8_t *)in64byte;
	out8 = (uint8_t *)out64byte;

	/* n */
	for (k = 0; k < n; k++) {
		x32 = state32[k];
		for (i = 0; i < 4; i++) {
			x8 = (x32 >> (i * 8)) & 0xFF;
			*(out8++) = *(in8++) ^ x8;
		}
	}

	/* m */
	if (m) {
		x32 = state32[n];
		for (i = 0; i < m; i++) {
			x8 = (x32 >> (i * 8)) & 0xFF;
			*(out8++) = *(in8++) ^ x8;
		}
	}
}

typedef void (*chacha20_mergetype)(struct chacha20 *, const void *, void *, unsigned);
#ifdef CHACHA20_ENDIAN
static chacha20_mergetype chacha20_merge0 = chacha20_merge2;
#else
static chacha20_mergetype chacha20_merge0 = chacha20_merge1;
#endif

void chacha20_block_merge(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size)
{
	(*chacha20_merge0)(c, in64byte, out64byte, (size < 64)? size: 64);
}

void chacha20_block_update(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size)
{
	chacha20_block(c);
	chacha20_block_merge(c, in64byte, out64byte, size);
}

void chacha20_encrypt(struct chacha20 *c, const void *in, void *out, size_t size)
{
	const uint8_t *in8;
	uint8_t *out8;
	size_t n, m, i;

	n = size / 64;
	m = size % 64;
	in8 = (const uint8_t *)in;
	out8 = (uint8_t *)out;
	for (i = 0; i < n; i++) {
		chacha20_block_update(c, in8, out8, 64);
		in8 += 64;
		out8 += 64;
	}
	if (m)
		chacha20_block_update(c, in8, out8, m);
}

void chacha20_replace(struct chacha20 *c, void *ptr, size_t size)
{
	uint8_t *ptr8;
	size_t n, m, i;

	n = size / 64;
	m = size % 64;
	ptr8 = (uint8_t *)ptr;
	for (i = 0; i < n; i++) {
		chacha20_block_update(c, ptr8, ptr8, 64);
		ptr8 += 64;
	}
	if (m)
		chacha20_block_update(c, ptr8, ptr8, m);
}


/*
 *  init
 */
void chacha20_endian1(void)
{
	chacha20_receive0 = chacha20_receive1;
	chacha20_merge0 = chacha20_merge1;
}

void chacha20_endian2(void)
{
	chacha20_receive0 = chacha20_receive2;
	chacha20_merge0 = chacha20_merge2;
}

static int check_little_chacha20(void)
{
	union little_endian_union_chacha20 {
		int y;
		char x[sizeof(int)];
	} u;

	u.y = 1;
	return (int)u.x[0];
}

static int endian_chacha20 = 0;

void init_chacha20(void)
{
	if (endian_chacha20)
		return;
	if (check_little_chacha20())
		chacha20_endian1();
	else
		chacha20_endian2();
	endian_chacha20 = 1;
}


/*
 *  Example
 */
void chacha20_example(void)
{
	uint8_t encode[8];
	struct chacha20 c;

	init_chacha20();
	chacha20_key(&c, "key", 5);
	chacha20_nonce(&c, "nonce", 5);
	chacha20_encrypt(&c, "message\0", encode, 8);
}

