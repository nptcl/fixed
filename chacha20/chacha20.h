#ifndef __CHACHA20_HEADER__
#define __CHACHA20_HEADER__

#include <stddef.h>
#include <stdint.h>

struct chacha20 {
	uint32_t state[4*4];
	uint32_t key[8];
	uint32_t nonce[3];
	uint32_t counter;
};

void init_chacha20(void);
void chacha20_endian1(void);
void chacha20_endian2(void);

void chacha20_key(struct chacha20 *c, const void *ptr32byte, unsigned size);
void chacha20_nonce(struct chacha20 *c, const void *ptr12byte, unsigned size);
void chacha20_block(struct chacha20 *c);
void chacha20_block_merge(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size);
void chacha20_block_update(struct chacha20 *c,
		const void *in64byte, void *out64byte, unsigned size);

void chacha20_encrypt(struct chacha20 *c, const void *in, void *out, size_t size);
void chacha20_replace(struct chacha20 *c, void *ptr, size_t size);

#endif

