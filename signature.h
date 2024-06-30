#ifndef __FIXED_SIGNATURE_HEADER__
#define __FIXED_SIGNATURE_HEADER__

#include "elliptic.h"
#include "fixed.h"
#include "random.h"

void sign_secp256k1(fixed s, struct fixed_random *state,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
void sign_secp256r1(fixed s, struct fixed_random *state,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
void sign_ed25519(fixed s,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
void sign_ed448(fixed s,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);

int verify_secp256k1(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
int verify_secp256r1(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
int verify_ed25519(fixed s,
		fixptr4 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);
int verify_ed448(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size);

int verify_string_secp256k1(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size);
int verify_string_secp256r1(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size);
int verify_string_ed25519(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size);
int verify_string_ed448(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size);

void genkey_elliptic(void);
int main_verify_elliptic(void);

#endif

