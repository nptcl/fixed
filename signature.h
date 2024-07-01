#ifndef __FIXED_SIGNATURE_HEADER__
#define __FIXED_SIGNATURE_HEADER__

#include "elliptic.h"
#include "fixed.h"
#include "public.h"
#include "random.h"

/* sign */
void sign_secp256k1(fixed s, struct fixed_random *state,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
void sign_secp256r1(fixed s, struct fixed_random *state,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
void sign_ed25519(fixed s,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
void sign_ed448(fixed s,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);

/* verify */
int verify_secp256k1(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
int verify_secp256r1(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
int verify_ed25519(fixed s,
		fixptr4 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);
int verify_ed448(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s);

/* private */
void private_string_secp256k1(char *r);
void private_string_secp256r1(char *r);
void private_string_ed25519(char *r);
void private_string_ed448(char *r);

/* public */
int public_string_secp256k1(const char *private_key, char *r);
int public_string_secp256r1(const char *private_key, char *r);
int public_string_ed25519(const char *private_key, char *r);
int public_string_ed448(const char *private_key, char *r);

/* sign_string */
int sign_string_secp256k1(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s);
int sign_string_secp256r1(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s);
int sign_string_ed25519(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s);
int sign_string_ed448(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s);

/* verify_string */
int verify_string_secp256k1(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s);
int verify_string_secp256r1(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s);
int verify_string_ed25519(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s);
int verify_string_ed448(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s);

/* others */
void genkey_elliptic(void);
int main_verify_elliptic(void);

#endif

