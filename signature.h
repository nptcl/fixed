#ifndef __FIXED_SIGNATURE_HEADER__
#define __FIXED_SIGNATURE_HEADER__

#include "elliptic.h"
#include "fixed.h"
#include "random.h"

#define vector1_size_secp256k1		32
#define vector1_size_secp256r1		32
#define vector1_size_ed25519		32
#define vector1_size_ed448			57
#define vector2_size_secp256k1		65
#define vector2_size_secp256r1		65
#define vector2_size_ed25519		32
#define vector2_size_ed448			57
typedef uint8_t vector1_secp256k1[vector1_size_secp256k1];
typedef uint8_t vector1_secp256r1[vector1_size_secp256r1];
typedef uint8_t vector1_ed25519[vector1_size_ed25519];
typedef uint8_t vector1_ed448[vector1_size_ed448];
typedef uint8_t vector2_secp256k1[vector2_size_secp256k1];
typedef uint8_t vector2_secp256r1[vector2_size_secp256r1];
typedef uint8_t vector2_ed25519[vector2_size_ed25519];
typedef uint8_t vector2_ed448[vector2_size_ed448];

void inverse_elliptic(fixed s, fixptr x, fixptr r, fixptr p, fixptr p2);
void inverse_secp256k1(fixed s, fixptr x, fixptr r);
void inverse_secp256r1(fixed s, fixptr x, fixptr r);
void inverse_ed25519(fixed s, fixptr x, fixptr r);
void inverse_ed448(fixed s, fixptr x, fixptr r);

void inverse_n_elliptic(fixed s, fixptr x, fixptr r, fixptr p, fixptr p2);
void inverse_n_secp256k1(fixed s, fixptr x, fixptr r);
void inverse_n_secp256r1(fixed s, fixptr x, fixptr r);
void inverse_n_ed25519(fixed s, fixptr x, fixptr r);
void inverse_n_ed448(fixed s, fixptr x, fixptr r);

void affine_secp256k1(fixed s, fixptr3 v, fixptr rx, fixptr ry);
void affine_secp256r1(fixed s, fixptr3 v, fixptr rx, fixptr ry);
void affine_ed25519(fixed s, fixptr4 v, fixptr rx, fixptr ry);
void affine_ed448(fixed s, fixptr3 v, fixptr rx, fixptr ry);

int equal_point_elliptic(fixed s, fixptr *p, fixptr *q, fixptr curve_p);
int equal_point_secp256k1(fixed s, fixptr3 p, fixptr3 q);
int equal_point_secp256r1(fixed s, fixptr3 p, fixptr3 q);
int equal_point_ed25519(fixed s, fixptr4 p, fixptr4 q);
int equal_point_ed448(fixed s, fixptr3 p, fixptr3 q);

int valid_secp256k1(fixed s, fixptr3 r);
int valid_secp256r1(fixed s, fixptr3 r);
int valid_ed25519(fixed s, fixptr4 r);
int valid_ed448(fixed s, fixptr3 r);

int neutral_secp256k1(fixed s, fixptr3 r);
int neutral_secp256r1(fixed s, fixptr3 r);
int neutral_ed25519(fixed s, fixptr4 r);
int neutral_ed448(fixed s, fixptr3 r);

void private_secp256k1(fixed s, struct fixed_random *state, fixptr r);
void private_secp256r1(fixed s, struct fixed_random *state, fixptr r);
void private_ed25519(fixed s, struct fixed_random *state, fixptr r);
void private_ed448(fixed s, struct fixed_random *state, fixptr r);

void public_secp256k1(fixed s, fixptr private_key, fixptr3 r);
void public_secp256r1(fixed s, fixptr private_key, fixptr3 r);
void public_ed25519(fixed s, fixptr private_key, fixptr4 r);
void public_ed448(fixed s, fixptr private_key, fixptr3 r);

int encode_secp256k1(fixed s, fixptr3 v, vector2_secp256k1 r, int compress);
int encode_secp256r1(fixed s, fixptr3 v, vector2_secp256r1 r, int compress);
int encode_ed25519(fixed s, fixptr4 v, vector2_ed25519 r);
int encode_ed448(fixed s, fixptr3 v, vector2_ed448 r);

void decode_secp256k1(fixed s, vector2_secp256k1 v, fixptr3 r);
void decode_secp256r1(fixed s, vector2_secp256r1 v, fixptr3 r);
void decode_ed25519(fixed s, vector2_ed25519 v, fixptr4 r);
void decode_ed448(fixed s, vector2_ed448 v, fixptr3 r);

int sign_secp256k1(fixed s, fixptr private_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size);
int sign_secp256r1(fixed s, fixptr private_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size);
int sign_ed25519(fixed s, fixptr private_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size);
int sign_ed448(fixed s, fixptr private_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size);

int verify_secp256k1(fixed s, fixptr public_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size, int *ret);
int verify_secp256r1(fixed s, fixptr public_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size, int *ret);
int verify_ed25519(fixed s, fixptr public_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size, int *ret);
int verify_ed448(fixed s, fixptr public_key,
		fixptr sign_r, fixptr sign_s, const void *ptr, size_t size, int *ret);

#endif

