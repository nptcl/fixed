#ifndef __FIXED_PUBLIC_HEADER__
#define __FIXED_PUBLIC_HEADER__

#include "elliptic.h"
#include "fixed.h"
#include "random.h"

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

void private_weierstrass(fixed s, struct fixed_random *state, fixptr r, fixptr curve_n);
void private_secp256k1(fixed s, struct fixed_random *state, fixptr r);
void private_secp256r1(fixed s, struct fixed_random *state, fixptr r);
void private_ed25519(fixed s, struct fixed_random *state, fixptr r);
void private_ed448(fixed s, struct fixed_random *state, fixptr r);

void public_secp256k1(fixed s, fixptr private_key, fixptr3 r);
void public_secp256r1(fixed s, fixptr private_key, fixptr3 r);
void public_ed25519(fixed s, fixptr private_key, fixptr4 r);
void public_ed448(fixed s, fixptr private_key, fixptr3 r);

void public_sign_ed25519(fixed s, fixptr private_key, fixptr r, fixptr sign);
void public_sign_ed448(fixed s, fixptr private_key, fixptr r, fixptr sign);


/*
 *  encode / decode
 */
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

int encode_secp256k1(fixed s, fixptr3 v, vector2_secp256k1 r, int compress);
int encode_secp256r1(fixed s, fixptr3 v, vector2_secp256r1 r, int compress);
int encode_ed25519(fixed s, fixptr4 v, vector2_ed25519 r);
int encode_ed448(fixed s, fixptr3 v, vector2_ed448 r);

int decode_secp256k1(fixed s, vector2_secp256k1 v, fixptr3 r);
int decode_secp256r1(fixed s, vector2_secp256r1 v, fixptr3 r);
int decode_ed25519(fixed s, vector2_ed25519 v, fixptr4 r);
int decode_ed448(fixed s, vector2_ed448 v, fixptr3 r);


/*
 *  string
 */
#define string1_size_secp256k1		(64+1)
#define string2_size_secp256k1		(2+64+64+1)
#define string1_size_secp256r1		(64+1)
#define string2_size_secp256r1		(2+64+64+1)
#define string1_size_ed25519		(64+1)
#define string2_size_ed25519		(64+1)
#define string1_size_ed448			(114+1)
#define string2_size_ed448			(114+1)

typedef char string1_secp256k1[string1_size_secp256k1];
typedef char string2_secp256k1[string2_size_secp256k1];
typedef char string1_secp256r1[string1_size_secp256k1];
typedef char string2_secp256r1[string2_size_secp256k1];
typedef char string1_ed25519[string1_size_ed25519];
typedef char string2_ed25519[string2_size_ed25519];
typedef char string1_ed448[string1_size_ed448];
typedef char string2_ed448[string2_size_ed448];

int encode1_string_secp256k1(fixed s, fixptr x, string1_secp256k1 r);
int encode2_string_secp256k1(fixed s, fixptr3 x, string2_secp256k1 r);
int decode1_string_secp256k1(fixed s, const string1_secp256k1 x, fixptr r);
int decode2_string_secp256k1(fixed s, const string2_secp256k1 x, fixptr3 r);

int encode1_string_secp256r1(fixed s, fixptr x, string1_secp256r1 r);
int encode2_string_secp256r1(fixed s, fixptr3 x, string2_secp256r1 r);
int decode1_string_secp256r1(fixed s, const string1_secp256r1 x, fixptr r);
int decode2_string_secp256r1(fixed s, const string2_secp256r1 x, fixptr3 r);

int encode1_string_ed25519(fixed s, fixptr x, string1_ed25519 r);
int encode2_string_ed25519(fixed s, fixptr4 x, string2_ed25519 r);
int decode1_string_ed25519(fixed s, const string1_ed25519 x, fixptr r);
int decode2_string_ed25519(fixed s, const string2_ed25519 x, fixptr4 r);

int encode1_string_ed448(fixed s, fixptr x, string1_ed448 r);
int encode2_string_ed448(fixed s, fixptr3 x, string2_ed448 r);
int decode1_string_ed448(fixed s, const string1_ed448 x, fixptr r);
int decode2_string_ed448(fixed s, const string2_ed448 x, fixptr3 r);

#endif

