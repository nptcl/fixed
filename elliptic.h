#ifndef __ELLIPTIC_HEADER__
#define __ELLIPTIC_HEADER__

#include "fixed.h"

#define elliptic_secp256k1_bit		256
#define elliptic_secp256r1_bit		256
#define elliptic_ed25519_bit		256
#define elliptic_ed448_bit			512

#define elliptic_secp256k1_byte		(elliptic_secp256k1_bit/8)
#define elliptic_secp256r1_byte		(elliptic_secp256r1_bit/8)
#define elliptic_ed25519_byte		(elliptic_ed25519_bit/8)
#define elliptic_ed448_byte			(elliptic_ed448_bit/8)

typedef fixptr fixptr3[3];
typedef fixptr fixptr4[4];

/* secp256k1 */
extern int Elliptic_secp256k1_h;
extern fixptr Elliptic_secp256k1_p;
extern fixptr Elliptic_secp256k1_a;
extern fixptr Elliptic_secp256k1_b;
extern fixptr Elliptic_secp256k1_n;
extern fixptr Elliptic_secp256k1_p2;
extern fixptr Elliptic_secp256k1_n2;
extern fixptr3 Elliptic_secp256k1_g;
extern fixptr3 Elliptic_secp256k1_o;

/* secp256r1 */
extern int Elliptic_secp256r1_h;
extern fixptr Elliptic_secp256r1_p;
extern fixptr Elliptic_secp256r1_a;
extern fixptr Elliptic_secp256r1_b;
extern fixptr Elliptic_secp256r1_n;
extern fixptr Elliptic_secp256r1_p2;
extern fixptr Elliptic_secp256r1_n2;
extern fixptr3 Elliptic_secp256r1_g;
extern fixptr3 Elliptic_secp256r1_o;

/* ed25519 */
extern int Elliptic_ed25519_h;
extern fixptr Elliptic_ed25519_p;
extern fixptr Elliptic_ed25519_a;
extern fixptr Elliptic_ed25519_d;
extern fixptr Elliptic_ed25519_n;
extern fixptr Elliptic_ed25519_p2;
extern fixptr Elliptic_ed25519_n2;
extern fixptr Elliptic_ed25519_d2;
extern fixptr4 Elliptic_ed25519_g;
extern fixptr4 Elliptic_ed25519_o;

/* ed448 */
extern int Elliptic_ed448_h;
extern fixptr Elliptic_ed448_p;
extern fixptr Elliptic_ed448_a;
extern fixptr Elliptic_ed448_d;
extern fixptr Elliptic_ed448_n;
extern fixptr Elliptic_ed448_p2;
extern fixptr Elliptic_ed448_n2;
extern fixptr3 Elliptic_ed448_g;
extern fixptr3 Elliptic_ed448_o;
extern uint8_t Elliptic_ed448_sha_size;
extern uint8_t Elliptic_ed448_sha_context[256];

/* vector */
void push3_fixed(fixed s, fixptr3 r);
void push4_fixed(fixed s, fixptr4 r);
void pop3_fixed(fixed s);
void pop4_fixed(fixed s);
#define setp3_fixptr(r,x,y,z)		(r[0]=(x), r[1]=(y), r[2]=(z))
#define setp4_fixptr(r,x,y,z,w)		(r[0]=(x), r[1]=(y), r[2]=(z), r[3]=(w))
void setv3_fixed(fixed s, fixptr3 r, fixnum x, fixnum y, fixnum z);
void setv4_fixed(fixed s, fixptr4 r, fixnum x, fixnum y, fixnum z, fixnum t);
void memcpy3_fixed(fixed s, fixptr3 dst, fixptr3 src);
void memcpy4_fixed(fixed s, fixptr4 dst, fixptr4 src);

/* operator */
void rem1_elliptic_curve(fixed s, fixptr x1, fixptr r1, fixptr curve);

void rem2_elliptic_curve(fixed s, fixptr x2, fixptr r1, fixptr curve_p);
void rem2_elliptic_secp256k1(fixed s, fixptr x2, fixptr r1);
void rem2_elliptic_secp256r1(fixed s, fixptr x2, fixptr r1);
void rem2_elliptic_ed25519(fixed s, fixptr x2, fixptr r1);
void rem2_elliptic_ed448(fixed s, fixptr x2, fixptr r1);

void add_elliptic_curve(fixptr x, fixptr y, fixptr r, fixptr curve_p, fixsize word1);
void add_elliptic_secp256k1(fixptr x, fixptr y, fixptr r, fixsize word1);
void add_elliptic_secp256r1(fixptr x, fixptr y, fixptr r, fixsize word1);
void add_elliptic_ed25519(fixptr x, fixptr y, fixptr r, fixsize word1);
void add_elliptic_ed448(fixptr x, fixptr y, fixptr r, fixsize word1);

void dbl_elliptic_curve(fixptr x, fixptr r, fixptr curve_p, fixsize word1);
void dbl_elliptic_secp256k1(fixptr x, fixptr r, fixsize word1);
void dbl_elliptic_secp256r1(fixptr x, fixptr r, fixsize word1);
void dbl_elliptic_ed25519(fixptr x, fixptr r, fixsize word1);
void dbl_elliptic_ed448(fixptr x, fixptr r, fixsize word1);

void sub_elliptic_curve(fixptr x, fixptr y, fixptr r, fixptr curve_p, fixsize word1);
void sub_elliptic_secp256k1(fixptr x, fixptr y, fixptr r, fixsize word1);
void sub_elliptic_secp256r1(fixptr x, fixptr y, fixptr r, fixsize word1);
void sub_elliptic_ed25519(fixptr x, fixptr y, fixptr r, fixsize word1);
void sub_elliptic_ed448(fixptr x, fixptr y, fixptr r, fixsize word1);

void println3_fixptr(fixed s, fixptr3 r, FILE *file, unsigned radix);
void println4_fixptr(fixed s, fixptr3 r, FILE *file, unsigned radix);
int string_integer_elliptic(const char *x, void *p, int size, int reverse);
void integer_string_elliptic(const void *p, int size, char *x, int reverse);

/* make */
fixed make_secp256k1_fixed(void);
fixed make_secp256r1_fixed(void);
fixed make_ed25519_fixed(void);
fixed make_ed448_fixed(void);

/* init */
void init_elliptic_secp256k1(void);
void init_elliptic_secp256r1(void);
void init_elliptic_ed25519(void);
void init_elliptic_ed448(void);
void init_elliptic(void);

#endif

