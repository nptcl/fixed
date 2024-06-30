#include "addition.h"
#include "crypt.h"
#include "elliptic.h"
#include "fixed.h"
#include "public.h"
#include "random.h"
#include "sha.h"

/*
 *  inverse
 */
void inverse_elliptic(fixed s, fixptr x, fixptr r, fixptr p, fixptr p2)
{
	power_mod_fixptr(s, x, p2, p, r);
}

void inverse_secp256k1(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_secp256k1_p2, Elliptic_secp256k1_p, r);
}

void inverse_secp256r1(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_secp256r1_p2, Elliptic_secp256r1_p, r);
}

void inverse_ed25519(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_ed25519_p2, Elliptic_ed25519_p, r);
}

void inverse_ed448(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_ed448_p2, Elliptic_ed448_p, r);
}


/*
 *  inverse_n
 */
void inverse_n_elliptic(fixed s, fixptr x, fixptr r, fixptr p, fixptr p2)
{
	power_mod_fixptr(s, x, p2, p, r);
}

void inverse_n_secp256k1(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_secp256k1_n2, Elliptic_secp256k1_n, r);
}

void inverse_n_secp256r1(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_secp256r1_n2, Elliptic_secp256r1_n, r);
}

void inverse_n_ed25519(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_ed25519_n2, Elliptic_ed25519_n, r);
}

void inverse_n_ed448(fixed s, fixptr x, fixptr r)
{
	power_mod_fixptr(s, x, Elliptic_ed448_n2, Elliptic_ed448_n, r);
}


/*
 *  affine
 */
static void affine_elliptic(fixed s, fixptr *v,
		fixptr rx, fixptr ry, fixptr p, fixptr p2)
{
	fixptr w, z;

	w = push2get_fixed(s);
	z = push1get_fixed(s);

	/* 1/z */
	inverse_elliptic(s, v[2], z, p, p2);

	/* x/z */
	mul_fixptr(v[0], z, s->word1, w, s->word2);
	rem2_elliptic_curve(s, w, rx, p);

	/* y/z */
	mul_fixptr(v[1], z, s->word1, w, s->word2);
	rem2_elliptic_curve(s, w, ry, p);

	pop1_fixed(s);
	pop2_fixed(s);
}

void affine_secp256k1(fixed s, fixptr3 v, fixptr rx, fixptr ry)
{
	affine_elliptic(s, v, rx, ry, Elliptic_secp256k1_p, Elliptic_secp256k1_p2);
}

void affine_secp256r1(fixed s, fixptr3 v, fixptr rx, fixptr ry)
{
	affine_elliptic(s, v, rx, ry, Elliptic_secp256r1_p, Elliptic_secp256r1_p2);
}

void affine_ed25519(fixed s, fixptr4 v, fixptr rx, fixptr ry)
{
	affine_elliptic(s, v, rx, ry, Elliptic_ed25519_p, Elliptic_ed25519_p2);
}

void affine_ed448(fixed s, fixptr3 v, fixptr rx, fixptr ry)
{
	affine_elliptic(s, v, rx, ry, Elliptic_ed448_p, Elliptic_ed448_p2);
}


/*
 *  equal_point
 */
int equal_point_elliptic(fixed s, fixptr *p, fixptr *q, fixptr curve_p)
{
	int check;
	fixptr w2, x, y;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);

	/* check1 */
	mul_fixptr(p[0], q[2], word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	mul_fixptr(q[0], p[2], word1, w2, word2);
	rem2_elliptic_curve(s, w2, y, curve_p);
	sub_elliptic_curve(x, y, x, curve_p, word1);
	if (! zerop_fixptr(x, word1)) {
		check = 0;
		goto finish;
	}

	/* check2 */
	mul_fixptr(p[1], q[2], word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	mul_fixptr(q[1], p[2], word1, w2, word2);
	rem2_elliptic_curve(s, w2, y, curve_p);
	sub_elliptic_curve(x, y, y, curve_p, word1);
	if (! zerop_fixptr(y, word1)) {
		check = 0;
		goto finish;
	}

	/* equal */
	check = 1;

finish:
	pop1n_fixed(s, 2);
	pop2_fixed(s);

	return check;
}

int equal_point_secp256k1(fixed s, fixptr3 p, fixptr3 q)
{
	return equal_point_elliptic(s, p, q, Elliptic_secp256k1_p);
}

int equal_point_secp256r1(fixed s, fixptr3 p, fixptr3 q)
{
	return equal_point_elliptic(s, p, q, Elliptic_secp256r1_p);
}

int equal_point_ed25519(fixed s, fixptr4 p, fixptr4 q)
{
	return equal_point_elliptic(s, p, q, Elliptic_ed25519_p);
}

int equal_point_ed448(fixed s, fixptr3 p, fixptr3 q)
{
	return equal_point_elliptic(s, p, q, Elliptic_ed448_p);
}


/*
 *  valid
 */
static int valid_weierstrass_elliptic(fixed s, fixptr x0, fixptr y0,
		fixptr curve_a, fixptr curve_b, fixptr curve_p)
{
	int compare;
	fixptr x, y, z, w;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);

	/* y*y */
	mul_square_fixptr(y0, word1, w, word2);
	rem2_elliptic_curve(s, w, y, curve_p);

	/* x*x*x */
	mul_square_fixptr(x0, word1, w, word2);
	rem2_elliptic_curve(s, w, x, curve_p);
	mul_fixptr(x, x0, word1, w, word2);
	rem2_elliptic_curve(s, w, x, curve_p);

	/* a*x */
	mul_fixptr(curve_a, x0, word1, w, word2);
	rem2_elliptic_curve(s, w, z, curve_p);

	/* + */
	add_elliptic_curve(x, z, x, curve_p, word1);
	add_elliptic_curve(x, curve_b, x, curve_p, word1);

	/* compare */
	compare = compare_fixptr(x, word1, y, word1);

	/* pop */
	pop1n_fixed(s, 3);
	pop2_fixed(s);

	return compare == 0;
}

int valid_secp256k1(fixed s, fixptr3 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_secp256k1(s, r, x, y);
	check = valid_weierstrass_elliptic(s, x, y,
			Elliptic_secp256k1_a,
			Elliptic_secp256k1_b,
			Elliptic_secp256k1_p);
	pop1n_fixed(s, 2);

	return check;
}

int valid_secp256r1(fixed s, fixptr3 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_secp256r1(s, r, x, y);
	check = valid_weierstrass_elliptic(s, x, y,
			Elliptic_secp256r1_a,
			Elliptic_secp256r1_b,
			Elliptic_secp256r1_p);
	pop1n_fixed(s, 2);

	return check;
}

static int valid_edwards_elliptic(fixed s, fixptr x0, fixptr y0,
		fixptr curve_a, fixptr curve_d, fixptr curve_p)
{
	int compare;
	fixptr x, y, xy, w;
	fixsize word1, word2;
	fixnum ignore;

	word1 = s->word1;
	word2 = s->word2;
	w = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	xy = push1get_fixed(s);

	/* x <- x*x */
	mul_square_fixptr(x0, word1, w, word2);
	rem2_elliptic_curve(s, w, x, curve_p);

	/* y <- y*y */
	mul_square_fixptr(y0, word1, w, word2);
	rem2_elliptic_curve(s, w, y, curve_p);

	/* xy <- x*y */
	mul_fixptr(x, y, word1, w, word2);
	rem2_elliptic_curve(s, w, xy, curve_p);

	/* x <- a*x */
	mul_fixptr(curve_a, x, word1, w, word2);
	rem2_elliptic_curve(s, w, x, curve_p);

	/* x <- x + y */
	add_elliptic_curve(x, y, x, curve_p, word1);

	/* y <- d*xy */
	mul_fixptr(curve_d, xy, word1, w, word2);
	rem2_elliptic_curve(s, w, y, curve_p);

	/* y <- 1 + y */
	addv_fixptr(y, s->word1, 1, &ignore);
	rem1_elliptic_curve(y, curve_p, word1);

	/* compare */
	compare = compare_fixptr(x, word1, y, word1);

	/* pop */
	pop1n_fixed(s, 3);
	pop2_fixed(s);

	return compare == 0;
}

static int valid_edwards_ed25519(fixed s, fixptr4 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed25519(s, r, x, y);
	check = valid_edwards_elliptic(s, x, y,
			Elliptic_ed25519_a,
			Elliptic_ed25519_d,
			Elliptic_ed25519_p);
	pop1n_fixed(s, 2);

	return check;
}

static int valid_point4_ed25519(fixed s, fixptr4 r)
{
	int compare;
	fixptr x, y, z, t, xy, w2;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);
	t = push1get_fixed(s);
	xy = push1get_fixed(s);

	inverse_ed25519(s, r[2], z);
	mul_fixptr(r[0], z, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, x);
	mul_fixptr(r[1], z, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, y);
	mul_fixptr(r[3], z, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, t);
	mul_fixptr(x, y, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, xy);
	compare = compare_fixptr(xy, word1, t, word1);

	pop1n_fixed(s, 5);
	pop2_fixed(s);

	return compare == 0;
}

int valid_ed25519(fixed s, fixptr4 r)
{
	return valid_point4_ed25519(s, r)
		&& valid_edwards_ed25519(s, r);
}

int valid_ed448(fixed s, fixptr3 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed448(s, r, x, y);
	check = valid_edwards_elliptic(s, x, y,
			Elliptic_ed448_a,
			Elliptic_ed448_d,
			Elliptic_ed448_p);
	pop1n_fixed(s, 2);

	return check;
}


/*
 *  neutral
 */
int neutral_secp256k1(fixed s, fixptr3 r)
{
	return zerop_fixptr(r[2], s->word1);
}

int neutral_secp256r1(fixed s, fixptr3 r)
{
	return zerop_fixptr(r[2], s->word1);
}

int neutral_ed25519(fixed s, fixptr4 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed25519(s, r, x, y);
	check = zerop_fixptr(x, s->word1)
		&& (compare_fixnum_fixptr(y, s->word1, 1) == 0);
	pop1n_fixed(s, 2);

	return check;
}

int neutral_ed448(fixed s, fixptr3 r)
{
	int check;
	fixptr x, y;

	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed448(s, r, x, y);
	check = zerop_fixptr(x, s->word1)
		&& (compare_fixnum_fixptr(y, s->word1, 1) == 0);
	pop1n_fixed(s, 2);

	return check;
}


/*
 *  make private key
 */
static void private_weierstrass(fixed s,
		struct fixed_random *state, fixptr r, fixptr curve_n)
{
	do {
		random_less_fixptr(state, Elliptic_secp256k1_n, r, s->word1);
	} while (zerop_fixptr(r, s->word1));
}

void private_secp256k1(fixed s, struct fixed_random *state, fixptr r)
{
	private_weierstrass(s, state, r, Elliptic_secp256k1_n);
}

void private_secp256r1(fixed s, struct fixed_random *state, fixptr r)
{
	private_weierstrass(s, state, r, Elliptic_secp256r1_n);
}

void private_ed25519(fixed s, struct fixed_random *state, fixptr r)
{
	random_full_fixptr(state, r, s->word1);
}

void private_ed448(fixed s, struct fixed_random *state, fixptr r)
{
	random_full_fixptr(state, r, s->word1);
}


/*
 *  make public key
 */
void public_secp256k1(fixed s, fixptr private_key, fixptr3 r)
{
	multiple_secp256k1(s, private_key, Elliptic_secp256k1_g, r);
}

void public_secp256r1(fixed s, fixptr private_key, fixptr3 r)
{
	multiple_secp256r1(s, private_key, Elliptic_secp256r1_g, r);
}

void public_sign_ed25519(fixed s, fixptr private_key, fixptr r, fixptr sign)
{
	uint8_t x[BYTE_SHA512ENCODE];
	struct sha64encode sha;
	fixsize word1;

	/* SHA-512 */
	word1 = s->word1;
	output_fixptr(private_key, word1, x, elliptic_ed25519_byte, 1);
	init_sha512encode(&sha);
	read_sha512encode(&sha, x, elliptic_ed25519_byte);
	calc_sha512encode(&sha, x);

	/* x */
	x[0] &= 0xF8;
	x[32 - 1] &= 0x7F;
	x[32 - 1] |= 0x40;

	/* r */
	input_fixptr(r, word1, x, elliptic_ed25519_byte, 1);

	/* sign */
	if (sign)
		input_fixptr(sign, word1, x + 32, elliptic_ed25519_byte, 1);
}

void public_ed25519(fixed s, fixptr private_key, fixptr4 r)
{
	fixptr x;

	x = push1get_fixed(s);
	public_sign_ed25519(s, private_key, x, NULL);
	multiple_ed25519(s, x, Elliptic_ed25519_g, r);
	pop1_fixed(s);
}

void public_sign_ed448(fixed s, fixptr private_key, fixptr r, fixptr sign)
{
	/*
	 *  ed448 -> 57byte
	 *  fixed -> 64byte
	 */
	uint8_t x[57*2];
	struct sha3encode sha;
	fixsize word1;

	/* Hash SHAKE-256 */
	word1 = s->word1;
	output_fixptr(private_key, word1, x, 57, 1);
	init_shake_256_encode(&sha);
	read_sha3encode(&sha, x, 57);
	result_sha3encode(&sha, x, 57*2);

	/* x */
	x[0] &= 0xFC;
	x[57 - 1] = 0;
	x[57 - 2] |= 0x80;

	/* r */
	input_fixptr(r, word1, x, 57, 1);

	/* sign */
	if (sign)
		input_fixptr(sign, word1, x + 57, 57, 1);
}

void public_ed448(fixed s, fixptr private_key, fixptr3 r)
{
	fixptr x;

	x = push1get_fixed(s);
	public_sign_ed448(s, private_key, x, NULL);
	multiple_ed448(s, x, Elliptic_ed448_g, r);
	pop1_fixed(s);
}


/*
 *  encode
 */
int encode_secp256k1(fixed s, fixptr3 v, vector2_secp256k1 r, int compress)
{
	int y0;
	fixsize word1;

	/* z = 0 */
	word1 = s->word1;
	if (zerop_fixptr(v[2], word1)) {
		r[0] = 0;
		return 1;
	}

	/* uncompress */
	if (! compress) {
		r[0] = 0x04;
		output_fixptr(v[0], word1, r + 1, 32, 0);
		output_fixptr(v[1], word1, r + 1 + 32, 32, 0);
		return 1 + 32 + 32;
	}

	/* compress */
	y0 = (v[1][0] & 0x01) != 0;
	r[0] = y0? 0x03: 0x02;
	output_fixptr(v[0], word1, r + 1, 32, 0);
	return 1 + 32;
}

int encode_secp256r1(fixed s, fixptr3 v, vector2_secp256r1 r, int compress)
{
	return encode_secp256k1(s, v, r, compress);
}

int encode_ed25519(fixed s, fixptr4 v, vector2_ed25519 r)
{
	fixptr x, y;
	fixsize word1;

	word1 = s->word1;
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed25519(s, v, x, y);
	if (x[0] & 0x01)
		setbit_fixptr(y, word1, 1, 255);
	output_fixptr(y, word1, r, vector2_size_ed25519, 1);
	pop1n_fixed(s, 2);

	return vector2_size_ed25519;
}

int encode_ed448(fixed s, fixptr3 v, vector2_ed448 r)
{
	fixptr x, y;
	fixsize word1;

	word1 = s->word1;
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	affine_ed448(s, v, x, y);
	if (x[0] & 0x01)
		setbit_fixptr(y, word1, 1, 455);
	output_fixptr(y, word1, r, vector2_size_ed448, 1);
	pop1n_fixed(s, 2);

	return vector2_size_ed448;
}


/*
 *  decode
 */
static int square_root_mod_4_elliptic(fixed s, fixptr a, fixptr r, fixptr curve_p)
{
	int compare;
	fixptr w, y;
	fixnum ignore;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w = push2get_fixed(s);
	y = push1get_fixed(s);

	/* (p+1)/4 */
	memcpy_fixptr(r, curve_p, word1);
	addv_fixptr(r, word1, 1, &ignore);
	shiftr_fixptr(r, word1, 2);  /* div 4 */
	/* power_mod */
	power_mod_fixptr(s, a, r, curve_p, r);
	/* r*r */
	mul_square_fixptr(r, word1, w, word2);
	rem2_elliptic_curve(s, w, y, curve_p);
	/* compare */
	compare = compare_fixptr(a, word1, y, word1);

	pop1_fixed(s);
	pop2_fixed(s);

	return compare != 0;
}

static int decode_weierstrass_compress(fixed s,
		vector2_secp256k1 v, fixptr3 r,
		fixptr curve_a, fixptr curve_b, fixptr curve_p)
{
	int y0, check;
	fixptr w2, a, b;
	fixsize word1, word2;

	/* y0 */
	if (v[0] == 0x02)
		y0 = 0;
	else if (v[0] == 0x03)
		y0 = 1;
	else
		return 1;

	/* push */
	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s);
	a = push1get_fixed(s);
	b = push1get_fixed(s);

	/* x */
	input_fixptr(r[0], word1, v + 1, 32, 0);

	/* x*x*x */
	mul_fixptr(r[0], r[0], word1, w2, word2);
	rem2_elliptic_curve(s, w2, a, curve_p);
	mul_fixptr(a, r[0], word1, w2, word2);
	rem2_elliptic_curve(s, w2, a, curve_p);

	/* curve_a*x */
	mul_fixptr(curve_a, r[0], word1, w2, word2);
	rem2_elliptic_curve(s, w2, b, curve_p);

	/* + */
	add_elliptic_curve(a, b, a, curve_p, word1);
	add_elliptic_curve(a, curve_b, a, curve_p, word1);

	/* square root */
	check = square_root_mod_4_elliptic(s, a, r[1], curve_p);
	if (check == 0) {
		if ((r[1][0] & 0x01) != y0)
			sub_elliptic_curve(curve_p, r[1], r[1], curve_p, word1);
		setv_fixptr(r[2], word1, 1);
	}
	pop1n_fixed(s, 2);
	pop2_fixed(s);

	return check;
}

static void decode_weierstrass_uncompress(fixed s,
		vector2_secp256k1 v, fixptr3 r, fixptr curve_p)
{
	fixsize word1;

	word1 = s->word1;
	input_fixptr(r[0], word1, v + 1, 32, 0);
	input_fixptr(r[1], word1, v + 1 + 32, 32, 0);
	setv_fixptr(r[2], word1, 1);
}

static int decode_weierstrass(fixed s, vector2_secp256k1 v, fixptr3 r,
		fixptr curve_a, fixptr curve_b, fixptr curve_p, fixptr3 curve_o,
		int (*valid)(fixed, fixptr3))
{
	/* O */
	if (v[0] == 0x00) {
		memcpy3_fixed(s, r, curve_o);
		return 0;
	}

	/* uncompress */
	if (v[0] == 0x04) {
		decode_weierstrass_uncompress(s, v, r, curve_p);
		return (*valid)(s, r) == 0;
	}

	/* compress */
	return decode_weierstrass_compress(s, v, r, curve_a, curve_b, curve_p);
}

int decode_secp256k1(fixed s, vector2_secp256k1 v, fixptr3 r)
{
	return decode_weierstrass(s, v, r,
			Elliptic_secp256k1_a,
			Elliptic_secp256k1_b,
			Elliptic_secp256k1_p,
			Elliptic_secp256k1_o,
			valid_secp256k1);
}

int decode_secp256r1(fixed s, vector2_secp256r1 v, fixptr3 r)
{
	return decode_weierstrass(s, v, r,
			Elliptic_secp256r1_a,
			Elliptic_secp256r1_b,
			Elliptic_secp256r1_p,
			Elliptic_secp256r1_o,
			valid_secp256r1);
}

static int decode_x_ed25519(fixed s, fixptr y, fixptr x)
{
	int compare, check;
	fixptr w2, yy, u1, v1, v2, v3, v4, u1v3, p, v1x2;
	fixsize word1, word2;
	fixnum ignore;

	word1 = s->word1;
	word2 = s->word2;
	compare = compare_fixptr(y, word1, Elliptic_ed25519_p, word1);
	if (0 <= compare)
		return 1;  /* error */

	w2 = push2get_fixed(s);
	yy = push1get_fixed(s);
	u1 = push1get_fixed(s);
	v1 = push1get_fixed(s);
	v2 = push1get_fixed(s);
	v3 = push1get_fixed(s);
	v4 = push1get_fixed(s);
	u1v3 = push1get_fixed(s);
	p = push1get_fixed(s);
	v1x2 = push1get_fixed(s);

	/* yy = y*y */
	mul_square_fixptr(y, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, yy);
	/* u1 = y-1 */
	if (zerop_fixptr(yy, word1))
		memcpy_fixptr(u1, Elliptic_ed25519_p, word1);
	else
		memcpy_fixptr(u1, yy, word1);
	subv_fixptr(u1, word1, 1, &ignore);
	/* v1 = d*yy + 1 */
	mul_fixptr(Elliptic_ed25519_d, yy, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v1);
	addv_fixptr(v1, word1, 1, &ignore);
	if (compare_fixptr(v1, word1, Elliptic_ed25519_p, word1) == 0)
		setv_fixptr(v1, word1, 0);
	/* v2 = v1*v1 */
	mul_square_fixptr(v1, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v2);
	/* v3 = v1*v2 */
	mul_fixptr(v1, v2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v3);
	/* v4 = v2*v2 */
	mul_square_fixptr(v2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v4);
	/* u1v3 = u1*v3*/
	mul_fixptr(u1, v3, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, u1v3);
	/* p = (p-5)/8 */
	memcpy_fixptr(p, Elliptic_ed25519_p, word1);
	subv_fixptr(p, word1, 5, &ignore);
	shiftr_fixptr(p, word1, 3);  /* div 8 */
	/* x = u1v3 * (u1v3*v4)^p */
	mul_fixptr(u1v3, v4, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, x);
	power_mod_fixptr(s, x, p, Elliptic_ed25519_p, x);
	mul_fixptr(u1v3, x, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, x);
	/* v1x2 = v1*x*x */
	mul_square_fixptr(x, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v1x2);
	mul_fixptr(v1, v1x2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, v1x2);

	/* v1x2 == u1 */
	check = 1;  /* error */
	compare = compare_fixptr(v1x2, word1, u1, word1);
	if (compare == 0) {
		check = 0;
		goto finish;
	}

	/* v1x2 == -u1 */
	sub_elliptic_ed25519(Elliptic_ed25519_p, u1, u1, word1);
	compare = compare_fixptr(v1x2, word1, u1, word1);
	if (compare == 0) {
		/* p = (p-1)/4 */
		memcpy_fixptr(p, Elliptic_ed25519_p, word1);
		subv_fixptr(p, word1, 1, &ignore);
		shiftr_fixptr(p, word1, 2);  /* div 4 */
		/* u1 = 2^p */
		setv_fixptr(u1, word1, 2);
		power_mod_fixptr(s, u1, p, Elliptic_ed25519_p, u1);
		/* x = x*u1 */
		mul_fixptr(x, u1, word1, w2, word2);
		rem2_elliptic_ed25519(s, w2, x);
		/* result */
		check = 0;
		goto finish;
	}

finish:
	pop1n_fixed(s, 9);
	pop2_fixed(s);

	return check;
}

int decode_ed25519(fixed s, vector2_ed25519 v, fixptr4 r)
{
	int x0, check;
	fixptr w2, x, y;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);

	/* y, x0 */
	input_fixptr(y, word1, v, vector2_size_ed25519, 1);
	x0 = logbitp_fixptr(y, word1, 255);
	setbit_fixptr(y, word1, 0, 255);
	/* x */
	check = decode_x_ed25519(s, y, x);
	if (check)
		goto finish;
	if (x0 && zerop_fixptr(x, word1)) {
		check = 1;
		goto finish;
	}
	if ((x[0] & 0x01) != x0)
		sub_elliptic_ed25519(Elliptic_ed25519_p, x, x, word1);
	/* x, y -> r */
	memcpy_fixptr(r[0], x, word1);
	memcpy_fixptr(r[1], y, word1);
	setv_fixptr(r[2], word1, 1);
	/* t */
	mul_fixptr(x, y, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, r[3]);

finish:
	pop1n_fixed(s, 2);
	pop2_fixed(s);

	return check;
}

static int decode_x_ed448(fixed s, fixptr y, fixptr x)
{
	int compare, check;
	fixptr w2, yy, u1, u2, u3, u5, v1, v3, u3v1, u5v3, p, v1x2;
	fixsize word1, word2;
	fixnum ignore;

	word1 = s->word1;
	word2 = s->word2;
	compare = compare_fixptr(y, word1, Elliptic_ed448_p, word1);
	if (0 <= compare)
		return 1;  /* error */

	w2 = push2get_fixed(s);
	yy = push1get_fixed(s);
	u1 = push1get_fixed(s);
	u2 = push1get_fixed(s);
	u3 = push1get_fixed(s);
	u5 = push1get_fixed(s);
	v1 = push1get_fixed(s);
	v3 = push1get_fixed(s);
	u3v1 = push1get_fixed(s);
	u5v3 = push1get_fixed(s);
	p = push1get_fixed(s);
	v1x2 = push1get_fixed(s);

	/* yy = y*y */
	mul_square_fixptr(y, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, yy);
	/* u1 = y-1 */
	if (zerop_fixptr(yy, word1))
		memcpy_fixptr(u1, Elliptic_ed448_p, word1);
	else
		memcpy_fixptr(u1, yy, word1);
	subv_fixptr(u1, word1, 1, &ignore);
	/* u2 = u1*u1 */
	mul_square_fixptr(u1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, u2);
	/* u3 = u1*u2 */
	mul_fixptr(u1, u2, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, u3);
	/* u5 = u2*u3 */
	mul_fixptr(u2, u3, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, u5);
	/* v1 = d*yy - 1 */
	mul_fixptr(Elliptic_ed448_d, yy, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, v1);
	if (zerop_fixptr(v1, word1))
		memcpy_fixptr(v1, Elliptic_ed448_p, word1);
	subv_fixptr(v1, word1, 1, &ignore);
	/* v3 = v1*v1*v1 */
	mul_square_fixptr(v1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, v3);
	mul_fixptr(v3, v1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, v3);
	/* u3v1 = u3*v1*/
	mul_fixptr(u3, v1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, u3v1);
	/* u5v3 = u3*v1*/
	mul_fixptr(u5, v3, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, u5v3);
	/* p = (p-3)/4 */
	memcpy_fixptr(p, Elliptic_ed448_p, word1);
	subv_fixptr(p, word1, 3, &ignore);
	shiftr_fixptr(p, word1, 2);  /* div 4 */
	/* x = u3v1 * u5v3^p */
	power_mod_fixptr(s, u5v3, p, Elliptic_ed448_p, x);
	mul_fixptr(u3v1, x, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, x);
	/* v1x2 = v1*x*x */
	mul_square_fixptr(x, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, v1x2);
	mul_fixptr(v1, v1x2, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, v1x2);

	/* v1x2 == u1 */
	check = (compare_fixptr(v1x2, word1, u1, word1) != 0);
	pop1n_fixed(s, 11);
	pop2_fixed(s);

	return check;
}

int decode_ed448(fixed s, vector2_ed448 v, fixptr3 r)
{
	int x0, check;
	fixptr w2, x, y;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s);
	x = push1get_fixed(s);
	y = push1get_fixed(s);

	/* y, x0 */
	input_fixptr(y, word1, v, vector2_size_ed448, 1);
	x0 = logbitp_fixptr(y, word1, 455);
	setbit_fixptr(y, word1, 0, 455);
	/* x */
	check = decode_x_ed448(s, y, x);
	if (check)
		goto finish;
	if (x0 && zerop_fixptr(x, word1)) {
		check = 1;
		goto finish;
	}
	if ((x[0] & 0x01) != x0)
		sub_elliptic_ed448(Elliptic_ed448_p, x, x, word1);
	/* x, y -> r */
	memcpy_fixptr(r[0], x, word1);
	memcpy_fixptr(r[1], y, word1);
	setv_fixptr(r[2], word1, 1);
	/* t */
	mul_fixptr(x, y, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, r[3]);

finish:
	pop1n_fixed(s, 2);
	pop2_fixed(s);

	return check;
}

