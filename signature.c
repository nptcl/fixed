#include "addition.h"
#include "crypt.h"
#include "elliptic.h"
#include "fixed.h"
#include "random.h"
#include "sha.h"
#include "signature.h"

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
	return equal_point_elliptic(s, p, q, (fixptr)Elliptic_secp256k1_p);
}

int equal_point_secp256r1(fixed s, fixptr3 p, fixptr3 q)
{
	return equal_point_elliptic(s, p, q, (fixptr)Elliptic_secp256r1_p);
}

int equal_point_ed25519(fixed s, fixptr4 p, fixptr4 q)
{
	return equal_point_elliptic(s, p, q, (fixptr)Elliptic_ed25519_p);
}

int equal_point_ed448(fixed s, fixptr3 p, fixptr3 q)
{
	return equal_point_elliptic(s, p, q, (fixptr)Elliptic_ed448_p);
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
void private_secp256k1(fixed s, struct fixed_random *state, fixptr r)
{
	do {
		random_less_fixptr(state, Elliptic_secp256k1_n, r, s->word1);
	} while (zerop_fixptr(r, s->word1));
}

void private_secp256r1(fixed s, struct fixed_random *state, fixptr r)
{
	do {
		random_less_fixptr(state, Elliptic_secp256r1_n, r, s->word1);
	} while (zerop_fixptr(r, s->word1));
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

static void public_sign_ed25519(fixed s, fixptr private_key, fixptr4 r, fixptr sign)
{
	uint8_t x[BYTE_SHA512ENCODE];
	struct sha64encode sha;
	fixptr a;
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
	a = push1get_fixed(s);
	input_fixptr(a, word1, x, elliptic_ed25519_byte, 1);
	multiple_ed25519(s, a, Elliptic_ed25519_g, r);
	pop1_fixed(s);

	/* sign */
	if (sign)
		input_fixptr(sign, word1, x + 32, elliptic_ed25519_byte, 1);
}

void public_ed25519(fixed s, fixptr private_key, fixptr4 r)
{
	public_sign_ed25519(s, private_key, r, NULL);
}

static void public_sign_ed448(fixed s, fixptr private_key, fixptr3 r, fixptr sign)
{
	/*
	 *  ed448 -> 57byte
	 *  fixed -> 64byte
	 */
	uint8_t x[57*2];
	struct sha3encode sha;
	fixptr a;
	fixsize word1;

	/* Hash SHAKE-256 */
	word1 = s->word1;
	output_fixptr(private_key, word1, x, 57, 1);
	init_shake_256_encode(&sha);
	read_sha3encode(&sha, x, 57);
	result_sha3encode(&sha, x, 57*2);

	/* a */
	x[0] &= 0xFC;
	x[57 - 1] = 0;
	x[57 - 2] |= 0x80;

	/* r */
	a = push1get_fixed(s);
	input_fixptr(a, word1, x, 57, 1);
	multiple_ed448(s, a, Elliptic_ed448_g, r);
	pop1_fixed(s);

	/* sign */
	if (sign)
		input_fixptr(sign, word1, x + 57, 57, 1);
}

void public_ed448(fixed s, fixptr private_key, fixptr3 r)
{
	public_sign_ed448(s, private_key, r, NULL);
}


/*
 *  encode
 */
int encode_secp256k1(fixed s, fixptr3 v, vector2_secp256k1 r, int compress);
int encode_secp256r1(fixed s, fixptr3 v, vector2_secp256r1 r, int compress);

int encode_ed25519(fixed s, fixptr4 v, vector2_ed25519 r)
{
	fixptr x, y;
	fixsize word1;

	word1 = s->word1;
	x = push1get_fixed(s);
	y = push1get_fixed(s);

	/* encode */
	affine_ed25519(s, v, x, y);
	if (x[0] & 0x01)
		setbit_fixptr(y, word1, 1, 255);
	output_fixptr(x, word1, r, vector2_size_ed25519, 1);

	/* pop */
	pop2_fixed(s);
	pop1n_fixed(s, 3);

	return vector2_size_ed25519;
}

int encode_ed448(fixed s, fixptr3 v, vector2_ed448 r)
{
	fixptr x, y;
	fixsize word1;

	word1 = s->word1;
	x = push1get_fixed(s);
	y = push1get_fixed(s);

	/* encode */
	affine_ed448(s, v, x, y);
	if (x[0] & 0x01)
		setbit_fixptr(y, word1, 1, 455);
	output_fixptr(x, word1, r, vector2_size_ed448, 1);

	/* pop */
	pop2_fixed(s);
	pop1n_fixed(s, 3);

	return vector2_size_ed448;
}


/*
 *  decode
 */
void decode_secp256k1(fixed s, vector2_secp256k1 v, fixptr3 r);
void decode_secp256r1(fixed s, vector2_secp256r1 v, fixptr3 r);
void decode_ed25519(fixed s, vector2_ed25519 v, fixptr4 r);
void decode_ed448(fixed s, vector2_ed448 v, fixptr3 r);

