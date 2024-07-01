#include "addition.h"
#include "fixed.h"
#include "elliptic.h"
#include "public.h"
#include "random.h"
#include "sha.h"
#include "signature.h"
#include <stdlib.h>

/*
 *  sign
 */
static void sign_sha_weierstrass(fixed s, fixptr r, const void *ptr, size_t size)
{
	uint8_t memory[BYTE_SHA256ENCODE];
	struct sha32encode sha;

	init_sha256encode(&sha);
	read_sha256encode(&sha, ptr, size);
	calc_sha256encode(&sha, memory);
	input_fixptr(r, s->word1, memory, BYTE_SHA256ENCODE, 0);
}

void sign_secp256k1(fixed s, struct fixed_random *state,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	fixptr curve_n, w2, k, x, e;
	fixptr3 b;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	curve_n = Elliptic_secp256k1_n;
	w2 = push2get_fixed(s);
	k = push1get_fixed(s);
	x = push1get_fixed(s);
	e = push1get_fixed(s);
	push3_fixed(s, b);

retry:
	/* k */
	private_secp256k1(s, state, k);
	/* b */
	public_secp256k1(s, k, b);
	/* sign_r */
	affine_secp256k1(s, b, x, e);
	rem1_elliptic_curve(s, x, sign_r, curve_n);
	/* retry sign_r*/
	if (zerop_fixptr(sign_r, word1))
		goto retry;
	/* e */
	sign_sha_weierstrass(s, e, ptr, size);
	rem1_elliptic_curve(s, e, e, curve_n);
	/* sign_s */
	mul_fixptr(sign_r, private_key, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_n);
	add_elliptic_curve(e, x, x, curve_n, word1);
	inverse_n_secp256k1(s, k, k);
	mul_fixptr(k, x, word1, w2, word2);
	rem2_elliptic_curve(s, w2, sign_s, curve_n);
	/* retry sign_s */
	if (zerop_fixptr(sign_s, word1))
		goto retry;

	pop3_fixed(s);
	pop1n_fixed(s, 3);
	pop2_fixed(s);
}

void sign_secp256r1(fixed s, struct fixed_random *state,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	fixptr curve_n, w2, k, x, e;
	fixptr3 b;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	curve_n = Elliptic_secp256r1_n;
	w2 = push2get_fixed(s);
	k = push1get_fixed(s);
	x = push1get_fixed(s);
	e = push1get_fixed(s);
	push3_fixed(s, b);

retry:
	/* k */
	private_secp256r1(s, state, k);
	/* b */
	public_secp256r1(s, k, b);
	/* sign_r */
	affine_secp256r1(s, b, x, e);
	rem1_elliptic_curve(s, x, sign_r, curve_n);
	/* retry sign_r*/
	if (zerop_fixptr(sign_r, word1))
		goto retry;
	/* e */
	sign_sha_weierstrass(s, e, ptr, size);
	rem1_elliptic_curve(s, e, e, curve_n);
	/* sign_s */
	mul_fixptr(sign_r, private_key, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_n);
	add_elliptic_curve(e, x, x, curve_n, word1);
	inverse_n_secp256r1(s, k, k);
	mul_fixptr(k, x, word1, w2, word2);
	rem2_elliptic_curve(s, w2, sign_s, curve_n);
	/* retry sign_s */
	if (zerop_fixptr(sign_s, word1))
		goto retry;

	pop3_fixed(s);
	pop1n_fixed(s, 3);
	pop2_fixed(s);
}

static void sign_sha_ed25519(fixed s, fixptr r, fixptr x, fixptr y,
		const void *ptr, size_t size)
{
	uint8_t memory[64];
	fixptr w;
	fixsize word1, word2;
	struct sha64encode sha;

	word1 = s->word1;
	word2 = s->word2;
	init_sha512encode(&sha);
	/* x */
	if (x) {
		output_fixptr(x, word1, memory, 32, 1);
		read_sha512encode(&sha, memory, 32);
	}
	/* y */
	if (y) {
		output_fixptr(y, word1, memory, 32, 1);
		read_sha512encode(&sha, memory, 32);
	}
	/* ptr */
	read_sha512encode(&sha, ptr, size);
	/* result */
	calc_sha512encode(&sha, memory);
	w = push2get_fixed(s);
	input_fixptr(w, word2, memory, 64, 1);
	rem_fixptr(s, w, Elliptic_ed25519_n, r);
	pop2_fixed(s);
}

void sign_ed25519(fixed s,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	vector2_ed25519 encode;
	fixptr *curve_g, curve_n, w2, u, v, a, w, k;
	fixptr4 z;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	curve_n = Elliptic_ed25519_n;
	curve_g = Elliptic_ed25519_g;
	w2 = push2get_fixed(s);
	u = push1get_fixed(s);
	v = push1get_fixed(s);
	a = push1get_fixed(s);
	w = push1get_fixed(s);
	k = push1get_fixed(s);
	push4_fixed(s, z);

	/* u, v */
	public_sign_ed25519(s, private_key, u, v);
	/* a */
	multiple_ed25519(s, u, curve_g, z);
	encode_ed25519(s, z, encode);
	input_fixptr(a, word1, encode, vector2_size_ed25519, 1);
	/* w */
	sign_sha_ed25519(s, w, v, NULL, ptr, size);
	/* r */
	multiple_ed25519(s, w, curve_g, z);
	encode_ed25519(s, z, encode);
	input_fixptr(sign_r, word1, encode, vector2_size_ed25519, 1);
	/* k */
	sign_sha_ed25519(s, k, sign_r, a, ptr, size);
	/* s */
	mul_fixptr(k, u, word1, w2, word2);
	rem2_elliptic_curve(s, w2, k, curve_n);
	add_elliptic_curve(w, k, sign_s, curve_n, word1);

	pop4_fixed(s);
	pop1n_fixed(s, 5);
	pop2_fixed(s);
}

static void sign_sha_ed448(fixed s, fixptr r, fixptr x, fixptr y,
		const void *ptr, size_t size)
{
	uint8_t memory[114];
	fixptr w;
	fixsize word1, word2;
	struct sha3encode sha;

	word1 = s->word1;
	word2 = s->word2;
	init_shake_256_encode(&sha);
	/* header */
	read_sha3encode(&sha, "SigEd448", 8);
	byte_sha3encode(&sha, 0x00);
	byte_sha3encode(&sha, Elliptic_ed448_sha_size);
	read_sha3encode(&sha, Elliptic_ed448_sha_context, Elliptic_ed448_sha_size);
	/* x */
	if (x) {
		output_fixptr(x, word1, memory, 57, 1);
		read_sha3encode(&sha, memory, 57);
	}
	/* y */
	if (y) {
		output_fixptr(y, word1, memory, 57, 1);
		read_sha3encode(&sha, memory, 57);
	}
	/* ptr */
	read_sha3encode(&sha, ptr, size);
	/* result */
	result_sha3encode(&sha, memory, 114);
	w = push2get_fixed(s);
	input_fixptr(w, word2, memory, 114, 1);
	rem_fixptr(s, w, Elliptic_ed448_n, r);
	pop2_fixed(s);
}

void sign_ed448(fixed s,
		fixptr private_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	vector2_ed448 encode;
	fixptr *curve_g, curve_n, w2, u, v, a, w, k;
	fixptr3 z;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	curve_g = Elliptic_ed448_g;
	curve_n = Elliptic_ed448_n;
	w2 = push2get_fixed(s);
	u = push1get_fixed(s);
	v = push1get_fixed(s);
	a = push1get_fixed(s);
	w = push1get_fixed(s);
	k = push1get_fixed(s);
	push3_fixed(s, z);

	/* u, v */
	public_sign_ed448(s, private_key, u, v);
	/* a */
	multiple_ed448(s, u, curve_g, z);
	encode_ed448(s, z, encode);
	input_fixptr(a, word1, encode, vector2_size_ed448, 1);
	/* w */
	sign_sha_ed448(s, w, v, NULL, ptr, size);
	/* r */
	multiple_ed448(s, w, curve_g, z);
	encode_ed448(s, z, encode);
	input_fixptr(sign_r, word1, encode, vector2_size_ed448, 1);
	/* k */
	sign_sha_ed448(s, k, sign_r, a, ptr, size);
	/* s */
	mul_fixptr(k, u, word1, w2, word2);
	rem2_elliptic_curve(s, w2, k, curve_n);
	add_elliptic_curve(w, k, sign_s, curve_n, word1);

	pop3_fixed(s);
	pop1n_fixed(s, 5);
	pop2_fixed(s);
}


/*
 *  verify
 */
int verify_secp256k1(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	int check;
	fixptr curve_n, w2, e, s1, u1, u2;
	fixptr3 p, q;
	fixsize word1, word2;

	/* range */
	word1 = s->word1;
	word2 = s->word2;
	curve_n = Elliptic_secp256k1_n;
	if (compare_fixnum_fixptr(sign_r, word1, 1) < 0)
		return 0;
	if (compare_fixnum_fixptr(sign_s, word1, 1) < 0)
		return 0;
	if (compare_fixptr(curve_n, word1, sign_r, word1) <= 0)
		return 0;
	if (compare_fixptr(curve_n, word1, sign_s, word1) <= 0)
		return 0;

	w2 = push2get_fixed(s);
	e = push1get_fixed(s);
	s1 = push1get_fixed(s);
	u1 = push1get_fixed(s);
	u2 = push1get_fixed(s);
	push3_fixed(s, p);
	push3_fixed(s, q);

	/* e */
	sign_sha_weierstrass(s, e, ptr, size);
	/* s1 */
	inverse_n_secp256k1(s, sign_s, s1);
	/* u1 */
	mul_fixptr(e, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u1, curve_n);
	/* u2 */
	mul_fixptr(sign_r, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u2, curve_n);
	/* p */
	multiple_secp256k1(s, u1, Elliptic_secp256k1_g, p);
	multiple_secp256k1(s, u2, public_key, q);
	addition_secp256k1(s, p, q, p);
	/* O */
	if (p[2] == 0) {
		check = 0;
		goto finish;
	}
	affine_secp256k1(s, p, u1, u2);
	rem1_elliptic_curve(s, u1, u1, curve_n);
	check = (compare_fixptr(sign_r, word1, u1, word1) == 0);

finish:
	pop3_fixed(s);
	pop3_fixed(s);
	pop1n_fixed(s, 4);
	pop2_fixed(s);

	return check;
}

int verify_secp256r1(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	int check;
	fixptr curve_n, w2, e, s1, u1, u2;
	fixptr3 p, q;
	fixsize word1, word2;

	/* range */
	word1 = s->word1;
	word2 = s->word2;
	curve_n = Elliptic_secp256r1_n;
	if (compare_fixnum_fixptr(sign_r, word1, 1) < 0)
		return 0;
	if (compare_fixnum_fixptr(sign_s, word1, 1) < 0)
		return 0;
	if (compare_fixptr(curve_n, word1, sign_r, word1) <= 0)
		return 0;
	if (compare_fixptr(curve_n, word1, sign_s, word1) <= 0)
		return 0;

	w2 = push2get_fixed(s);
	e = push1get_fixed(s);
	s1 = push1get_fixed(s);
	u1 = push1get_fixed(s);
	u2 = push1get_fixed(s);
	push3_fixed(s, p);
	push3_fixed(s, q);

	/* e */
	sign_sha_weierstrass(s, e, ptr, size);
	/* s1 */
	inverse_n_secp256r1(s, sign_s, s1);
	/* u1 */
	mul_fixptr(e, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u1, curve_n);
	/* u2 */
	mul_fixptr(sign_r, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u2, curve_n);
	/* p */
	multiple_secp256r1(s, u1, Elliptic_secp256r1_g, p);
	multiple_secp256r1(s, u2, public_key, q);
	addition_secp256r1(s, p, q, p);
	/* O */
	if (p[2] == 0) {
		check = 0;
		goto finish;
	}
	affine_secp256r1(s, p, u1, u2);
	rem1_elliptic_curve(s, u1, u1, curve_n);
	check = (compare_fixptr(sign_r, word1, u1, word1) == 0);

finish:
	pop3_fixed(s);
	pop3_fixed(s);
	pop1n_fixed(s, 4);
	pop2_fixed(s);

	return check;
}

int verify_ed25519(fixed s,
		fixptr4 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	vector2_ed25519 memory;
	int check;
	fixptr a, k;
	fixptr4 p, x, y;
	fixsize word1;

	/* sign_s */
	word1 = s->word1;
	if (compare_fixptr(Elliptic_ed25519_n, word1, sign_s, word1) <= 0)
		return 0;

	a = push1get_fixed(s);
	k = push1get_fixed(s);
	push4_fixed(s, p);
	push4_fixed(s, x);
	push4_fixed(s, y);

	/* a */
	encode_ed25519(s, public_key, memory);
	input_fixptr(a, word1, memory, vector2_size_ed25519, 1);
	/* p */
	output_fixptr(sign_r, word1, memory, 32, 1);
	if (decode_ed25519(s, memory, p)) {
		check = 0;
		goto finish;
	}
	/* k */
	sign_sha_ed25519(s, k, sign_r, a, ptr, size);
	/* x */
	multiple_ed25519(s, sign_s, Elliptic_ed25519_g, x);
	/* y */
	multiple_ed25519(s, k, public_key, y);
	addition_ed25519(s, p, y, y);
	/* result */
	check = equal_point_ed25519(s, x, y);

finish:
	pop4_fixed(s);
	pop4_fixed(s);
	pop4_fixed(s);
	pop1n_fixed(s, 2);

	return check;
}

int verify_ed448(fixed s,
		fixptr3 public_key, const void *ptr, size_t size,
		fixptr sign_r, fixptr sign_s)
{
	vector2_ed448 memory;
	int check;
	fixptr a, k;
	fixptr3 p, x, y;
	fixsize word1;

	/* sign_s */
	word1 = s->word1;
	if (compare_fixptr(Elliptic_ed448_n, word1, sign_s, word1) <= 0)
		return 0;

	a = push1get_fixed(s);
	k = push1get_fixed(s);
	push3_fixed(s, p);
	push3_fixed(s, x);
	push3_fixed(s, y);

	/* a */
	encode_ed448(s, public_key, memory);
	input_fixptr(a, word1, memory, vector2_size_ed448, 1);
	/* p */
	output_fixptr(sign_r, word1, memory, 57, 1);
	if (decode_ed448(s, memory, p)) {
		check = 0;
		goto finish;
	}
	/* k */
	sign_sha_ed448(s, k, sign_r, a, ptr, size);
	/* x */
	multiple_ed448(s, sign_s, Elliptic_ed448_g, x);
	/* y */
	multiple_ed448(s, k, public_key, y);
	addition_ed448(s, p, y, y);
	/* result */
	check = equal_point_ed448(s, x, y);

finish:
	pop3_fixed(s);
	pop3_fixed(s);
	pop3_fixed(s);
	pop1n_fixed(s, 2);

	return check;
}


/*
 *  make-string
 */
static fixed make_secp256k1_string(void)
{
	fixed s;
	s = make_secp256k1_fixed();
	if (s == NULL) {
		fprintf(stderr, "make_secp256k1_fixed error.\n");
		exit(1);
	}
	return s;
}

static fixed make_secp256r1_string(void)
{
	fixed s;
	s = make_secp256r1_fixed();
	if (s == NULL) {
		fprintf(stderr, "make_secp256r1_fixed error.\n");
		exit(1);
	}
	return s;
}

static fixed make_ed25519_string(void)
{
	fixed s;
	s = make_ed25519_fixed();
	if (s == NULL) {
		fprintf(stderr, "make_ed25519_fixed error.\n");
		exit(1);
	}
	return s;
}

static fixed make_ed448_string(void)
{
	fixed s;
	s = make_ed448_fixed();
	if (s == NULL) {
		fprintf(stderr, "make_ed448_fixed error.\n");
		exit(1);
	}
	return s;
}

static void make_fixrandom_string(struct fixed_random *ptr)
{
	if (make_fixrandom(ptr)) {
		fprintf(stderr, "make_fixrandom_string error.\n");
		exit(1);
	}
}


/*
 *  private_string
 */
void private_string_secp256k1(char *r)
{
	fixed s;
	fixptr x;
	struct fixed_random state;

	s = make_secp256k1_string();
	make_fixrandom_string(&state);
	x = push1get_fixed(s);
	private_secp256k1(s, &state, x);
	encode1_string_secp256k1(s, x, r);
	pop1_fixed(s);
	free_fixed(s);
}

void private_string_secp256r1(char *r)
{
	fixed s;
	fixptr x;
	struct fixed_random state;

	s = make_secp256r1_string();
	make_fixrandom_string(&state);
	x = push1get_fixed(s);
	private_secp256r1(s, &state, x);
	encode1_string_secp256r1(s, x, r);
	pop1_fixed(s);
	free_fixed(s);
}

void private_string_ed25519(char *r)
{
	fixed s;
	fixptr x;
	struct fixed_random state;

	s = make_ed25519_string();
	make_fixrandom_string(&state);
	x = push1get_fixed(s);
	private_ed25519(s, &state, x);
	encode1_string_ed25519(s, x, r);
	pop1_fixed(s);
	free_fixed(s);
}

void private_string_ed448(char *r)
{
	fixed s;
	fixptr x;
	struct fixed_random state;

	s = make_ed448_string();
	make_fixrandom_string(&state);
	x = push1get_fixed(s);
	private_ed448(s, &state, x);
	encode1_string_ed448(s, x, r);
	pop1_fixed(s);
	free_fixed(s);
}


/*
 *  public_string
 */
int public_string_secp256k1(const char *private_key, char *r)
{
	int check;
	fixed s;
	fixptr x;
	fixptr3 y;

	s = make_secp256k1_string();
	x = push1get_fixed(s);
	push3_fixed(s, y);
	if (decode1_string_secp256k1(s, private_key, x)) {
		check = 1;
		goto finish;
	}
	public_secp256k1(s, x, y);
	encode2_string_secp256k1(s, y, r);
	check = 0;
finish:
	pop3_fixed(s);
	pop1_fixed(s);
	free_fixed(s);
	return check;
}

int public_string_secp256r1(const char *private_key, char *r)
{
	int check;
	fixed s;
	fixptr x;
	fixptr3 y;

	s = make_secp256r1_string();
	x = push1get_fixed(s);
	push3_fixed(s, y);
	if (decode1_string_secp256r1(s, private_key, x)) {
		check = 1;
		goto finish;
	}
	public_secp256r1(s, x, y);
	encode2_string_secp256r1(s, y, r);
	check = 0;
finish:
	pop3_fixed(s);
	pop1_fixed(s);
	free_fixed(s);
	return check;
}

int public_string_ed25519(const char *private_key, char *r)
{
	int check;
	fixed s;
	fixptr x;
	fixptr4 y;

	s = make_ed25519_string();
	x = push1get_fixed(s);
	push4_fixed(s, y);
	if (decode1_string_ed25519(s, private_key, x)) {
		check = 1;
		goto finish;
	}
	public_ed25519(s, x, y);
	encode2_string_ed25519(s, y, r);
	check = 0;
finish:
	pop4_fixed(s);
	pop1_fixed(s);
	free_fixed(s);
	return check;
}

int public_string_ed448(const char *private_key, char *r)
{
	int check;
	fixed s;
	fixptr x;
	fixptr3 y;

	s = make_ed448_string();
	x = push1get_fixed(s);
	push3_fixed(s, y);
	if (decode1_string_ed448(s, private_key, x)) {
		check = 1;
		goto finish;
	}
	public_ed448(s, x, y);
	encode2_string_ed448(s, y, r);
	check = 0;
finish:
	pop3_fixed(s);
	pop1_fixed(s);
	free_fixed(s);
	return check;
}

/*
 *  sign_string
 */
int sign_string_secp256k1(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s)
{
	int check;
	fixed s;
	fixptr p1, r1, s1;
	struct fixed_random state;

	s = make_secp256k1_string();
	make_fixrandom_string(&state);
	p1 = push1get_fixed(s);
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	if (decode1_string_secp256k1(s, private_key, p1)) {
		check = 1;
		goto finish;
	}
	sign_secp256k1(s, &state, p1, ptr, size, r1, s1);
	encode1_string_secp256k1(s, r1, sign_r);
	encode1_string_secp256k1(s, s1, sign_s);
	check = 0;

finish:
	pop1n_fixed(s, 3);
	free_fixed(s);
	return check;
}

int sign_string_secp256r1(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s)
{
	int check;
	fixed s;
	fixptr p1, r1, s1;
	struct fixed_random state;

	s = make_secp256r1_string();
	make_fixrandom_string(&state);
	p1 = push1get_fixed(s);
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	if (decode1_string_secp256r1(s, private_key, p1)) {
		check = 1;
		goto finish;
	}
	sign_secp256r1(s, &state, p1, ptr, size, r1, s1);
	encode1_string_secp256r1(s, r1, sign_r);
	encode1_string_secp256r1(s, s1, sign_s);
	check = 0;

finish:
	pop1n_fixed(s, 3);
	free_fixed(s);
	return check;
}

int sign_string_ed25519(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s)
{
	int check;
	fixed s;
	fixptr p1, r1, s1;

	s = make_ed25519_string();
	p1 = push1get_fixed(s);
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	if (decode1_string_ed25519(s, private_key, p1)) {
		check = 1;
		goto finish;
	}
	sign_ed25519(s, p1, ptr, size, r1, s1);
	encode1_string_ed25519(s, r1, sign_r);
	encode1_string_ed25519(s, s1, sign_s);
	check = 0;

finish:
	pop1n_fixed(s, 3);
	free_fixed(s);
	return check;
}

int sign_string_ed448(const char *private_key, const void *ptr, size_t size,
		char *sign_r, char *sign_s)
{
	int check;
	fixed s;
	fixptr p1, r1, s1;

	s = make_ed448_string();
	p1 = push1get_fixed(s);
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	if (decode1_string_ed448(s, private_key, p1)) {
		check = 1;
		goto finish;
	}
	sign_ed448(s, p1, ptr, size, r1, s1);
	encode1_string_ed448(s, r1, sign_r);
	encode1_string_ed448(s, s1, sign_s);
	check = 0;

finish:
	pop1n_fixed(s, 3);
	free_fixed(s);
	return check;
}


/*
 *  verify_string
 */
int verify_string_secp256k1(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s)
{
	int check;
	fixed s;
	fixptr3 p3;
	fixptr r1, s1;

	/* push */
	s = make_secp256k1_string();
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* decode */
	check = 0;
	if (decode2_string_secp256k1(s, public_key, p3))
		goto finish;
	if (decode1_string_secp256k1(s, sign_r, r1))
		goto finish;
	if (decode1_string_secp256k1(s, sign_s, s1))
		goto finish;

	/* verify */
	check = verify_secp256k1(s, p3, ptr, size, r1, s1);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 2);
	free_fixed(s);
	return check;
}

int verify_string_secp256r1(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s)
{
	int check;
	fixed s;
	fixptr3 p3;
	fixptr r1, s1;

	/* push */
	s = make_secp256r1_string();
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* decode */
	check = 0;
	if (decode2_string_secp256r1(s, public_key, p3))
		goto finish;
	if (decode1_string_secp256r1(s, sign_r, r1))
		goto finish;
	if (decode1_string_secp256r1(s, sign_s, s1))
		goto finish;

	/* verify */
	check = verify_secp256r1(s, p3, ptr, size, r1, s1);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 2);
	free_fixed(s);
	return check;
}

int verify_string_ed25519(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s)
{
	int check;
	fixed s;
	fixptr4 p4;
	fixptr r1, s1;

	/* push */
	s = make_ed25519_string();
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push4_fixed(s, p4);

	/* decode */
	check = 0;
	if (decode2_string_ed25519(s, public_key, p4))
		goto finish;
	if (decode1_string_ed25519(s, sign_r, r1))
		goto finish;
	if (decode1_string_ed25519(s, sign_s, s1))
		goto finish;

	/* verify */
	check = verify_ed25519(s, p4, ptr, size, r1, s1);

finish:
	pop4_fixed(s);
	pop1n_fixed(s, 2);
	free_fixed(s);
	return check;
}

int verify_string_ed448(const char *public_key, const void *ptr, size_t size,
		const char *sign_r, const char *sign_s)
{
	int check;
	fixed s;
	fixptr3 p3;
	fixptr r1, s1;

	/* push */
	s = make_ed448_string();
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* decode */
	check = 0;
	if (decode2_string_ed448(s, public_key, p3))
		goto finish;
	if (decode1_string_ed448(s, sign_r, r1))
		goto finish;
	if (decode1_string_ed448(s, sign_s, s1))
		goto finish;

	/* verify */
	check = verify_ed448(s, p3, ptr, size, r1, s1);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 2);
	free_fixed(s);
	return check;
}


/*
 *  others
 */
#include <stdio.h>

void genkey_elliptic(void)
{
	static const char message[] = "Hello";
	static const size_t size = 5;
	string1_secp256k1 private1;
	string1_secp256r1 private2;
	string1_ed25519 private3;
	string1_ed448 private4;
	string2_secp256k1 public1;
	string2_secp256r1 public2;
	string2_ed25519 public3;
	string2_ed448 public4;
	string1_secp256k1 sign_r1;
	string1_secp256r1 sign_r2;
	string1_ed25519 sign_r3;
	string1_ed448 sign_r4;
	string1_secp256k1 sign_s1;
	string1_secp256r1 sign_s2;
	string1_ed25519 sign_s3;
	string1_ed448 sign_s4;
	int verify1, verify2, verify3, verify4;

	init_fixrandom();
	init_elliptic();
	private_string_secp256k1(private1);
	private_string_secp256r1(private2);
	private_string_ed25519(private3);
	private_string_ed448(private4);
	public_string_secp256k1(private1, public1);
	public_string_secp256r1(private2, public2);
	public_string_ed25519(private3, public3);
	public_string_ed448(private4, public4);
	sign_string_secp256k1(private1, message, size, sign_r1, sign_s1);
	sign_string_secp256r1(private2, message, size, sign_r2, sign_s2);
	sign_string_ed25519(private3, message, size, sign_r3, sign_s3);
	sign_string_ed448(private4, message, size, sign_r4, sign_s4);
	verify1 = verify_string_secp256k1(public1, message, size, sign_r1, sign_s1);
	verify2 = verify_string_secp256r1(public2, message, size, sign_r2, sign_s2);
	verify3 = verify_string_ed25519(public3, message, size, sign_r3, sign_s3);
	verify4 = verify_string_ed448(public4, message, size, sign_r4, sign_s4);

	printf("[private]\n");
	printf("secp256k1: \"%s\"\n", private1);
	printf("secp256r1: \"%s\"\n", private2);
	printf("ed25519  : \"%s\"\n", private3);
	printf("ed448    : \"%s\"\n", private4);
	printf("\n[public]\n");
	printf("secp256k1: \"%s\"\n", public1);
	printf("secp256r1: \"%s\"\n", public2);
	printf("ed25519  : \"%s\"\n", public3);
	printf("ed448    : \"%s\"\n", public4);
	printf("\n[sign] \"%s\"\n", message);
	printf("secp256k1.r: \"%s\"\n", sign_r1);
	printf("secp256k1.s: \"%s\"\n", sign_s1);
	printf("secp256r1.r: \"%s\"\n", sign_r2);
	printf("secp256r1.s: \"%s\"\n", sign_s2);
	printf("ed25519.r  : \"%s\"\n", sign_r3);
	printf("ed25519.s  : \"%s\"\n", sign_s3);
	printf("ed448.r    : \"%s\"\n", sign_r4);
	printf("ed448.s    : \"%s\"\n", sign_s4);
	printf("\n[verify]\n");
	printf("secp256k1: %s\n", verify1? "T": "NIL");
	printf("secp256r1: %s\n", verify2? "T": "NIL");
	printf("ed25519  : %s\n", verify3? "T": "NIL");
	printf("ed448    : %s\n", verify4? "T": "NIL");
}

int main_verify_elliptic(void)
{
	int verify;

	/* secp256k1 */
	verify = verify_string_secp256k1(
			"03FEEF09658067CFBE3BE8685DDCE8E9C03B4A397ADC4A0255CE0B29FC63BCDC9C",
			"Hello", 5,
			"7C7EDD22B0AED24D1B4A3826E228CE52EC897D52826D5912459238FC36008B86",
			"38C86C613A977CD5D1E024380FB56CDB924B0D972E903AB740F4E7F3A90F62BC");
	printf("secp256k1.verify = %d\n", verify);

	/* secp256r1 */
	verify = verify_string_secp256r1(
			"03CD92CF7B1C9CE9858383806B8540D72FB022BE577E21DE02B8EAA27371DB7AF2",
			"Hello", 5,
			"FF6331919D62BFF9236113998250AB9079AA81C83085A27CC38A2CC0EEDDD98D",
			"1A374ADE37A61F6014C29C723C425BB3E6B519D517E16F66A46869F8EC535F89");
	printf("secp256r1.verify = %d\n", verify);

	/* ed25519 */
	verify = verify_string_ed25519(
			"75AB16F53A060E7AF9A4B8ECEA3D4DEF058AED2C626FEC96D5505C4A7D922960",
			"Hello", 5,
			"285D61D0DAC982F09365DA699DFD10A7B1B3A4D29A8468655A71F49965D4CEE1",
			"A58118E7ECAE263034F4BA7EB57BEE8D639C9BAF5BDE6BE97F2F864B3A1A7606");
	printf("ed25519.verify = %d\n", verify);

	/* ed448 */
	verify = verify_string_ed448(
			"99AFC3768EE41B96F208EBAF8627908690DC6A5AC64659F93D0A46C20"
			"92B61E84AD14DD03F7B3F146799C29F65682126D517B7E1EA57716E00",
			"Hello", 5,
			"DC38653AAD2F456132602EBC47571DABB56C36BA35D6965F820AFFB0F"
			"BE478439C7CF1D9EE7033792A23E80811CFAB07DC2B71DDEF526F6700",
			"0E11296ECFACEA4E5E9B795AC4048D711636BE468A99639F953ED1E94"
			"8A6351F51DE0AE167EB268012E9712F7D6ADD97E80BB36E291C2A2D00");
	printf("ed448.verify = %d\n", verify);

	return 0;
}

