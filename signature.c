#include "addition.h"
#include "fixed.h"
#include "elliptic.h"
#include "public.h"
#include "random.h"
#include "sha.h"
#include "signature.h"

/*
 *  sign
 */
static void sign_weierstrass(fixed s,
		struct fixed_random *state,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size,
		void (*make_public)(fixed, fixptr, fixptr3),
		fixptr curve_p,
		fixptr curve_n)
{
}

void sign_secp256k1(fixed s, struct fixed_random *state,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	sign_weierstrass(s, state, private_key, sign_r, sign_s, ptr, size,
			public_secp256k1,
			Elliptic_secp256k1_p,
			Elliptic_secp256k1_n);
}

void sign_secp256r1(fixed s, struct fixed_random *state,
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	sign_weierstrass(s, state, private_key, sign_r, sign_s, ptr, size,
			public_secp256r1,
			Elliptic_secp256r1_p,
			Elliptic_secp256r1_n);
}

static void sign_sha_ed25519(fixed s, fixptr r, fixptr x, fixptr y,
		const void *ptr, size_t size)
{
	uint32_t memory[64];
	fixptr w;
	fixsize word1, word2;
	struct sha64encode sha;

	word1 = s->word1;
	word2 = s->word2;
	init_sha512encode(&sha);
	/* x */
	output_fixptr(x, word1, memory, 32, 1);
	read_sha512encode(&sha, memory, 32);
	/* y */
	output_fixptr(y, word1, memory, 32, 1);
	read_sha512encode(&sha, memory, 32);
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
		fixptr private_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	vector2_ed25519 encode;
	fixptr w2, u, v, a, w, k;
	fixptr4 z;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
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
	multiple_ed25519(s, u, Elliptic_ed25519_g, z);
	encode_ed25519(s, z, encode);
	input_fixptr(a, word1, encode, vector2_size_ed25519, 1);
	/* w */
	sign_sha_ed25519(s, w, v, NULL, ptr, size);
	/* r */
	multiple_ed25519(s, w, Elliptic_ed25519_g, z);
	encode_ed25519(s, z, encode);
	input_fixptr(sign_r, word1, encode, vector2_size_ed25519, 1);
	/* k */
	sign_sha_ed25519(s, k, sign_r, a, ptr, size);
	/* s */
	mul_fixptr(k, u, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, k);
	add_elliptic_ed25519(w, k, sign_s, word1);

	pop3_fixed(s);
	pop1n_fixed(s, 5);
	pop2_fixed(s);
}


/*
 *  verify
 */
int verify_secp256k1(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	return 0;
}

int verify_secp256r1(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	return 0;
}

int verify_ed25519(fixed s, fixptr4 public_key,
		fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	return 0;
}

int verify_ed448(fixed s,
		fixptr3 public_key, fixptr sign_r, fixptr sign_s,
		const void *ptr, size_t size)
{
	return 0;
}


/*
 *  verify_string
 */
int verify_string_secp256k1(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size)
{
	int check;
	fixptr3 p3;
	fixptr r1, s1;
	vector2_secp256k1 v1;
	vector1_secp256k1 v2;
	vector1_secp256k1 v3;

	/* parse */
	if (string_integer_elliptic(public_key, v1, vector2_size_secp256k1, 0))
		return 0;
	if (string_integer_elliptic(sign_r, v2, vector1_size_secp256k1, 0))
		return 0;
	if (string_integer_elliptic(sign_s, v3, vector1_size_secp256k1, 0))
		return 0;

	/* push */
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* verify */
	if (decode_secp256k1(s, v1, p3)) {
		check = 0;
		goto finish;
	}
	input_fixptr(s1, s->word1, v2, vector1_size_secp256k1, 0);
	input_fixptr(r1, s->word1, v3, vector1_size_secp256k1, 0);
	check = verify_secp256k1(s, p3, r1, s1, ptr, size);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 3);
	return check;
}

int verify_string_secp256r1(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size)
{
	int check;
	fixptr3 p3;
	fixptr r1, s1;
	vector2_secp256r1 v1;
	vector1_secp256r1 v2;
	vector1_secp256r1 v3;

	/* parse */
	if (string_integer_elliptic(public_key, v1, vector2_size_secp256r1, 0))
		return 0;
	if (string_integer_elliptic(sign_r, v2, vector1_size_secp256r1, 0))
		return 0;
	if (string_integer_elliptic(sign_s, v3, vector1_size_secp256r1, 0))
		return 0;

	/* push */
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* verify */
	if (decode_secp256r1(s, v1, p3)) {
		check = 0;
		goto finish;
	}
	input_fixptr(s1, s->word1, v2, vector1_size_secp256r1, 0);
	input_fixptr(r1, s->word1, v3, vector1_size_secp256r1, 0);
	check = verify_secp256r1(s, p3, r1, s1, ptr, size);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 3);
	return check;
}

int verify_string_ed25519(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size)
{
	int check;
	fixptr4 p4;
	fixptr r1, s1;
	vector2_ed25519 v1;
	vector1_ed25519 v2;
	vector1_ed25519 v3;

	/* parse */
	if (string_integer_elliptic(public_key, v1, vector2_size_ed25519, 0))
		return 0;
	if (string_integer_elliptic(sign_r, v2, vector1_size_ed25519, 0))
		return 0;
	if (string_integer_elliptic(sign_s, v3, vector1_size_ed25519, 0))
		return 0;

	/* push */
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push4_fixed(s, p4);

	/* verify */
	if (decode_ed25519(s, v1, p4)) {
		check = 0;
		goto finish;
	}
	input_fixptr(s1, s->word1, v2, vector1_size_ed25519, 0);
	input_fixptr(r1, s->word1, v3, vector1_size_ed25519, 0);
	check = verify_ed25519(s, p4, r1, s1, ptr, size);

finish:
	pop4_fixed(s);
	pop1n_fixed(s, 3);
	return check;
}

int verify_string_ed448(fixed s,
		const char *public_key, const char *sign_r, const char *sign_s,
		const void *ptr, size_t size)
{
	int check;
	fixptr3 p3;
	fixptr r1, s1;
	vector2_ed448 v1;
	vector1_ed448 v2;
	vector1_ed448 v3;

	/* parse */
	if (string_integer_elliptic(public_key, v1, vector2_size_ed448, 0))
		return 0;
	if (string_integer_elliptic(sign_r, v2, vector1_size_ed448, 0))
		return 0;
	if (string_integer_elliptic(sign_s, v3, vector1_size_ed448, 0))
		return 0;

	/* push */
	r1 = push1get_fixed(s);
	s1 = push1get_fixed(s);
	push3_fixed(s, p3);

	/* verify */
	if (decode_ed448(s, v1, p3)) {
		check = 0;
		goto finish;
	}
	input_fixptr(s1, s->word1, v2, vector1_size_ed448, 0);
	input_fixptr(r1, s->word1, v3, vector1_size_ed448, 0);
	check = verify_ed448(s, p3, r1, s1, ptr, size);

finish:
	pop3_fixed(s);
	pop1n_fixed(s, 3);
	return check;
}


/*
 *  others
 */
#include <stdio.h>

void genkey_elliptic(void)
{
}

int main_verify_elliptic(void)
{
	int verify;
	fixed s;

	/* secp256k1 */
	s = make_secp256k1_fixed();
	verify = verify_string_secp256k1(s,
			"03FEEF09658067CFBE3BE8685DDCE8E9C03B4A397ADC4A0255CE0B29FC63BCDC9C",
			"7C7EDD22B0AED24D1B4A3826E228CE52EC897D52826D5912459238FC36008B86",
			"38C86C613A977CD5D1E024380FB56CDB924B0D972E903AB740F4E7F3A90F62BC",
			"Hello", 5);
	printf("secp256k1.verify = %d\n", verify);
	free_fixed(s);

	/* secp256r1 */
	s = make_secp256r1_fixed();
	verify = verify_string_secp256r1(s,
			"03CD92CF7B1C9CE9858383806B8540D72FB022BE577E21DE02B8EAA27371DB7AF2",
			"FF6331919D62BFF9236113998250AB9079AA81C83085A27CC38A2CC0EEDDD98D",
			"1A374ADE37A61F6014C29C723C425BB3E6B519D517E16F66A46869F8EC535F89",
			"Hello", 5);
	printf("secp256r1.verify = %d\n", verify);
	free_fixed(s);

	/* ed25519 */
	s = make_ed25519_fixed();
	verify = verify_string_ed25519(s,
			"75AB16F53A060E7AF9A4B8ECEA3D4DEF058AED2C626FEC96D5505C4A7D922960",
			"285D61D0DAC982F09365DA699DFD10A7B1B3A4D29A8468655A71F49965D4CEE1",
			"A58118E7ECAE263034F4BA7EB57BEE8D639C9BAF5BDE6BE97F2F864B3A1A7606",
			"Hello", 5);
	printf("ed25519.verify = %d\n", verify);
	free_fixed(s);

	/* ed448 */
	s = make_ed448_fixed();
	verify = verify_string_ed448(s,
			"99AFC3768EE41B96F208EBAF8627908690DC6A5AC64659F93D0A46C20"
			"92B61E84AD14DD03F7B3F146799C29F65682126D517B7E1EA57716E00",
			"DC38653AAD2F456132602EBC47571DABB56C36BA35D6965F820AFFB0F"
			"BE478439C7CF1D9EE7033792A23E80811CFAB07DC2B71DDEF526F6700",
			"0E11296ECFACEA4E5E9B795AC4048D711636BE468A99639F953ED1E94"
			"8A6351F51DE0AE167EB268012E9712F7D6ADD97E80BB36E291C2A2D00",
			"Hello", 5);
	printf("ed25519.verify = %d\n", verify);
	free_fixed(s);

	return 0;
}

