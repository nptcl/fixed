#include "addition.h"
#include "crypt.h"
#include "elliptic.h"
#include "public.h"
#include "random.h"
#include "signature.h"
#include "test.h"

static struct fixed_random random_state;

/*
 *  valid
 */
static int test_valid(void)
{
	fixed s;
	fixsize root;

	s = make_secp256k1_fixed();
	root = s->index;
	test(! valid_secp256k1(s, Elliptic_secp256k1_o), "valid.1");
	test(root == s->index, "valid.2");
	test(valid_secp256k1(s, Elliptic_secp256k1_g), "valid.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	root = s->index;
	test(! valid_secp256r1(s, Elliptic_secp256r1_o), "valid.4");
	test(root == s->index, "valid.5");
	test(valid_secp256r1(s, Elliptic_secp256r1_g), "valid.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	root = s->index;
	test(valid_ed25519(s, Elliptic_ed25519_o), "valid.7");
	test(root == s->index, "valid.8");
	test(valid_ed25519(s, Elliptic_ed25519_g), "valid.9");
	free_fixed(s);

	s = make_ed448_fixed();
	root = s->index;
	test(valid_ed448(s, Elliptic_ed448_o), "valid.10");
	test(root == s->index, "valid.11");
	test(valid_ed448(s, Elliptic_ed448_g), "valid.12");
	free_fixed(s);

	Return;
}


/*
 *  neutral
 */
static int test_neutral(void)
{
	fixed s;
	fixsize root;

	s = make_secp256k1_fixed();
	root = s->index;
	test(neutral_secp256k1(s, Elliptic_secp256k1_o), "neutral.1");
	test(root == s->index, "neutral.2");
	test(! neutral_secp256k1(s, Elliptic_secp256k1_g), "neutral.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	root = s->index;
	test(neutral_secp256r1(s, Elliptic_secp256r1_o), "neutral.4");
	test(root == s->index, "neutral.5");
	test(! neutral_secp256r1(s, Elliptic_secp256r1_g), "neutral.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	root = s->index;
	test(neutral_ed25519(s, Elliptic_ed25519_o), "neutral.7");
	test(root == s->index, "neutral.8");
	test(! neutral_ed25519(s, Elliptic_ed25519_g), "neutral.9");
	free_fixed(s);

	s = make_ed448_fixed();
	root = s->index;
	test(neutral_ed448(s, Elliptic_ed448_o), "neutral.10");
	test(root == s->index, "neutral.11");
	test(! neutral_ed448(s, Elliptic_ed448_g), "neutral.12");
	free_fixed(s);

	Return;
}


/*
 *  inverse
 */
static int test_inverse(void)
{
	fixed s;
	fixptr x, y, z;
	fixsize root;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);
	random_less_fixptr(&random_state, Elliptic_secp256k1_p, x, s->word1);
	root = s->index;
	inverse_secp256k1(s, x, y);
	test(root == s->index, "inverse.1");
	inverse_secp256k1(s, y, z);
	test(compare_fixptr(x, s->word1, z, s->word1) == 0, "inverse.2");
	pop1n_fixed(s, 3);
	free_fixed(s);

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);
	random_less_fixptr(&random_state, Elliptic_secp256r1_p, x, s->word1);
	root = s->index;
	inverse_secp256r1(s, x, y);
	test(root == s->index, "inverse.3");
	inverse_secp256r1(s, y, z);
	test(compare_fixptr(x, s->word1, z, s->word1) == 0, "inverse.4");
	pop1n_fixed(s, 3);
	free_fixed(s);

	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);
	random_less_fixptr(&random_state, Elliptic_ed25519_p, x, s->word1);
	root = s->index;
	inverse_ed25519(s, x, y);
	test(root == s->index, "inverse.5");
	inverse_ed25519(s, y, z);
	test(compare_fixptr(x, s->word1, z, s->word1) == 0, "inverse.6");
	pop1n_fixed(s, 3);
	free_fixed(s);

	s = make_ed448_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	z = push1get_fixed(s);
	random_less_fixptr(&random_state, Elliptic_ed448_p, x, s->word1);
	root = s->index;
	inverse_ed448(s, x, y);
	test(root == s->index, "inverse.7");
	inverse_ed448(s, y, z);
	test(compare_fixptr(x, s->word1, z, s->word1) == 0, "inverse.8");
	pop1n_fixed(s, 3);
	free_fixed(s);

	Return;
}


/*
 *  addition
 */
static int test_addition_O_G(void)
{
	fixed s;
	fixptr *g, *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	g = Elliptic_secp256k1_g;
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256k1(s, o, g, r3);
	test(equal_point_secp256k1(s, g, r3), "addition_O_G.1");
	test(root == s->index, "addition_O_G.2");
	test(valid_secp256k1(s, r3), "addition_O_G.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	g = Elliptic_secp256r1_g;
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256r1(s, o, g, r3);
	test(equal_point_secp256r1(s, g, r3), "addition_O_G.4");
	test(root == s->index, "addition_O_G.5");
	test(valid_secp256r1(s, r3), "addition_O_G.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	g = Elliptic_ed25519_g;
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	addition_ed25519(s, o, g, r4);
	test(equal_point_ed25519(s, g, r4), "addition_O_G.7");
	test(root == s->index, "addition_O_G.8");
	test(valid_ed25519(s, r4), "addition_O_G.9");
	free_fixed(s);

	s = make_ed448_fixed();
	g = Elliptic_ed448_g;
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_ed448(s, o, g, r3);
	test(equal_point_ed448(s, g, r3), "addition_O_G.10");
	test(root == s->index, "addition_O_G.11");
	test(valid_ed448(s, r3), "addition_O_G.12");
	free_fixed(s);

	Return;
}

static int test_addition_G_O(void)
{
	fixed s;
	fixptr *g, *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	g = Elliptic_secp256k1_g;
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256k1(s, g, o, r3);
	test(equal_point_secp256k1(s, g, r3), "addition_G_O.1");
	test(root == s->index, "addition_G_O.2");
	test(valid_secp256k1(s, r3), "addition_G_O.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	g = Elliptic_secp256r1_g;
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256r1(s, g, o, r3);
	test(equal_point_secp256r1(s, g, r3), "addition_G_O.4");
	test(root == s->index, "addition_G_O.5");
	test(valid_secp256r1(s, r3), "addition_G_O.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	g = Elliptic_ed25519_g;
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	addition_ed25519(s, g, o, r4);
	test(equal_point_ed25519(s, g, r4), "addition_G_O.7");
	test(root == s->index, "addition_G_O.8");
	test(valid_ed25519(s, r4), "addition_G_O.9");
	free_fixed(s);

	s = make_ed448_fixed();
	g = Elliptic_ed448_g;
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_ed448(s, g, o, r3);
	test(equal_point_ed448(s, g, r3), "addition_G_O.10");
	test(root == s->index, "addition_G_O.11");
	test(valid_ed448(s, r3), "addition_G_O.12");
	free_fixed(s);

	Return;
}

static int test_addition_O_O(void)
{
	fixed s;
	fixptr *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256k1(s, o, o, r3);
	test(equal_point_secp256k1(s, o, r3), "addition_O_O.1");
	test(root == s->index, "addition_O_O.2");
	test(neutral_secp256k1(s, o), "addition_O_O.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_secp256r1(s, o, o, r3);
	test(equal_point_secp256r1(s, o, r3), "addition_O_O.4");
	test(root == s->index, "addition_O_O.5");
	test(neutral_secp256r1(s, o), "addition_O_O.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	addition_ed25519(s, o, o, r4);
	test(equal_point_ed25519(s, o, r4), "addition_O_O.7");
	test(root == s->index, "addition_O_O.8");
	test(neutral_ed25519(s, o), "addition_O_O.9");
	free_fixed(s);

	s = make_ed448_fixed();
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	addition_ed448(s, o, o, r3);
	test(equal_point_ed448(s, o, r3), "addition_O_O.10");
	test(root == s->index, "addition_O_O.11");
	test(neutral_ed448(s, o), "addition_O_O.12");
	free_fixed(s);

	Return;
}

static int test_doubling_O(void)
{
	fixed s;
	fixptr *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256k1(s, o, r3);
	test(equal_point_secp256k1(s, o, r3), "doubling_O.1");
	test(root == s->index, "doubling_O.2");
	test(neutral_secp256k1(s, o), "doubling_O.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256r1(s, o, r3);
	test(equal_point_secp256r1(s, o, r3), "doubling_O.4");
	test(root == s->index, "doubling_O.5");
	test(neutral_secp256r1(s, o), "doubling_O.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	doubling_ed25519(s, o, r4);
	test(equal_point_ed25519(s, o, r4), "doubling_O.7");
	test(root == s->index, "doubling_O.8");
	test(neutral_ed25519(s, o), "doubling_O.9");
	free_fixed(s);

	s = make_ed448_fixed();
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_ed448(s, o, r3);
	test(equal_point_ed448(s, o, r3), "doubling_O.10");
	test(root == s->index, "doubling_O.11");
	test(neutral_ed448(s, o), "doubling_O.12");
	free_fixed(s);

	Return;
}

static int test_doubling_O_G(void)
{
	fixed s;
	fixptr *g, *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	g = Elliptic_secp256k1_g;
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256k1(s, o, r3);
	addition_secp256k1(s, r3, g, r3);
	test(equal_point_secp256k1(s, g, r3), "doubling_O_G.1");
	test(root == s->index, "doubling_O_G.2");
	test(valid_secp256k1(s, r3), "doubling_O_G.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	g = Elliptic_secp256r1_g;
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256r1(s, o, r3);
	addition_secp256r1(s, r3, g, r3);
	test(equal_point_secp256r1(s, g, r3), "doubling_O_G.4");
	test(root == s->index, "doubling_O_G.5");
	test(valid_secp256r1(s, r3), "doubling_O_G.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	g = Elliptic_ed25519_g;
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	doubling_ed25519(s, o, r4);
	addition_ed25519(s, r4, g, r4);
	test(equal_point_ed25519(s, g, r4), "doubling_O_G.7");
	test(root == s->index, "doubling_O_G.8");
	test(valid_ed25519(s, r4), "doubling_O_G.9");
	free_fixed(s);

	s = make_ed448_fixed();
	g = Elliptic_ed448_g;
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_ed448(s, o, r3);
	addition_ed448(s, r3, g, r3);
	test(equal_point_ed448(s, g, r3), "doubling_O_G.10");
	test(root == s->index, "doubling_O_G.11");
	test(valid_ed448(s, r3), "doubling_O_G.12");
	free_fixed(s);

	Return;
}

static int test_doubling_G_O(void)
{
	fixed s;
	fixptr *g, *o;
	fixptr3 r3;
	fixptr4 r4;
	fixsize root;

	s = make_secp256k1_fixed();
	g = Elliptic_secp256k1_g;
	o = Elliptic_secp256k1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256k1(s, o, r3);
	addition_secp256k1(s, g, r3, r3);
	test(equal_point_secp256k1(s, g, r3), "doubling_G_O.1");
	test(root == s->index, "doubling_G_O.2");
	test(valid_secp256k1(s, r3), "doubling_G_O.3");
	free_fixed(s);

	s = make_secp256r1_fixed();
	g = Elliptic_secp256r1_g;
	o = Elliptic_secp256r1_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_secp256r1(s, o, r3);
	addition_secp256r1(s, g, r3, r3);
	test(equal_point_secp256r1(s, g, r3), "doubling_G_O.4");
	test(root == s->index, "doubling_G_O.5");
	test(valid_secp256r1(s, r3), "doubling_G_O.6");
	free_fixed(s);

	s = make_ed25519_fixed();
	g = Elliptic_ed25519_g;
	o = Elliptic_ed25519_o;
	push4_fixed(s, r4);
	root = s->index;
	doubling_ed25519(s, o, r4);
	addition_ed25519(s, g, r4, r4);
	test(equal_point_ed25519(s, g, r4), "doubling_G_O.7");
	test(root == s->index, "doubling_G_O.8");
	test(valid_ed25519(s, r4), "doubling_G_O.9");
	free_fixed(s);

	s = make_ed448_fixed();
	g = Elliptic_ed448_g;
	o = Elliptic_ed448_o;
	push3_fixed(s, r3);
	root = s->index;
	doubling_ed448(s, o, r3);
	addition_ed448(s, g, r3, r3);
	test(equal_point_ed448(s, g, r3), "doubling_G_O.10");
	test(root == s->index, "doubling_G_O.11");
	test(valid_ed448(s, r3), "doubling_G_O.12");
	free_fixed(s);

	Return;
}

static int test_addition_G_G(void)
{
	fixed s;
	fixptr *g, n;
	fixptr3 a3, b3, c3;
	fixptr4 a4, b4, c4;
	fixsize root;

	s = make_secp256k1_fixed();
	g = Elliptic_secp256k1_g;
	push3_fixed(s, a3);
	push3_fixed(s, b3);
	push3_fixed(s, c3);
	n = push1get_fixed(s);
	setu_fixptr(n, s->word1, 2);
	root = s->index;
	addition_secp256k1(s, g, g, a3);
	doubling_secp256k1(s, g, b3);
	multiple_secp256k1(s, n, g, c3);
	test(equal_point_secp256k1(s, a3, b3), "addition_G_G.1");
	test(equal_point_secp256k1(s, a3, c3), "addition_G_G.2");
	test(root == s->index, "addition_G_G.3");
	test(valid_secp256k1(s, a3), "doubling_G_O.4");
	test(valid_secp256k1(s, b3), "doubling_G_O.5");
	test(valid_secp256k1(s, c3), "doubling_G_O.6");
	free_fixed(s);

	s = make_secp256r1_fixed();
	g = Elliptic_secp256r1_g;
	push3_fixed(s, a3);
	push3_fixed(s, b3);
	push3_fixed(s, c3);
	n = push1get_fixed(s);
	setu_fixptr(n, s->word1, 2);
	root = s->index;
	addition_secp256r1(s, g, g, a3);
	doubling_secp256r1(s, g, b3);
	multiple_secp256r1(s, n, g, c3);
	test(equal_point_secp256r1(s, a3, b3), "addition_G_G.7");
	test(equal_point_secp256r1(s, a3, c3), "addition_G_G.8");
	test(root == s->index, "addition_G_G.9");
	test(valid_secp256r1(s, a3), "doubling_G_O.10");
	test(valid_secp256r1(s, b3), "doubling_G_O.11");
	test(valid_secp256r1(s, c3), "doubling_G_O.12");
	free_fixed(s);

	s = make_ed25519_fixed();
	g = Elliptic_ed25519_g;
	push4_fixed(s, a4);
	push4_fixed(s, b4);
	push4_fixed(s, c4);
	n = push1get_fixed(s);
	setu_fixptr(n, s->word1, 2);
	root = s->index;
	addition_ed25519(s, g, g, a4);
	doubling_ed25519(s, g, b4);
	multiple_ed25519(s, n, g, c4);
	test(equal_point_ed25519(s, a4, b4), "addition_G_G.13");
	test(equal_point_ed25519(s, a4, c4), "addition_G_G.14");
	test(root == s->index, "addition_G_G.15");
	test(valid_ed25519(s, a4), "doubling_G_O.16");
	test(valid_ed25519(s, b4), "doubling_G_O.17");
	test(valid_ed25519(s, c4), "doubling_G_O.18");
	free_fixed(s);

	s = make_ed448_fixed();
	g = Elliptic_ed448_g;
	push3_fixed(s, a3);
	push3_fixed(s, b3);
	push3_fixed(s, c3);
	n = push1get_fixed(s);
	setu_fixptr(n, s->word1, 2);
	root = s->index;
	addition_ed448(s, g, g, a3);
	doubling_ed448(s, g, b3);
	multiple_ed448(s, n, g, c3);
	test(equal_point_ed448(s, a3, b3), "addition_G_G.19");
	test(equal_point_ed448(s, a3, c3), "addition_G_G.20");
	test(root == s->index, "addition_G_G.21");
	test(valid_ed448(s, a3), "doubling_G_O.22");
	test(valid_ed448(s, b3), "doubling_G_O.23");
	test(valid_ed448(s, c3), "doubling_G_O.24");
	free_fixed(s);

	Return;
}


/*
 *  multiple
 */
static int test_multiple_secp256k1(void)
{
	fixed s;
	fixptr *g, *o, n;
	fixptr3 a, b, c;
	fixsize root;

	s = make_secp256k1_fixed();
	n = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);
	push3_fixed(s, c);
	g = Elliptic_secp256k1_g;
	o = Elliptic_secp256k1_o;

	/* 0G */
	setu_fixptr(n, s->word1, 0);
	root = s->index;
	multiple_secp256k1(s, n, g, a);
	test(root == s->index, "multiple_secp256k1.1");
	test(equal_point_secp256k1(s, o, a), "multiple_secp256k1.2");

	/* 1G */
	setu_fixptr(n, s->word1, 1);
	root = s->index;
	multiple_secp256k1(s, n, g, a);
	test(root == s->index, "multiple_secp256k1.3");
	test(equal_point_secp256k1(s, g, a), "multiple_secp256k1.4");
	test(valid_secp256k1(s, a), "multiple_secp256k1.5");

	/* 5G */
	setu_fixptr(n, s->word1, 5);
	root = s->index;
	multiple_secp256k1(s, n, g, a);
	test(root == s->index, "multiple_secp256k1.6");
	test(valid_secp256k1(s, a), "multiple_secp256k1.7");

	/* G+G+G+G+G */
	addition_secp256k1(s, g, g, b);
	addition_secp256k1(s, b, g, b);
	addition_secp256k1(s, b, g, b);
	addition_secp256k1(s, b, g, b);
	test(equal_point_secp256k1(s, a, b), "multiple_secp256k1.8");
	test(valid_secp256k1(s, b), "multiple_secp256k1.9");

	/* 2G+2G+G */
	doubling_secp256k1(s, g, b);
	addition_secp256k1(s, b, b, c);
	addition_secp256k1(s, c, g, c);
	test(equal_point_secp256k1(s, a, c), "multiple_secp256k1.10");
	test(valid_secp256k1(s, c), "multiple_secp256k1.11");

	/* nG */
	root = s->index;
	multiple_secp256k1(s, Elliptic_secp256k1_n, g, a);
	test(root == s->index, "multiple_secp256k1.12");
	test(neutral_secp256k1(s, a), "multiple_secp256k1.13");

	/* G + nG */
	addition_secp256k1(s, g, a, b);
	test(equal_point_secp256k1(s, g, b), "multiple_secp256k1.14");

	/* nG + G */
	addition_secp256k1(s, a, g, b);
	test(equal_point_secp256k1(s, g, b), "multiple_secp256k1.15");

	/* 1000G */
	setu_fixptr(n, s->word1, 1000);
	multiple_secp256k1(s, n, g, a);
	sub_elliptic_secp256k1(Elliptic_secp256k1_n, n, n, s->word1);
	multiple_secp256k1(s, n, g, b);
	addition_secp256k1(s, a, b, a);
	test(neutral_secp256k1(s, a), "multiple_secp256k1.16");

	free_fixed(s);

	Return;
}

static int test_multiple_secp256r1(void)
{
	fixed s;
	fixptr *g, *o, n;
	fixptr3 a, b, c;
	fixsize root;

	s = make_secp256r1_fixed();
	n = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);
	push3_fixed(s, c);
	g = Elliptic_secp256r1_g;
	o = Elliptic_secp256r1_o;

	/* 0G */
	setu_fixptr(n, s->word1, 0);
	root = s->index;
	multiple_secp256r1(s, n, g, a);
	test(root == s->index, "multiple_secp256r1.1");
	test(equal_point_secp256r1(s, o, a), "multiple_secp256r1.2");

	/* 1G */
	setu_fixptr(n, s->word1, 1);
	root = s->index;
	multiple_secp256r1(s, n, g, a);
	test(root == s->index, "multiple_secp256r1.3");
	test(equal_point_secp256r1(s, g, a), "multiple_secp256r1.4");
	test(valid_secp256r1(s, a), "multiple_secp256r1.5");

	/* 5G */
	setu_fixptr(n, s->word1, 5);
	root = s->index;
	multiple_secp256r1(s, n, g, a);
	test(root == s->index, "multiple_secp256r1.6");
	test(valid_secp256r1(s, a), "multiple_secp256r1.7");

	/* G+G+G+G+G */
	addition_secp256r1(s, g, g, b);
	addition_secp256r1(s, b, g, b);
	addition_secp256r1(s, b, g, b);
	addition_secp256r1(s, b, g, b);
	test(equal_point_secp256r1(s, a, b), "multiple_secp256r1.8");
	test(valid_secp256r1(s, b), "multiple_secp256r1.9");

	/* 2G+2G+G */
	doubling_secp256r1(s, g, b);
	addition_secp256r1(s, b, b, c);
	addition_secp256r1(s, c, g, c);
	test(equal_point_secp256r1(s, a, c), "multiple_secp256r1.10");
	test(valid_secp256r1(s, c), "multiple_secp256r1.11");

	/* nG */
	root = s->index;
	multiple_secp256r1(s, Elliptic_secp256r1_n, g, a);
	test(root == s->index, "multiple_secp256r1.12");
	test(neutral_secp256r1(s, a), "multiple_secp256r1.13");

	/* G + nG */
	addition_secp256r1(s, g, a, b);
	test(equal_point_secp256r1(s, g, b), "multiple_secp256r1.14");

	/* nG + G */
	addition_secp256r1(s, a, g, b);
	test(equal_point_secp256r1(s, g, b), "multiple_secp256r1.15");

	/* 1000G */
	setu_fixptr(n, s->word1, 1000);
	multiple_secp256r1(s, n, g, a);
	sub_elliptic_secp256r1(Elliptic_secp256r1_n, n, n, s->word1);
	multiple_secp256r1(s, n, g, b);
	addition_secp256r1(s, a, b, a);
	test(neutral_secp256r1(s, a), "multiple_secp256r1.16");

	free_fixed(s);

	Return;
}

static int test_multiple_ed25519(void)
{
	fixed s;
	fixptr *g, *o, n;
	fixptr4 a, b, c;
	fixsize root;

	s = make_ed25519_fixed();
	n = push1get_fixed(s);
	push4_fixed(s, a);
	push4_fixed(s, b);
	push4_fixed(s, c);
	g = Elliptic_ed25519_g;
	o = Elliptic_ed25519_o;

	/* 0G */
	setu_fixptr(n, s->word1, 0);
	root = s->index;
	multiple_ed25519(s, n, g, a);
	test(root == s->index, "multiple_ed25519.1");
	test(equal_point_ed25519(s, o, a), "multiple_ed25519.2");

	/* 1G */
	setu_fixptr(n, s->word1, 1);
	root = s->index;
	multiple_ed25519(s, n, g, a);
	test(root == s->index, "multiple_ed25519.3");
	test(equal_point_ed25519(s, g, a), "multiple_ed25519.4");
	test(valid_ed25519(s, a), "multiple_ed25519.5");

	/* 5G */
	setu_fixptr(n, s->word1, 5);
	root = s->index;
	multiple_ed25519(s, n, g, a);
	test(root == s->index, "multiple_ed25519.6");
	test(valid_ed25519(s, a), "multiple_ed25519.7");

	/* G+G+G+G+G */
	addition_ed25519(s, g, g, b);
	addition_ed25519(s, b, g, b);
	addition_ed25519(s, b, g, b);
	addition_ed25519(s, b, g, b);
	test(equal_point_ed25519(s, a, b), "multiple_ed25519.8");
	test(valid_ed25519(s, b), "multiple_ed25519.9");

	/* 2G+2G+G */
	doubling_ed25519(s, g, b);
	addition_ed25519(s, b, b, c);
	addition_ed25519(s, c, g, c);
	test(equal_point_ed25519(s, a, c), "multiple_ed25519.10");
	test(valid_ed25519(s, c), "multiple_ed25519.11");

	/* nG */
	root = s->index;
	multiple_ed25519(s, Elliptic_ed25519_n, g, a);
	test(root == s->index, "multiple_ed25519.12");
	test(neutral_ed25519(s, a), "multiple_ed25519.13");

	/* G + nG */
	addition_ed25519(s, g, a, b);
	test(equal_point_ed25519(s, g, b), "multiple_ed25519.14");

	/* nG + G */
	addition_ed25519(s, a, g, b);
	test(equal_point_ed25519(s, g, b), "multiple_ed25519.15");

	/* 1000G */
	setu_fixptr(n, s->word1, 1000);
	multiple_ed25519(s, n, g, a);
	sub_elliptic_ed25519(Elliptic_ed25519_n, n, n, s->word1);
	multiple_ed25519(s, n, g, b);
	addition_ed25519(s, a, b, a);
	test(neutral_ed25519(s, a), "multiple_ed25519.16");

	free_fixed(s);

	Return;
}

static int test_multiple_ed448(void)
{
	fixed s;
	fixptr *g, *o, n;
	fixptr3 a, b, c;
	fixsize root;

	s = make_ed448_fixed();
	n = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);
	push3_fixed(s, c);
	g = Elliptic_ed448_g;
	o = Elliptic_ed448_o;

	/* 0G */
	setu_fixptr(n, s->word1, 0);
	root = s->index;
	multiple_ed448(s, n, g, a);
	test(root == s->index, "multiple_ed448.1");
	test(equal_point_ed448(s, o, a), "multiple_ed448.2");

	/* 1G */
	setu_fixptr(n, s->word1, 1);
	root = s->index;
	multiple_ed448(s, n, g, a);
	test(root == s->index, "multiple_ed448.3");
	test(equal_point_ed448(s, g, a), "multiple_ed448.4");
	test(valid_ed448(s, a), "multiple_ed448.5");

	/* 5G */
	setu_fixptr(n, s->word1, 5);
	root = s->index;
	multiple_ed448(s, n, g, a);
	test(root == s->index, "multiple_ed448.6");
	test(valid_ed448(s, a), "multiple_ed448.7");

	/* G+G+G+G+G */
	addition_ed448(s, g, g, b);
	addition_ed448(s, b, g, b);
	addition_ed448(s, b, g, b);
	addition_ed448(s, b, g, b);
	test(equal_point_ed448(s, a, b), "multiple_ed448.8");
	test(valid_ed448(s, b), "multiple_ed448.9");

	/* 2G+2G+G */
	doubling_ed448(s, g, b);
	addition_ed448(s, b, b, c);
	addition_ed448(s, c, g, c);
	test(equal_point_ed448(s, a, c), "multiple_ed448.10");
	test(valid_ed448(s, c), "multiple_ed448.11");

	/* nG */
	root = s->index;
	multiple_ed448(s, Elliptic_ed448_n, g, a);
	test(root == s->index, "multiple_ed448.12");
	test(neutral_ed448(s, a), "multiple_ed448.13");

	/* G + nG */
	addition_ed448(s, g, a, b);
	test(equal_point_ed448(s, g, b), "multiple_ed448.14");

	/* nG + G */
	addition_ed448(s, a, g, b);
	test(equal_point_ed448(s, g, b), "multiple_ed448.15");

	/* 1000G */
	setu_fixptr(n, s->word1, 1000);
	multiple_ed448(s, n, g, a);
	sub_elliptic_ed448(Elliptic_ed448_n, n, n, s->word1);
	multiple_ed448(s, n, g, b);
	addition_ed448(s, a, b, a);
	test(neutral_ed448(s, a), "multiple_ed448.16");

	free_fixed(s);

	Return;
}


/*
 *  encode
 */
static int test_encode_secp256k1(void)
{
	uint8_t u[100];
	const char *p;
	fixed s;
	fixptr *a;
	fixsize root;
	vector2_secp256k1 v, x, y;

	p = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	string_integer_elliptic(p, x, 32, 0);
	p = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	string_integer_elliptic(p, y, 32, 0);
	s = make_secp256k1_fixed();

	/* o */
	a = Elliptic_secp256k1_o;
	memset(v, 0xAA, vector2_size_secp256k1);
	root = s->index;
	test(encode_secp256k1(s, a, v, 0) == 1, "encode_secp256k1.1");
	test(root == s->index, "encode_secp256k1.2");
	test(v[0] == 0x00, "encode_secp256k1.3");
	test(v[1] == 0xAA, "encode_secp256k1.4");
	memset(v, 0xAA, vector2_size_secp256k1);
	root = s->index;
	test(encode_secp256k1(s, a, v, 1) == 1, "encode_secp256k1.5");
	test(root == s->index, "encode_secp256k1.6");
	test(v[0] == 0x00, "encode_secp256k1.7");
	test(v[1] == 0xAA, "encode_secp256k1.8");

	/* uncompress */
	a = Elliptic_secp256k1_g;
	memset(u, 0xAA, 100);
	encode_secp256k1(s, a, u, 0);
	test(u[65] == 0xAA, "encode_secp256k1.9");
	memset(u, 0xBB, 100);
	encode_secp256k1(s, a, u, 0);
	test(u[65] == 0xBB, "encode_secp256k1.10");
	root = s->index;
	test(encode_secp256k1(s, a, v, 0) == 65, "encode_secp256k1.11");
	test(root == s->index, "encode_secp256k1.12");
	test(v[0] == 0x04, "encode_secp256k1.13");
	test(memcmp(v + 1, x, 32) == 0, "encode_secp256k1.14");
	test(memcmp(v + 1 + 32, y, 32) == 0, "encode_secp256k1.15");

	/* compress */
	a = Elliptic_secp256k1_g;
	memset(v, 0xAA, vector2_size_secp256k1);
	encode_secp256k1(s, a, v, 1);
	test(v[33] == 0xAA, "encode_secp256k1.16");
	memset(v, 0xBB, vector2_size_secp256k1);
	root = s->index;
	encode_secp256k1(s, a, v, 1);
	test(v[33] == 0xBB, "encode_secp256k1.17");
	test(encode_secp256k1(s, a, v, 1) == 33, "encode_secp256k1.18");
	test(root == s->index, "encode_secp256k1.19");
	test(v[0] == 0x02, "encode_secp256k1.20");
	test(encode_secp256k1(s, a, v, 1) == 33, "encode_secp256k1.21");
	test(memcmp(v + 1, x, 32) == 0, "encode_secp256k1.22");

	free_fixed(s);

	Return;
}

static int test_encode_secp256r1(void)
{
	uint8_t u[100];
	const char *p;
	fixed s;
	fixptr *a;
	fixsize root;
	vector2_secp256r1 v, x, y;

	p = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
	string_integer_elliptic(p, x, 32, 0);
	p = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
	string_integer_elliptic(p, y, 32, 0);
	s = make_secp256r1_fixed();

	/* o */
	a = Elliptic_secp256r1_o;
	memset(v, 0xAA, vector2_size_secp256r1);
	root = s->index;
	test(encode_secp256r1(s, a, v, 0) == 1, "encode_secp256r1.1");
	test(root == s->index, "encode_secp256r1.2");
	test(v[0] == 0x00, "encode_secp256r1.3");
	test(v[1] == 0xAA, "encode_secp256r1.4");
	memset(v, 0xAA, vector2_size_secp256r1);
	root = s->index;
	test(encode_secp256r1(s, a, v, 1) == 1, "encode_secp256r1.5");
	test(root == s->index, "encode_secp256r1.6");
	test(v[0] == 0x00, "encode_secp256r1.7");
	test(v[1] == 0xAA, "encode_secp256r1.8");

	/* uncompress */
	a = Elliptic_secp256r1_g;
	memset(u, 0xAA, 100);
	encode_secp256r1(s, a, u, 0);
	test(u[65] == 0xAA, "encode_secp256r1.9");
	memset(u, 0xBB, 100);
	encode_secp256r1(s, a, u, 0);
	test(u[65] == 0xBB, "encode_secp256r1.10");
	root = s->index;
	test(encode_secp256r1(s, a, v, 0) == 65, "encode_secp256r1.11");
	test(root == s->index, "encode_secp256r1.12");
	test(v[0] == 0x04, "encode_secp256r1.13");
	test(memcmp(v + 1, x, 32) == 0, "encode_secp256r1.14");
	test(memcmp(v + 1 + 32, y, 32) == 0, "encode_secp256r1.15");

	/* compress */
	a = Elliptic_secp256r1_g;
	memset(v, 0xAA, vector2_size_secp256r1);
	encode_secp256r1(s, a, v, 1);
	test(v[33] == 0xAA, "encode_secp256r1.16");
	memset(v, 0xBB, vector2_size_secp256r1);
	root = s->index;
	encode_secp256r1(s, a, v, 1);
	test(v[33] == 0xBB, "encode_secp256r1.17");
	test(encode_secp256r1(s, a, v, 1) == 33, "encode_secp256r1.18");
	test(root == s->index, "encode_secp256r1.19");
	test(v[0] == 0x03, "encode_secp256r1.20");
	test(encode_secp256r1(s, a, v, 1) == 33, "encode_secp256r1.21");
	test(memcmp(v + 1, x, 32) == 0, "encode_secp256r1.22");

	free_fixed(s);

	Return;
}

static int test_encode_ed25519(void)
{
	uint8_t u[100];
	const char *p;
	fixed s;
	fixptr *a, n;
	fixptr4 r4;
	fixsize root;
	vector2_ed25519 v, x;

	/*
	 *  G  (x0=0)
	 *    216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
	 *    6666666666666666666666666666666666666666666666666666666666666658
	 *
	 *  5G  (x0=1)
	 *    49FDA73EADE3587BFCEF7CF7D12DA5DE5C2819F93E1BE1A591409CC0322EF233
	 *    5F4825B298FEAE6FE02C6E148992466631282ECA89430B5D10D21F83D676C8ED
	 */
	s = make_ed25519_fixed();
	n = push1get_fixed(s);
	push4_fixed(s, r4);

	/* bound */
	a = Elliptic_ed25519_g;
	memset(u, 0xAA, 100);
	encode_ed25519(s, a, u);
	test(u[32] == 0xAA, "encode_ed25519.1");
	memset(u, 0xBB, 100);
	encode_ed25519(s, a, u);
	test(u[32] == 0xBB, "encode_ed25519.2");

	/* G */
	p = "6666666666666666666666666666666666666666666666666666666666666658";
	string_integer_elliptic(p, x, 32, 1);
	root = s->index;
	test(encode_ed25519(s, a, v) == 32, "encode_ed25519.3");
	test(root == s->index, "encode_ed25519.4");
	test(memcmp(v, x, 32) == 0, "encode_ed25519.5");

	/* 5G */
	p = "DF4825B298FEAE6FE02C6E148992466631282ECA89430B5D10D21F83D676C8ED";
	string_integer_elliptic(p, x, 32, 1);
	setv_fixptr(n, s->word1, 5);
	a = Elliptic_ed25519_g;
	multiple_ed25519(s, n, a, r4);
	root = s->index;
	test(encode_ed25519(s, r4, v) == 32, "encode_ed25519.6");
	test(root == s->index, "encode_ed25519.7");
	test(memcmp(v, x, 32) == 0, "encode_ed25519.8");

	free_fixed(s);

	Return;
}

static int test_encode_ed448(void)
{
	uint8_t u[100];
	const char *p;
	fixed s;
	fixptr *a, n;
	fixptr3 r3;
	fixsize root;
	vector2_ed448 v, x;

	/*
	 *  G  (x0=0)
	 *  4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324
	 *  A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
	 *  693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E
	 *  05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14
	 *
	 *  2G  (x0=2)
	 *  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9
	 *  55555555555555555555555555555555555555555555555555555555
	 *  AE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D72
	 *  8AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED
	 */
	s = make_ed448_fixed();
	n = push1get_fixed(s);
	push3_fixed(s, r3);

	/* bound */
	a = Elliptic_ed448_g;
	memset(u, 0xAA, 100);
	encode_ed448(s, a, u);
	test(u[57] == 0xAA, "encode_ed448.1");
	memset(u, 0xBB, 100);
	encode_ed448(s, a, u);
	test(u[57] == 0xBB, "encode_ed448.2");

	/* G */
	p = "00693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1"
		"E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14";
	string_integer_elliptic(p, x, 57, 1);
	root = s->index;
	test(encode_ed448(s, a, v) == 57, "encode_ed448.3");
	test(root == s->index, "encode_ed448.4");
	test(memcmp(v, x, 57) == 0, "encode_ed448.5");

	/* 2G */
	p = "80AE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D7"
		"28AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED";
	string_integer_elliptic(p, x, 57, 1);
	setv_fixptr(n, s->word1, 2);
	a = Elliptic_ed448_g;
	multiple_ed448(s, n, a, r3);
	root = s->index;
	test(encode_ed448(s, r3, v) == 57, "encode_ed448.6");
	test(root == s->index, "encode_ed448.7");
	test(memcmp(v, x, 57) == 0, "encode_ed448.8");

	free_fixed(s);

	Return;
}


/*
 *  decode
 */
static int test_decode_secp256k1(void)
{
	fixed s;
	fixptr *a;
	fixptr3 r3;
	fixsize root;
	vector2_secp256k1 v;

	s = make_secp256k1_fixed();
	push3_fixed(s, r3);

	/* O */
	memset(v, 0xAA, vector2_size_secp256k1);
	v[0] = 0x00;
	root = s->index;
	test(decode_secp256k1(s, v, r3) == 0, "decode_secp256k1.1");
	test(root == s->index, "decode_secp256k1.2");
	test(neutral_secp256k1(s, r3), "decode_secp256k1.3");

	/* G */
	memset(v, 0xAA, vector2_size_secp256k1);
	a = Elliptic_secp256k1_g;
	encode_secp256k1(s, a, v, 0);
	root = s->index;
	test(decode_secp256k1(s, v, r3) == 0, "decode_secp256k1.4");
	test(root == s->index, "decode_secp256k1.5");
	test(valid_secp256k1(s, r3), "decode_secp256k1.6");
	test(equal_point_secp256k1(s, a, r3), "decode_secp256k1.7");

	/* G */
	memset(v, 0xAA, vector2_size_secp256k1);
	a = Elliptic_secp256k1_g;
	encode_secp256k1(s, a, v, 1);
	root = s->index;
	test(decode_secp256k1(s, v, r3) == 0, "decode_secp256k1.8");
	test(root == s->index, "decode_secp256k1.9");
	test(valid_secp256k1(s, r3), "decode_secp256k1.10");
	test(equal_point_secp256k1(s, a, r3), "decode_secp256k1.11");

	free_fixed(s);

	Return;
}

static int test_decode_secp256r1(void)
{
	fixed s;
	fixptr *a;
	fixptr3 r3;
	fixsize root;
	vector2_secp256r1 v;

	s = make_secp256r1_fixed();
	push3_fixed(s, r3);

	/* O */
	memset(v, 0xAA, vector2_size_secp256r1);
	v[0] = 0x00;
	root = s->index;
	test(decode_secp256r1(s, v, r3) == 0, "decode_secp256r1.1");
	test(root == s->index, "decode_secp256r1.2");
	test(neutral_secp256r1(s, r3), "decode_secp256r1.3");

	/* G */
	memset(v, 0xAA, vector2_size_secp256r1);
	a = Elliptic_secp256r1_g;
	encode_secp256r1(s, a, v, 0);
	root = s->index;
	test(decode_secp256r1(s, v, r3) == 0, "decode_secp256r1.4");
	test(root == s->index, "decode_secp256r1.5");
	test(valid_secp256r1(s, r3), "decode_secp256r1.6");
	test(equal_point_secp256r1(s, a, r3), "decode_secp256r1.7");

	/* G */
	memset(v, 0xAA, vector2_size_secp256r1);
	a = Elliptic_secp256r1_g;
	encode_secp256r1(s, a, v, 1);
	root = s->index;
	test(decode_secp256r1(s, v, r3) == 0, "decode_secp256r1.8");
	test(root == s->index, "decode_secp256r1.9");
	test(valid_secp256r1(s, r3), "decode_secp256r1.10");
	test(equal_point_secp256r1(s, a, r3), "decode_secp256r1.11");

	free_fixed(s);

	Return;
}

static int test_decode_ed25519(void)
{
	fixed s;
	fixptr *a, n;
	fixptr4 r4, g4;
	fixsize root;
	vector2_ed25519 v;

	s = make_ed25519_fixed();
	n = push1get_fixed(s);
	push4_fixed(s, r4);
	push4_fixed(s, g4);

	/* O */
	memset(v, 0xAA, vector2_size_ed25519);
	a = Elliptic_ed25519_o;
	encode_ed25519(s, a, v);
	root = s->index;
	test(decode_ed25519(s, v, r4) == 0, "decode_ed25519.1");
	test(root == s->index, "decode_ed25519.2");
	test(neutral_ed25519(s, r4), "decode_ed25519.3");

	/* G */
	memset(v, 0xAA, vector2_size_ed25519);
	a = Elliptic_ed25519_g;
	encode_ed25519(s, a, v);
	root = s->index;
	test(decode_ed25519(s, v, r4) == 0, "decode_ed25519.4");
	test(root == s->index, "decode_ed25519.5");
	test(valid_ed25519(s, r4), "decode_ed25519.6");
	test(equal_point_ed25519(s, a, r4), "decode_ed25519.7");

	/* 5G */
	memset(v, 0xAA, vector2_size_ed25519);
	a = Elliptic_ed25519_g;
	setu_fixptr(n, s->word1, 5);
	multiple_ed25519(s, n, a, g4);
	encode_ed25519(s, g4, v);
	root = s->index;
	test(decode_ed25519(s, v, r4) == 0, "decode_ed25519.8");
	test(root == s->index, "decode_ed25519.9");
	test(valid_ed25519(s, r4), "decode_ed25519.10");
	test(equal_point_ed25519(s, g4, r4), "decode_ed25519.11");

	free_fixed(s);

	Return;
}

static int test_decode_ed448(void)
{
	fixed s;
	fixptr *a, n;
	fixptr3 r3, g3;
	fixsize root;
	vector2_ed448 v;

	s = make_ed448_fixed();
	n = push1get_fixed(s);
	push3_fixed(s, r3);
	push3_fixed(s, g3);

	/* O */
	memset(v, 0xAA, vector2_size_ed448);
	a = Elliptic_ed448_o;
	encode_ed448(s, a, v);
	root = s->index;
	test(decode_ed448(s, v, r3) == 0, "decode_ed448.1");
	test(root == s->index, "decode_ed448.2");
	test(neutral_ed448(s, r3), "decode_ed448.3");

	/* G */
	memset(v, 0xAA, vector2_size_ed448);
	a = Elliptic_ed448_g;
	encode_ed448(s, a, v);
	root = s->index;
	test(decode_ed448(s, v, r3) == 0, "decode_ed448.4");
	test(root == s->index, "decode_ed448.5");
	test(valid_ed448(s, r3), "decode_ed448.6");
	test(equal_point_ed448(s, a, r3), "decode_ed448.7");

	/* 2G */
	memset(v, 0xAA, vector2_size_ed448);
	a = Elliptic_ed448_g;
	setu_fixptr(n, s->word1, 2);
	multiple_ed448(s, n, a, g3);
	encode_ed448(s, g3, v);
	root = s->index;
	test(decode_ed448(s, v, r3) == 0, "decode_ed448.8");
	test(root == s->index, "decode_ed448.9");
	test(valid_ed448(s, r3), "decode_ed448.10");
	test(equal_point_ed448(s, g3, r3), "decode_ed448.11");

	free_fixed(s);

	Return;
}


/*
 *  private
 */
static int test_private(void)
{
	fixed s;
	fixptr x;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	private_secp256k1(s, &random_state, x);
	test(! zerop_fixptr(x, s->word1), "private.1");
	free_fixed(s);

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	private_secp256r1(s, &random_state, x);
	test(! zerop_fixptr(x, s->word1), "private.2");
	free_fixed(s);

	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	private_ed25519(s, &random_state, x);
	test(1, "private.3");
	free_fixed(s);

	s = make_ed448_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	private_ed448(s, &random_state, x);
	test(1, "private.4");
	free_fixed(s);

	Return;
}


/*
 *  public
 */
static int test_public_secp256k1(void)
{
	fixed s;
	fixptr *g, x;
	fixptr3 r;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r);

	g = Elliptic_secp256k1_g;
	setv_fixptr(x, s->word1, 1);
	public_secp256k1(s, x, r);
	test(equal_point_secp256k1(s, g, r), "public_secp256k1.1");
	free_fixed(s);

	Return;
}

static int test_public_secp256r1(void)
{
	fixed s;
	fixptr *g, x;
	fixptr3 r;

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r);

	g = Elliptic_secp256r1_g;
	setv_fixptr(x, s->word1, 1);
	public_secp256r1(s, x, r);
	test(equal_point_secp256r1(s, g, r), "public_secp256r1.1");
	free_fixed(s);

	Return;
}

static int public_pq_ed25519(const char *p, const char *q)
{
	int check;
	fixed s;
	fixptr x;
	fixptr4 r4, p4;
	vector1_ed25519 v1;
	vector2_ed25519 v2;

	string_integer_elliptic(p, v1, vector1_size_ed25519, 0);
	string_integer_elliptic(q, v2, vector2_size_ed25519, 0);
	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	push4_fixed(s, r4);
	push4_fixed(s, p4);

	input_fixptr(x, s->word1, v1, vector1_size_ed25519, 1);
	public_ed25519(s, x, p4);
	if (decode_ed25519(s, v2, r4))
		return 0;
	check = equal_point_ed25519(s, p4, r4);
	free_fixed(s);

	return check;
}

static int test_public_ed25519(void)
{
	const char *p, *q;

	/* 1 */
	p = "9d61b19deffd5a60ba844af492ec2cc4"
		"4449c5697b326919703bac031cae7f60";
	q = "d75a980182b10ab7d54bfed3c964073a"
		"0ee172f3daa62325af021a68f707511a";
	test(public_pq_ed25519(p, q), "public_ed25519.1");

	/* 2 */
	p = "4ccd089b28ff96da9db6c346ec114e0f"
		"5b8a319f35aba624da8cf6ed4fb8a6fb";
	q = "3d4017c3e843895a92b70aa74d1b7ebc"
		"9c982ccf2ec4968cc0cd55f12af4660c";
	test(public_pq_ed25519(p, q), "public_ed25519.2");

	/* 3 */
	p = "c5aa8df43f9f837bedb7442f31dcb7b1"
		"66d38535076f094b85ce3a2e0b4458f7";
	q = "fc51cd8e6218a1a38da47ed00230f058"
		"0816ed13ba3303ac5deb911548908025";
	test(public_pq_ed25519(p, q), "public_ed25519.3");

	/* 4 */
	p = "f5e5767cf153319517630f226876b86c"
		"8160cc583bc013744c6bf255f5cc0ee5";
	q = "278117fc144c72340f67d0f2316e8386"
		"ceffbf2b2428c9c51fef7c597f1d426e";
	test(public_pq_ed25519(p, q), "public_ed25519.4");

	/* 5 */
	p = "833fe62409237b9d62ec77587520911e"
		"9a759cec1d19755b7da901b96dca3d42";
	q = "ec172b93ad5e563bf4932c70e1245034"
		"c35467ef2efd4d64ebf819683467e2bf";
	test(public_pq_ed25519(p, q), "public_ed25519.5");

	Return;
}

static int public_pq_ed448(const char *p, const char *q)
{
	int check;
	fixed s;
	fixptr x;
	fixptr3 r3, p3;
	vector1_ed448 v1;
	vector2_ed448 v2;

	string_integer_elliptic(p, v1, vector1_size_ed448, 0);
	string_integer_elliptic(q, v2, vector2_size_ed448, 0);
	s = make_ed448_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r3);
	push3_fixed(s, p3);

	input_fixptr(x, s->word1, v1, vector1_size_ed448, 1);
	public_ed448(s, x, p3);
	if (decode_ed448(s, v2, r3))
		return 0;
	check = equal_point_ed448(s, p3, r3);
	free_fixed(s);

	return check;
}

static int test_public_ed448(void)
{
	const char *p, *q;

	/* 1 */
	p = "6c82a562cb808d10d632be89c8513ebf"
		"6c929f34ddfa8c9f63c9960ef6e348a3"
		"528c8a3fcc2f044e39a3fc5b94492f8f"
		"032e7549a20098f95b";
	q = "5fd7449b59b461fd2ce787ec616ad46a"
		"1da1342485a70e1f8a0ea75d80e96778"
		"edf124769b46c7061bd6783df1e50f6c"
		"d1fa1abeafe8256180";
	test(public_pq_ed448(p, q), "public_ed448.1");

	/* 2 */
	p = "c4eab05d357007c632f3dbb48489924d"
		"552b08fe0c353a0d4a1f00acda2c463a"
		"fbea67c5e8d2877c5e3bc397a659949e"
		"f8021e954e0a12274e";
	q = "43ba28f430cdff456ae531545f7ecd0a"
		"c834a55d9358c0372bfa0c6c6798c086"
		"6aea01eb00742802b8438ea4cb82169c"
		"235160627b4c3a9480";
	test(public_pq_ed448(p, q), "public_ed448.2");

	/* 3 */
	p = "c4eab05d357007c632f3dbb48489924d"
		"552b08fe0c353a0d4a1f00acda2c463a"
		"fbea67c5e8d2877c5e3bc397a659949e"
		"f8021e954e0a12274e";
	q = "43ba28f430cdff456ae531545f7ecd0a"
		"c834a55d9358c0372bfa0c6c6798c086"
		"6aea01eb00742802b8438ea4cb82169c"
		"235160627b4c3a9480";
	test(public_pq_ed448(p, q), "public_ed448.3");

	/* 4 */
	p = "cd23d24f714274e744343237b93290f5"
		"11f6425f98e64459ff203e8985083ffd"
		"f60500553abc0e05cd02184bdb89c4cc"
		"d67e187951267eb328";
	q = "dcea9e78f35a1bf3499a831b10b86c90"
		"aac01cd84b67a0109b55a36e9328b1e3"
		"65fce161d71ce7131a543ea4cb5f7e9f"
		"1d8b00696447001400";
	test(public_pq_ed448(p, q), "public_ed448.4");

	/* 5 */
	p = "258cdd4ada32ed9c9ff54e63756ae582"
		"fb8fab2ac721f2c8e676a72768513d93"
		"9f63dddb55609133f29adf86ec9929dc"
		"cb52c1c5fd2ff7e21b";
	q = "3ba16da0c6f2cc1f30187740756f5e79"
		"8d6bc5fc015d7c63cc9510ee3fd44adc"
		"24d8e968b6e46e6f94d19b945361726b"
		"d75e149ef09817f580";
	test(public_pq_ed448(p, q), "public_ed448.5");

	Return;
}


/*
 *  test
 */
int test_elliptic(void)
{
	make_fixrandom(&random_state);
	TestCall(test_valid);
	TestCall(test_neutral);
	TestCall(test_inverse);
	TestCall(test_addition_O_G);
	TestCall(test_addition_G_O);
	TestCall(test_addition_O_O);
	TestCall(test_doubling_O);
	TestCall(test_doubling_O_G);
	TestCall(test_doubling_G_O);
	TestCall(test_addition_G_G);
	TestCall(test_multiple_secp256k1);
	TestCall(test_multiple_secp256r1);
	TestCall(test_multiple_ed25519);
	TestCall(test_multiple_ed448);
	TestCall(test_encode_secp256k1);
	TestCall(test_encode_secp256r1);
	TestCall(test_encode_ed25519);
	TestCall(test_encode_ed448);
	TestCall(test_decode_secp256k1);
	TestCall(test_decode_secp256r1);
	TestCall(test_decode_ed25519);
	TestCall(test_decode_ed448);
	TestCall(test_private);
	TestCall(test_public_secp256k1);
	TestCall(test_public_secp256r1);
	TestCall(test_public_ed25519);
	TestCall(test_public_ed448);

	return 0;
}

