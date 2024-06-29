#include "addition.h"
#include "crypt.h"
#include "elliptic.h"
#include "random.h"
#include "signature.h"
#include "test.h"

static struct fixed_random random_state;

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

	return 0;
}


