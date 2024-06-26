#include "addition.h"
#include "crypt.h"
#include "elliptic.h"
#include "public.h"
#include "random.h"
#include "signature.h"
#include "test.h"

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
	fixptr3 r3, g3;
	fixsize root;
	vector2_secp256k1 v;

	s = make_secp256k1_fixed();
	push3_fixed(s, r3);
	push3_fixed(s, g3);

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

	/* 2G */
	memset(v, 0xAA, vector2_size_secp256k1);
	a = Elliptic_secp256k1_g;
	doubling_secp256k1(s, a, g3);
	encode_secp256k1(s, g3, v, 0);
	root = s->index;
	test(decode_secp256k1(s, v, r3) == 0, "decode_secp256k1.12");
	test(root == s->index, "decode_secp256k1.13");
	test(valid_secp256k1(s, r3), "decode_secp256k1.14");
	test(equal_point_secp256k1(s, g3, r3), "decode_secp256k1.15");

	/* 2G */
	memset(v, 0xAA, vector2_size_secp256k1);
	a = Elliptic_secp256k1_g;
	doubling_secp256k1(s, a, g3);
	encode_secp256k1(s, g3, v, 1);
	root = s->index;
	test(decode_secp256k1(s, v, r3) == 0, "decode_secp256k1.16");
	test(root == s->index, "decode_secp256k1.17");
	test(valid_secp256k1(s, r3), "decode_secp256k1.18");
	test(equal_point_secp256k1(s, g3, r3), "decode_secp256k1.19");

	free_fixed(s);

	Return;
}

static int test_decode_secp256r1(void)
{
	fixed s;
	fixptr *a;
	fixptr3 r3, g3;
	fixsize root;
	vector2_secp256r1 v;

	s = make_secp256r1_fixed();
	push3_fixed(s, r3);
	push3_fixed(s, g3);

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

	/* 2G */
	memset(v, 0xAA, vector2_size_secp256r1);
	a = Elliptic_secp256r1_g;
	doubling_secp256r1(s, a, g3);
	encode_secp256r1(s, g3, v, 0);
	root = s->index;
	test(decode_secp256r1(s, v, r3) == 0, "decode_secp256r1.12");
	test(root == s->index, "decode_secp256r1.13");
	test(valid_secp256r1(s, r3), "decode_secp256r1.14");
	test(equal_point_secp256r1(s, g3, r3), "decode_secp256r1.15");

	/* 2G */
	memset(v, 0xAA, vector2_size_secp256r1);
	a = Elliptic_secp256r1_g;
	doubling_secp256r1(s, a, g3);
	encode_secp256r1(s, g3, v, 1);
	root = s->index;
	test(decode_secp256r1(s, v, r3) == 0, "decode_secp256r1.16");
	test(root == s->index, "decode_secp256r1.17");
	test(valid_secp256r1(s, r3), "decode_secp256r1.18");
	test(equal_point_secp256r1(s, g3, r3), "decode_secp256r1.19");

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
	fixsize root;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	root = s->index;
	private_secp256k1(s, &random_state, x);
	test(root == s->index, "private.1");
	test(! zerop_fixptr(x, s->word1), "private.2");
	free_fixed(s);

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	root = s->index;
	private_secp256r1(s, &random_state, x);
	test(root == s->index, "private.3");
	test(! zerop_fixptr(x, s->word1), "private.4");
	free_fixed(s);

	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	root = s->index;
	private_ed25519(s, &random_state, x);
	test(root == s->index, "private.5");
	free_fixed(s);

	s = make_ed448_fixed();
	x = push1get_fixed(s);
	setv_fixptr(x, s->word1, 0);
	root = s->index;
	private_ed448(s, &random_state, x);
	test(root == s->index, "private.6");
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
	fixsize root;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r);

	g = Elliptic_secp256k1_g;
	setv_fixptr(x, s->word1, 1);
	root = s->index;
	public_secp256k1(s, x, r);
	test(root == s->index, "public_secp256k1.1");
	test(equal_point_secp256k1(s, g, r), "public_secp256k1.2");
	free_fixed(s);

	Return;
}

static int test_public_secp256r1(void)
{
	fixed s;
	fixptr *g, x;
	fixptr3 r;
	fixsize root;

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r);

	g = Elliptic_secp256r1_g;
	setv_fixptr(x, s->word1, 1);
	root = s->index;
	public_secp256r1(s, x, r);
	test(root == s->index, "public_secp256r1.1");
	test(equal_point_secp256r1(s, g, r), "public_secp256r1.2");
	free_fixed(s);

	Return;
}

static int public_pq_ed25519(const char *p, const char *q)
{
	int check;
	fixed s;
	fixptr x;
	fixptr4 r4, p4;
	fixsize root;
	vector1_ed25519 v1;
	vector2_ed25519 v2;

	string_integer_elliptic(p, v1, vector1_size_ed25519, 0);
	string_integer_elliptic(q, v2, vector2_size_ed25519, 0);
	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	push4_fixed(s, r4);
	push4_fixed(s, p4);

	input_fixptr(x, s->word1, v1, vector1_size_ed25519, 1);
	root = s->index;
	public_ed25519(s, x, p4);
	if (root != s->index)
		return 0;
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
	fixsize root;
	vector1_ed448 v1;
	vector2_ed448 v2;

	string_integer_elliptic(p, v1, vector1_size_ed448, 0);
	string_integer_elliptic(q, v2, vector2_size_ed448, 0);
	s = make_ed448_fixed();
	x = push1get_fixed(s);
	push3_fixed(s, r3);
	push3_fixed(s, p3);

	root = s->index;
	input_fixptr(x, s->word1, v1, vector1_size_ed448, 1);
	if (root != s->index)
		return 0;
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
 *  sign
 */
static int test_sign_secp256k1(void)
{
	int check;
	fixed s;
	fixptr x, sign_r, sign_s;
	fixptr3 y;
	fixsize root;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	sign_r = push1get_fixed(s);
	sign_s = push1get_fixed(s);
	push3_fixed(s, y);

	/* ok */
	private_secp256k1(s, &random_state, x);
	public_secp256k1(s, x, y);
	root = s->index;
	sign_secp256k1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256k1.1");
	check = verify_secp256k1(s, y, "Hello", 5, sign_r, sign_s);
	test(check, "sign_secp256k1.2");

	/* Hallo */
	private_secp256k1(s, &random_state, x);
	public_secp256k1(s, x, y);
	root = s->index;
	sign_secp256k1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256k1.3");
	check = verify_secp256k1(s, y, "Hallo", 5, sign_r, sign_s);
	test(! check, "sign_secp256k1.4");

	/* public */
	private_secp256k1(s, &random_state, x);
	public_secp256k1(s, x, y);
	root = s->index;
	sign_secp256k1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256k1.5");
	doubling_secp256k1(s, y, y);
	check = verify_secp256k1(s, y, "Hello", 5, sign_r, sign_s);
	test(! check, "sign_secp256k1.6");

	free_fixed(s);

	Return;
}

static int test_sign_secp256r1(void)
{
	int check;
	fixed s;
	fixptr x, sign_r, sign_s;
	fixptr3 y;
	fixsize root;

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	sign_r = push1get_fixed(s);
	sign_s = push1get_fixed(s);
	push3_fixed(s, y);

	/* ok */
	private_secp256r1(s, &random_state, x);
	public_secp256r1(s, x, y);
	root = s->index;
	sign_secp256r1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256r1.1");
	check = verify_secp256r1(s, y, "Hello", 5, sign_r, sign_s);
	test(check, "sign_secp256r1.2");

	/* Hallo */
	private_secp256r1(s, &random_state, x);
	public_secp256r1(s, x, y);
	root = s->index;
	sign_secp256r1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256r1.3");
	check = verify_secp256r1(s, y, "Hallo", 5, sign_r, sign_s);
	test(! check, "sign_secp256r1.4");

	/* public */
	private_secp256r1(s, &random_state, x);
	public_secp256r1(s, x, y);
	root = s->index;
	sign_secp256r1(s, &random_state, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_secp256r1.5");
	doubling_secp256r1(s, y, y);
	check = verify_secp256r1(s, y, "Hello", 5, sign_r, sign_s);
	test(! check, "sign_secp256r1.6");

	free_fixed(s);

	Return;
}

static int test_sign_ed25519(void)
{
	int check;
	fixed s;
	fixptr x, sign_r, sign_s;
	fixptr4 y;
	fixsize root;

	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	sign_r = push1get_fixed(s);
	sign_s = push1get_fixed(s);
	push4_fixed(s, y);

	/* ok */
	private_ed25519(s, &random_state, x);
	public_ed25519(s, x, y);
	root = s->index;
	sign_ed25519(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed25519.1");
	check = verify_ed25519(s, y, "Hello", 5, sign_r, sign_s);
	test(check, "sign_ed25519.2");

	/* Hallo */
	private_ed25519(s, &random_state, x);
	public_ed25519(s, x, y);
	root = s->index;
	sign_ed25519(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed25519.3");
	check = verify_ed25519(s, y, "Hallo", 5, sign_r, sign_s);
	test(! check, "sign_ed25519.4");

	/* public */
	private_ed25519(s, &random_state, x);
	public_ed25519(s, x, y);
	root = s->index;
	sign_ed25519(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed25519.5");
	doubling_ed25519(s, y, y);
	check = verify_ed25519(s, y, "Hello", 5, sign_r, sign_s);
	test(! check, "sign_ed25519.6");

	free_fixed(s);

	Return;
}

static int test_sign_ed448(void)
{
	int check;
	fixed s;
	fixptr x, sign_r, sign_s;
	fixptr3 y;
	fixsize root;

	s = make_ed448_fixed();
	x = push1get_fixed(s);
	sign_r = push1get_fixed(s);
	sign_s = push1get_fixed(s);
	push3_fixed(s, y);

	/* ok */
	private_ed448(s, &random_state, x);
	public_ed448(s, x, y);
	root = s->index;
	sign_ed448(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed448.1");
	check = verify_ed448(s, y, "Hello", 5, sign_r, sign_s);
	test(check, "sign_ed448.2");

	/* Hallo */
	private_ed448(s, &random_state, x);
	public_ed448(s, x, y);
	root = s->index;
	sign_ed448(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed448.3");
	check = verify_ed448(s, y, "Hallo", 5, sign_r, sign_s);
	test(! check, "sign_ed448.4");

	/* public */
	private_ed448(s, &random_state, x);
	public_ed448(s, x, y);
	root = s->index;
	sign_ed448(s, x, "Hello", 5, sign_r, sign_s);
	test(root == s->index, "sign_ed448.5");
	doubling_ed448(s, y, y);
	check = verify_ed448(s, y, "Hello", 5, sign_r, sign_s);
	test(! check, "sign_ed448.6");

	free_fixed(s);

	Return;
}


/*
 *  string
 */
static int test_encode_string_secp256k1(void)
{
	int check;
	fixed s;
	fixptr x, y;
	fixptr3 a, b;
	string1_secp256k1 s1;
	string2_secp256k1 s2;

	s = make_secp256k1_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);

	/* integer */
	private_secp256k1(s, &random_state, x);
	encode1_string_secp256k1(s, x, s1);
	check = decode1_string_secp256k1(s, s1, y);
	test(check == 0, "string_secp256k1.1");
	test(compare_fixptr(x, s->word1, y, s->word1) == 0, "string_secp256k1.2");

	/* point */
	doubling_secp256k1(s, Elliptic_secp256k1_g, a);
	encode2_string_secp256k1(s, a, s2);
	check = decode2_string_secp256k1(s, s2, b);
	test(check == 0, "string_secp256k1.3");
	test(equal_point_secp256k1(s, a, b), "string_secp256k1.4");

	free_fixed(s);

	Return;
}

static int test_encode_string_secp256r1(void)
{
	int check;
	fixed s;
	fixptr x, y;
	fixptr3 a, b;
	string1_secp256r1 s1;
	string2_secp256r1 s2;

	s = make_secp256r1_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);

	/* integer */
	private_secp256r1(s, &random_state, x);
	encode1_string_secp256r1(s, x, s1);
	check = decode1_string_secp256r1(s, s1, y);
	test(check == 0, "string_secp256r1.1");
	test(compare_fixptr(x, s->word1, y, s->word1) == 0, "string_secp256r1.2");

	/* point */
	doubling_secp256r1(s, Elliptic_secp256r1_g, a);
	encode2_string_secp256r1(s, a, s2);
	check = decode2_string_secp256r1(s, s2, b);
	test(check == 0, "string_secp256r1.3");
	test(equal_point_secp256r1(s, a, b), "string_secp256r1.4");

	free_fixed(s);

	Return;
}

static int test_encode_string_ed25519(void)
{
	int check;
	fixed s;
	fixptr x, y;
	fixptr4 a, b;
	string1_ed25519 s1;
	string2_ed25519 s2;

	s = make_ed25519_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	push4_fixed(s, a);
	push4_fixed(s, b);

	/* integer */
	private_ed25519(s, &random_state, x);
	encode1_string_ed25519(s, x, s1);
	check = decode1_string_ed25519(s, s1, y);
	test(check == 0, "string_ed25519.1");
	test(compare_fixptr(x, s->word1, y, s->word1) == 0, "string_ed25519.2");

	/* point */
	doubling_ed25519(s, Elliptic_ed25519_g, a);
	encode2_string_ed25519(s, a, s2);
	check = decode2_string_ed25519(s, s2, b);
	test(check == 0, "string_ed25519.3");
	test(equal_point_ed25519(s, a, b), "string_ed25519.4");

	free_fixed(s);

	Return;
}

static int test_encode_string_ed448(void)
{
	int check;
	fixed s;
	fixptr x, y;
	fixptr3 a, b;
	string1_ed448 s1;
	string2_ed448 s2;

	s = make_ed448_fixed();
	x = push1get_fixed(s);
	y = push1get_fixed(s);
	push3_fixed(s, a);
	push3_fixed(s, b);

	/* integer */
	private_ed448(s, &random_state, x);
	encode1_string_ed448(s, x, s1);
	check = decode1_string_ed448(s, s1, y);
	test(check == 0, "string_ed448.1");
	test(compare_fixptr(x, s->word1, y, s->word1) == 0, "string_ed448.2");

	/* point */
	doubling_ed448(s, Elliptic_ed448_g, a);
	encode2_string_ed448(s, a, s2);
	check = decode2_string_ed448(s, s2, b);
	test(check == 0, "string_ed448.3");
	test(equal_point_ed448(s, a, b), "string_ed448.4");

	free_fixed(s);

	Return;
}

static int test_string_secp256k1(void)
{
	char private_key[string1_size_secp256k1];
	char public_key[string2_size_secp256k1];
	char sign_r[string1_size_secp256k1];
	char sign_s[string1_size_secp256k1];
	int check;

	private_string_secp256k1(private_key);
	public_string_secp256k1(private_key, public_key);
	sign_string_secp256k1(private_key, "Hello", 5, sign_r, sign_s);
	sign_string_secp256k1(private_key, "Hello", 5, sign_r, sign_s);
	check = verify_string_secp256k1(public_key, "Hello", 5, sign_r, sign_s);
	test(check, "string_secp256k1.1");

	Return;
}

static int test_string_secp256r1(void)
{
	char private_key[string1_size_secp256r1];
	char public_key[string2_size_secp256r1];
	char sign_r[string1_size_secp256r1];
	char sign_s[string1_size_secp256r1];
	int check;

	private_string_secp256r1(private_key);
	public_string_secp256r1(private_key, public_key);
	sign_string_secp256r1(private_key, "Hello", 5, sign_r, sign_s);
	sign_string_secp256r1(private_key, "Hello", 5, sign_r, sign_s);
	check = verify_string_secp256r1(public_key, "Hello", 5, sign_r, sign_s);
	test(check, "string_secp256r1.1");

	Return;
}

static int test_string_ed25519(void)
{
	char private_key[string1_size_ed25519];
	char public_key[string2_size_ed25519];
	char sign_r[string1_size_ed25519];
	char sign_s[string1_size_ed25519];
	int check;

	private_string_ed25519(private_key);
	public_string_ed25519(private_key, public_key);
	sign_string_ed25519(private_key, "Hello", 5, sign_r, sign_s);
	sign_string_ed25519(private_key, "Hello", 5, sign_r, sign_s);
	check = verify_string_ed25519(public_key, "Hello", 5, sign_r, sign_s);
	test(check, "string_ed25519.1");

	Return;
}

static int test_string_ed448(void)
{
	char private_key[string1_size_ed448];
	char public_key[string2_size_ed448];
	char sign_r[string1_size_ed448];
	char sign_s[string1_size_ed448];
	int check;

	private_string_ed448(private_key);
	public_string_ed448(private_key, public_key);
	sign_string_ed448(private_key, "Hello", 5, sign_r, sign_s);
	sign_string_ed448(private_key, "Hello", 5, sign_r, sign_s);
	check = verify_string_ed448(public_key, "Hello", 5, sign_r, sign_s);
	test(check, "string_ed448.1");

	Return;
}


/*
 *  verify
 */
static int test_verify_rfc8032_ed25519(void)
{
	const char *p, *r, *s;

	/* 1 */
	p = "d75a980182b10ab7d54bfed3c964073a"
		"0ee172f3daa62325af021a68f707511a";
	r = "e5564300c360ac729086e2cc806e828a"
		"84877f1eb8e5d974d873e06522490155";
	s = "5fb8821590a33bacc61e39701cf9b46b"
		"d25bf5f0595bbe24655141438e7a100b";
	test(verify_string_ed25519(p, "", 0, r, s), "verify-ed25519.1");

	/* 2 */
	p = "3d4017c3e843895a92b70aa74d1b7ebc"
		"9c982ccf2ec4968cc0cd55f12af4660c";
	r = "92a009a9f0d4cab8720e820b5f642540"
		"a2b27b5416503f8fb3762223ebdb69da";
	s = "085ac1e43e15996e458f3613d0f11d8c"
		"387b2eaeb4302aeeb00d291612bb0c00";
	test(verify_string_ed25519(p, "\x72", 1, r, s), "verify-ed25519.2");

	/* 3 */
	p = "fc51cd8e6218a1a38da47ed00230f058"
		"0816ed13ba3303ac5deb911548908025";
	r = "6291d657deec24024827e69c3abe01a3"
		"0ce548a284743a445e3680d7db5ac3ac";
	s = "18ff9b538d16f290ae67f760984dc659"
		"4a7c15e9716ed28dc027beceea1ec40a";
	test(verify_string_ed25519(p, "\xaf\x82", 2, r, s), "verify-ed25519.3");

	Return;
}

static int test_verify_rfc8032_ed448(void)
{
	const char *p, *r, *s;

	/* 1 */
	p = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
		"edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
	r = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
		"2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980";
	s = "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda"
		"8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
	test(verify_string_ed448(p, "", 0, r, s), "verify-ed448.1");

	/* 2 */
	p = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
		"6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
	r = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
		"2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd77980";
	s = "5e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905"
		"e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00";
	test(verify_string_ed448(p, "\x03", 1, r, s), "verify-ed448.2");

	/* 3 */
	p = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
		"6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
	r = "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2"
		"151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea00";
	s = "0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f57"
		"8c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00";
	memcpy(Elliptic_ed448_sha_context, "\x66\x6F\x6F", 3);
	Elliptic_ed448_sha_size = 3;
	test(verify_string_ed448(p, "\x03", 1, r, s), "verify-ed448.3");
	Elliptic_ed448_sha_size = 0;

	Return;
}


/*
 *  signature
 */
static int test_verify_signature(void)
{
	const char *p, *r, *s;

	p = "03FEEF09658067CFBE3BE8685DDCE8E9C03B4A397ADC4A0255CE0B29FC63BCDC9C";
	r = "7C7EDD22B0AED24D1B4A3826E228CE52EC897D52826D5912459238FC36008B86";
	s = "38C86C613A977CD5D1E024380FB56CDB924B0D972E903AB740F4E7F3A90F62BC";
	test(verify_string_secp256k1(p, "Hello", 5, r, s), "verify_signature.1");

	p = "03CD92CF7B1C9CE9858383806B8540D72FB022BE577E21DE02B8EAA27371DB7AF2";
	r = "FF6331919D62BFF9236113998250AB9079AA81C83085A27CC38A2CC0EEDDD98D";
	s = "1A374ADE37A61F6014C29C723C425BB3E6B519D517E16F66A46869F8EC535F89";
	test(verify_string_secp256r1(p, "Hello", 5, r, s), "verify_signature.2");

	p = "75AB16F53A060E7AF9A4B8ECEA3D4DEF058AED2C626FEC96D5505C4A7D922960";
	r = "285D61D0DAC982F09365DA699DFD10A7B1B3A4D29A8468655A71F49965D4CEE1";
	s = "A58118E7ECAE263034F4BA7EB57BEE8D639C9BAF5BDE6BE97F2F864B3A1A7606";
	test(verify_string_ed25519(p, "Hello", 5, r, s), "verify_signature.3");

	p = "99AFC3768EE41B96F208EBAF8627908690DC6A5AC64659F93D0A46C20"
		"92B61E84AD14DD03F7B3F146799C29F65682126D517B7E1EA57716E00";
	r = "DC38653AAD2F456132602EBC47571DABB56C36BA35D6965F820AFFB0F"
		"BE478439C7CF1D9EE7033792A23E80811CFAB07DC2B71DDEF526F6700";
	s = "0E11296ECFACEA4E5E9B795AC4048D711636BE468A99639F953ED1E94"
		"8A6351F51DE0AE167EB268012E9712F7D6ADD97E80BB36E291C2A2D00";
	test(verify_string_ed448(p, "Hello", 5, r, s), "verify_signature.4");

	Return;
}


/*
 *  test
 */
int test_encode(void)
{
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
	TestCall(test_sign_secp256k1);
	TestCall(test_sign_secp256r1);
	TestCall(test_sign_ed25519);
	TestCall(test_sign_ed448);
	TestCall(test_encode_string_secp256k1);
	TestCall(test_encode_string_secp256r1);
	TestCall(test_encode_string_ed25519);
	TestCall(test_encode_string_ed448);
	TestCall(test_string_secp256k1);
	TestCall(test_string_secp256r1);
	TestCall(test_string_ed25519);
	TestCall(test_string_ed448);
	TestCall(test_verify_rfc8032_ed25519);
	TestCall(test_verify_rfc8032_ed448);
	TestCall(test_verify_signature);

	return 0;
}

