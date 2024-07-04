#include "elliptic.h"
#include "fixed.h"
#include <string.h>

/*
 *  constant
 */
static const char *elliptic_secp256k1_parameter[] = {
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000007",
	"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
};

static const char *elliptic_secp256r1_parameter[] = {
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
	"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
};

static const char *elliptic_ed25519_parameter[] = {
	"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
	"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
	"52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
	"216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
	"6666666666666666666666666666666666666666666666666666666666666658",
	"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
};

static const char *elliptic_ed448_parameter[] = {
	("fffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
	 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	("01"),
	("fffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
	 "ffffffffffffffffffffffffffffffffffffffffffffffffffff6756"),
	("4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324"
	 "a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e"),
	("693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e"
	 "05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"),
	("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	 "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3")
};

typedef uint8_t elliptic_secp256k1_memory[elliptic_secp256k1_byte];
typedef elliptic_secp256k1_memory elliptic_secp256k1_point[3];
static elliptic_secp256k1_memory elliptic_secp256k1_p;
static elliptic_secp256k1_memory elliptic_secp256k1_a;
static elliptic_secp256k1_memory elliptic_secp256k1_b;
static elliptic_secp256k1_memory elliptic_secp256k1_x;
static elliptic_secp256k1_memory elliptic_secp256k1_y;
static elliptic_secp256k1_memory elliptic_secp256k1_n;
static elliptic_secp256k1_memory elliptic_secp256k1_p2;
static elliptic_secp256k1_memory elliptic_secp256k1_n2;
int Elliptic_secp256k1_h;
elliptic_secp256k1_point Elliptic_secp256k1_point_g;
elliptic_secp256k1_point Elliptic_secp256k1_point_o;
fixptr Elliptic_secp256k1_p = (fixptr)elliptic_secp256k1_p;
fixptr Elliptic_secp256k1_a = (fixptr)elliptic_secp256k1_a;
fixptr Elliptic_secp256k1_b = (fixptr)elliptic_secp256k1_b;
fixptr Elliptic_secp256k1_n = (fixptr)elliptic_secp256k1_n;
fixptr Elliptic_secp256k1_p2 = (fixptr)elliptic_secp256k1_p2;
fixptr Elliptic_secp256k1_n2 = (fixptr)elliptic_secp256k1_n2;
fixptr3 Elliptic_secp256k1_g;
fixptr3 Elliptic_secp256k1_o;

typedef uint8_t elliptic_secp256r1_memory[elliptic_secp256r1_byte];
typedef elliptic_secp256r1_memory elliptic_secp256r1_point[3];
static elliptic_secp256r1_memory elliptic_secp256r1_p;
static elliptic_secp256r1_memory elliptic_secp256r1_a;
static elliptic_secp256r1_memory elliptic_secp256r1_b;
static elliptic_secp256r1_memory elliptic_secp256r1_x;
static elliptic_secp256r1_memory elliptic_secp256r1_y;
static elliptic_secp256r1_memory elliptic_secp256r1_n;
static elliptic_secp256r1_memory elliptic_secp256r1_p2;
static elliptic_secp256r1_memory elliptic_secp256r1_n2;
int Elliptic_secp256r1_h;
elliptic_secp256r1_point Elliptic_secp256r1_point_g;
elliptic_secp256r1_point Elliptic_secp256r1_point_o;
fixptr Elliptic_secp256r1_p = (fixptr)elliptic_secp256r1_p;
fixptr Elliptic_secp256r1_a = (fixptr)elliptic_secp256r1_a;
fixptr Elliptic_secp256r1_b = (fixptr)elliptic_secp256r1_b;
fixptr Elliptic_secp256r1_n = (fixptr)elliptic_secp256r1_n;
fixptr Elliptic_secp256r1_p2 = (fixptr)elliptic_secp256r1_p2;
fixptr Elliptic_secp256r1_n2 = (fixptr)elliptic_secp256r1_n2;
fixptr3 Elliptic_secp256r1_g;
fixptr3 Elliptic_secp256r1_o;

typedef uint8_t elliptic_ed25519_memory[elliptic_ed25519_byte];
typedef elliptic_ed25519_memory elliptic_ed25519_point[4];
static elliptic_ed25519_memory elliptic_ed25519_p;
static elliptic_ed25519_memory elliptic_ed25519_a;
static elliptic_ed25519_memory elliptic_ed25519_d;
static elliptic_ed25519_memory elliptic_ed25519_x;
static elliptic_ed25519_memory elliptic_ed25519_y;
static elliptic_ed25519_memory elliptic_ed25519_n;
static elliptic_ed25519_memory elliptic_ed25519_p2;
static elliptic_ed25519_memory elliptic_ed25519_n2;
static elliptic_ed25519_memory elliptic_ed25519_d2;
int Elliptic_ed25519_h;
elliptic_ed25519_point Elliptic_ed25519_point_g;
elliptic_ed25519_point Elliptic_ed25519_point_o;
fixptr Elliptic_ed25519_p = (fixptr)elliptic_ed25519_p;
fixptr Elliptic_ed25519_a = (fixptr)elliptic_ed25519_a;
fixptr Elliptic_ed25519_d = (fixptr)elliptic_ed25519_d;
fixptr Elliptic_ed25519_n = (fixptr)elliptic_ed25519_n;
fixptr Elliptic_ed25519_p2 = (fixptr)elliptic_ed25519_p2;
fixptr Elliptic_ed25519_n2 = (fixptr)elliptic_ed25519_n2;
fixptr Elliptic_ed25519_d2 = (fixptr)elliptic_ed25519_d2;
fixptr4 Elliptic_ed25519_g;
fixptr4 Elliptic_ed25519_o;

typedef uint8_t elliptic_ed448_memory[elliptic_ed448_byte];
typedef elliptic_ed448_memory elliptic_ed448_point[3];
static elliptic_ed448_memory elliptic_ed448_p;
static elliptic_ed448_memory elliptic_ed448_a;
static elliptic_ed448_memory elliptic_ed448_d;
static elliptic_ed448_memory elliptic_ed448_x;
static elliptic_ed448_memory elliptic_ed448_y;
static elliptic_ed448_memory elliptic_ed448_n;
static elliptic_ed448_memory elliptic_ed448_p2;
static elliptic_ed448_memory elliptic_ed448_n2;
int Elliptic_ed448_h;
elliptic_ed448_point Elliptic_ed448_point_g;
elliptic_ed448_point Elliptic_ed448_point_o;
fixptr Elliptic_ed448_p = (fixptr)elliptic_ed448_p;
fixptr Elliptic_ed448_a = (fixptr)elliptic_ed448_a;
fixptr Elliptic_ed448_d = (fixptr)elliptic_ed448_d;
fixptr Elliptic_ed448_n = (fixptr)elliptic_ed448_n;
fixptr Elliptic_ed448_p2 = (fixptr)elliptic_ed448_p2;
fixptr Elliptic_ed448_n2 = (fixptr)elliptic_ed448_n2;
fixptr3 Elliptic_ed448_g;
fixptr3 Elliptic_ed448_o;
uint8_t Elliptic_ed448_sha_size;
uint8_t Elliptic_ed448_sha_context[256];


/*
 *  vector
 */
void push3_fixed(fixed s, fixptr3 r)
{
	int i;

	for (i = 0; i < 3; i++)
		r[i] = push1get_fixed(s);
}

void push4_fixed(fixed s, fixptr4 r)
{
	int i;

	for (i = 0; i < 4; i++)
		r[i] = push1get_fixed(s);
}

void pop3_fixed(fixed s)
{
	pop1n_fixed(s, 3);
}

void pop4_fixed(fixed s)
{
	pop1n_fixed(s, 4);
}

void setv3_fixed(fixed s, fixptr3 r, fixnum x, fixnum y, fixnum z)
{
	setv_fixptr(r[0], s->word1, x);
	setv_fixptr(r[1], s->word1, y);
	setv_fixptr(r[2], s->word1, z);
}

void setv4_fixed(fixed s, fixptr4 r, fixnum x, fixnum y, fixnum z, fixnum t)
{
	setv_fixptr(r[0], s->word1, x);
	setv_fixptr(r[1], s->word1, y);
	setv_fixptr(r[2], s->word1, z);
	setv_fixptr(r[3], s->word1, t);
}

void memcpy3_fixed(fixed s, fixptr3 dst, fixptr3 src)
{
	int i;

	if (dst == src)
		return;
	for (i = 0; i < 3; i++)
		memcpy_fixptr(dst[i], src[i], s->word1);
}

void memcpy4_fixed(fixed s, fixptr4 dst, fixptr4 src)
{
	int i;

	if (dst == src)
		return;
	for (i = 0; i < 4; i++)
		memcpy_fixptr(dst[i], src[i], s->word1);
}


/*
 *  operator
 */

/* remloop */
static void remloop_elliptic_curve(fixptr r, fixptr curve_p, fixsize word1)
{
	fixnum ignore;

	while (compare_fixptr(r, word1, curve_p, word1) >= 0)
		sub_fixptr(r, curve_p, r, word1, &ignore);
}


/* rem1 */
void rem1_elliptic_curve(fixed s, fixptr x1, fixptr r1, fixptr curve)
{
	int check;

	check = compare_fixptr(x1, s->word1, curve, s->word1);
	if (check < 0)
		memcpy_fixptr(r1, x1, s->word1);
	else
		rem1_fixptr(s, x1, curve, r1);
}


/* rem2 */
void rem2_elliptic_curve(fixed s, fixptr x2, fixptr r1, fixptr curve_p)
{
	int check;

	check = compare_fixptr(x2, s->word2, curve_p, s->word1);
	if (check < 0)
		memcpy_fixptr(r1, x2, s->word1);
	else
		rem_fixptr(s, x2, curve_p, r1);
}

void rem2_elliptic_secp256k1(fixed s, fixptr x2, fixptr r1)
{
	rem2_elliptic_curve(s, x2, r1, Elliptic_secp256k1_p);
}

void rem2_elliptic_secp256r1(fixed s, fixptr x2, fixptr r1)
{
	rem2_elliptic_curve(s, x2, r1, Elliptic_secp256r1_p);
}

void rem2_elliptic_ed25519(fixed s, fixptr x2, fixptr r1)
{
	rem2_elliptic_curve(s, x2, r1, Elliptic_ed25519_p);
}

void rem2_elliptic_ed448(fixed s, fixptr x2, fixptr r1)
{
	rem2_elliptic_curve(s, x2, r1, Elliptic_ed448_p);
}


/* add */
void add_elliptic_curve(fixptr x, fixptr y, fixptr r, fixptr curve_p, fixsize word1)
{
	fixnum carry;

	add_fixptr(x, y, r, word1, &carry);
	if (carry)
		sub_fixptr(r, curve_p, r, word1, &carry);
	else
		remloop_elliptic_curve(r, curve_p, word1);
}

void add_elliptic_secp256k1(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	add_elliptic_curve(x, y, r, (fixptr)Elliptic_secp256k1_p, word1);
}

void add_elliptic_secp256r1(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	add_elliptic_curve(x, y, r, (fixptr)Elliptic_secp256r1_p, word1);
}

void add_elliptic_ed25519(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	add_elliptic_curve(x, y, r, (fixptr)Elliptic_ed25519_p, word1);
}

void add_elliptic_ed448(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	add_elliptic_curve(x, y, r, (fixptr)Elliptic_ed448_p, word1);
}


/* dbl */
void dbl_elliptic_curve(fixptr x, fixptr r, fixptr curve_p, fixsize word1)
{
	fixnum carry;

	add_fixptr(x, x, r, word1, &carry);
	if (carry)
		sub_fixptr(r, curve_p, r, word1, &carry);
	else
		remloop_elliptic_curve(r, curve_p, word1);
}

void dbl_elliptic_secp256k1(fixptr x, fixptr r, fixsize word1)
{
	dbl_elliptic_curve(x, r, (fixptr)Elliptic_secp256k1_p, word1);
}

void dbl_elliptic_secp256r1(fixptr x, fixptr r, fixsize word1)
{
	dbl_elliptic_curve(x, r, (fixptr)Elliptic_secp256r1_p, word1);
}

void dbl_elliptic_ed25519(fixptr x, fixptr r, fixsize word1)
{
	dbl_elliptic_curve(x, r, (fixptr)Elliptic_ed25519_p, word1);
}

void dbl_elliptic_ed448(fixptr x, fixptr r, fixsize word1)
{
	dbl_elliptic_curve(x, r, (fixptr)Elliptic_ed448_p, word1);
}


/* sub */
void sub_elliptic_curve(fixptr x, fixptr y, fixptr r, fixptr curve_p, fixsize word1)
{
	fixnum carry;

	sub_fixptr(x, y, r, word1, &carry);
	if (carry)
		add_fixptr(r, curve_p, r, word1, &carry);
	else
		remloop_elliptic_curve(r, curve_p, word1);
}
void sub_elliptic_secp256k1(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	sub_elliptic_curve(x, y, r, (fixptr)Elliptic_secp256k1_p, word1);
}

void sub_elliptic_secp256r1(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	sub_elliptic_curve(x, y, r, (fixptr)Elliptic_secp256r1_p, word1);
}

void sub_elliptic_ed25519(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	sub_elliptic_curve(x, y, r, (fixptr)Elliptic_ed25519_p, word1);
}

void sub_elliptic_ed448(fixptr x, fixptr y, fixptr r, fixsize word1)
{
	sub_elliptic_curve(x, y, r, (fixptr)Elliptic_ed448_p, word1);
}


/*
 *  print3, print4
 */
static void println3_fixptr_axis_t(fixed s,
		fixptr3 r, FILE *file, unsigned radix, int axis_t)
{
	/* X */
	push1ptr_fixed(s, r[0]);
	printf("X: ");
	println1_fixed(s, 0, file, radix);
	pop1_fixed(s);
	/* Y */
	push1ptr_fixed(s, r[1]);
	printf("Y: ");
	println1_fixed(s, 0, file, radix);
	pop1_fixed(s);
	/* Z */
	push1ptr_fixed(s, r[2]);
	printf("Z: ");
	println1_fixed(s, 0, file, radix);
	pop1_fixed(s);
	/* T */
	if (axis_t) {
		push1ptr_fixed(s, r[3]);
		printf("T: ");
		println1_fixed(s, 0, file, radix);
		pop1_fixed(s);
	}
}

void println3_fixptr(fixed s, fixptr3 r, FILE *file, unsigned radix)
{
	println3_fixptr_axis_t(s, r, file, radix, 0);
}

void println4_fixptr(fixed s, fixptr3 r, FILE *file, unsigned radix)
{
	println3_fixptr_axis_t(s, r, file, radix, 1);
}


/*
 *  string-integer
 */
static uint8_t string_integer_char_elliptic(char c, int *errorp)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	if ('a' <= c && c <= 'f')
		return c - 'a' + 0x0a;
	if ('A' <= c && c <= 'F')
		return c - 'A' + 0x0A;

	/* error */
	*errorp = 1;
	return 0;
}

int string_integer_elliptic(const char *x, void *p, int size, int reverse)
{
	uint8_t *r, c1, c2;
	int i, k, u, errorp;

	r = (uint8_t *)p;
	errorp = 0;
	for (i = 0; i < size; i++) {
		k = i * 2;
		/* c1 */
		c1 = x[k + 0];
		if (c1 == 0)
			break;
		c1 = string_integer_char_elliptic(c1, &errorp);
		if (errorp)
			break;
		/* c2 */
		c2 = x[k + 1];
		if (c2 == 0)
			break;
		c2 = string_integer_char_elliptic(c2, &errorp);
		if (errorp)
			break;
		/* set */
		u = reverse? (size - i - 1): i;
		r[u] = (c1 << 4U) | c2;
	}
	for (; i < size; i++) {
		u = reverse? (size - i - 1): i;
		r[u] = 0;
	}

	return errorp;
}

static char integer_string_byte_elliptic(uint8_t c)
{
	if (0 <= c && c <= 9)
		return c + '0';
	if (0x0A <= c && c <= 0x0F)
		return c - 0x0A + 'A';
	/* error */
	return 0;
}

void integer_string_elliptic(const void *p, int size, char *x, int reverse)
{
	const uint8_t *r;
	uint8_t v;
	int i, k, u;

	r = (const uint8_t *)p;
	for (i = 0; i < size; i++) {
		k = i * 2;
		u = reverse? (size - i - 1): i;
		v = r[u];
		x[k + 0] = integer_string_byte_elliptic(v >> 4U);
		x[k + 1] = integer_string_byte_elliptic(v & 0x0F);
	}
	x[size * 2] = '\0';
}


/*
 *  make-fixed
 */
fixed make_secp256k1_fixed(void)
{
	return make_fixed(elliptic_secp256k1_bit, 64);
}

fixed make_secp256r1_fixed(void)
{
	return make_fixed(elliptic_secp256r1_bit, 64);
}

fixed make_ed25519_fixed(void)
{
	return make_fixed(elliptic_ed25519_bit, 64);
}

fixed make_ed448_fixed(void)
{
	return make_fixed(elliptic_ed448_bit, 64);
}


/*
 *  parameter_g
 */
static void init_elliptic_secp256k1_g(fixed s)
{
	fixptr x, y, z, *g;

	x = (fixptr)&Elliptic_secp256k1_point_g[0];
	y = (fixptr)&Elliptic_secp256k1_point_g[1];
	z = (fixptr)&Elliptic_secp256k1_point_g[2];
	g = Elliptic_secp256k1_g;
	/* point */
	memcpy_fixptr(x, (fixptr)elliptic_secp256k1_x, s->word1);
	memcpy_fixptr(y, (fixptr)elliptic_secp256k1_y, s->word1);
	setv_fixptr(z, s->word1, 1);
	/* g */
	setp3_fixptr(g, x, y, z);
}

static void init_elliptic_secp256r1_g(fixed s)
{
	fixptr x, y, z, *g;

	x = (fixptr)&Elliptic_secp256r1_point_g[0];
	y = (fixptr)&Elliptic_secp256r1_point_g[1];
	z = (fixptr)&Elliptic_secp256r1_point_g[2];
	g = Elliptic_secp256r1_g;
	/* point */
	memcpy_fixptr(x, (fixptr)elliptic_secp256r1_x, s->word1);
	memcpy_fixptr(y, (fixptr)elliptic_secp256r1_y, s->word1);
	setv_fixptr(z, s->word1, 1);
	/* g */
	setp3_fixptr(g, x, y, z);
}

static void init_elliptic_ed25519_g(fixed s)
{
	fixptr x, y, z, t, w, *g;

	x = (fixptr)&Elliptic_ed25519_point_g[0];
	y = (fixptr)&Elliptic_ed25519_point_g[1];
	z = (fixptr)&Elliptic_ed25519_point_g[2];
	t = (fixptr)&Elliptic_ed25519_point_g[3];
	g = Elliptic_ed25519_g;
	/* point */
	memcpy_fixptr(x, (fixptr)elliptic_ed25519_x, s->word1);
	memcpy_fixptr(y, (fixptr)elliptic_ed25519_y, s->word1);
	setv_fixptr(z, s->word1, 1);
	/* t = x*y */
	w = push2get_fixed(s);
	mul_fixptr(x, y, s->word1, w, s->word2);
	rem2_elliptic_ed25519(s, w, t);
	pop2_fixed(s);
	/* g */
	setp4_fixptr(g, x, y, z, t);
}

static void init_elliptic_ed448_g(fixed s)
{
	fixptr x, y, z, *g;

	x = (fixptr)&Elliptic_ed448_point_g[0];
	y = (fixptr)&Elliptic_ed448_point_g[1];
	z = (fixptr)&Elliptic_ed448_point_g[2];
	g = Elliptic_ed448_g;
	/* point */
	memcpy_fixptr(x, (fixptr)elliptic_ed448_x, s->word1);
	memcpy_fixptr(y, (fixptr)elliptic_ed448_y, s->word1);
	setv_fixptr(z, s->word1, 1);
	/* g */
	setp3_fixptr(g, x, y, z);
}


/*
 *  parameter_o
 */
static void init_elliptic_secp256k1_o(fixed s)
{
	fixptr x, y, z, *v;

	x = (fixptr)&Elliptic_secp256k1_point_o[0];
	y = (fixptr)&Elliptic_secp256k1_point_o[1];
	z = (fixptr)&Elliptic_secp256k1_point_o[2];
	v = Elliptic_secp256k1_o;
	setp3_fixptr(v, x, y, z);
	setv3_fixed(s, v, 0, 0, 0);
}

static void init_elliptic_secp256r1_o(fixed s)
{
	fixptr x, y, z, *v;

	x = (fixptr)&Elliptic_secp256r1_point_o[0];
	y = (fixptr)&Elliptic_secp256r1_point_o[1];
	z = (fixptr)&Elliptic_secp256r1_point_o[2];
	v = Elliptic_secp256r1_o;
	setp3_fixptr(v, x, y, z);
	setv3_fixed(s, v, 0, 0, 0);
}

static void init_elliptic_ed25519_o(fixed s)
{
	fixptr x, y, z, t, *v;

	x = (fixptr)&Elliptic_ed25519_point_o[0];
	y = (fixptr)&Elliptic_ed25519_point_o[1];
	z = (fixptr)&Elliptic_ed25519_point_o[2];
	t = (fixptr)&Elliptic_ed25519_point_o[3];
	v = Elliptic_ed25519_o;
	setp4_fixptr(v, x, y, z, t);
	setv4_fixed(s, v, 0, 1, 1, 0);
}

static void init_elliptic_ed448_o(fixed s)
{
	fixptr x, y, z, *v;

	x = (fixptr)&Elliptic_ed448_point_o[0];
	y = (fixptr)&Elliptic_ed448_point_o[1];
	z = (fixptr)&Elliptic_ed448_point_o[2];
	v = Elliptic_ed448_o;
	setp3_fixptr(v, x, y, z);
	setv3_fixed(s, v, 0, 1, 1);
}


/*
 *  init_elliptic
 */
#define init_elliptic_macro(s, x, y, z) { \
	read1p_fixed(s, elliptic_##x##_parameter[z], 16); \
	memcpy((void *)elliptic_##x##_##y, top1_fixed(s), elliptic_##x##_byte); \
	pop1_fixed(s); \
}

#define init_elliptic_stack			32

static void init_elliptic_minus2(fixed s, fixptr curve_p, fixptr curve_p2)
{
	fixnum ignore;

	memcpy_fixptr(curve_p2, curve_p, s->word1);
	subv_fixptr(curve_p2, s->word1, 2, &ignore);
}

#define init_elliptic_curve_p2(s, curve) { \
	init_elliptic_minus2(s, \
			(fixptr)elliptic_##curve##_p, \
			(fixptr)elliptic_##curve##_p2); \
}

static void init_elliptic_secp256k1_p2(fixed s)
{
	init_elliptic_curve_p2(s, secp256k1);
}

static void init_elliptic_secp256r1_p2(fixed s)
{
	init_elliptic_curve_p2(s, secp256r1);
}

static void init_elliptic_ed25519_p2(fixed s)
{
	init_elliptic_curve_p2(s, ed25519);
}

static void init_elliptic_ed448_p2(fixed s)
{
	init_elliptic_curve_p2(s, ed448);
}

#define init_elliptic_curve_n2(s, curve) { \
	init_elliptic_minus2(s, \
			(fixptr)elliptic_##curve##_n, \
			(fixptr)elliptic_##curve##_n2); \
}

static void init_elliptic_secp256k1_n2(fixed s)
{
	init_elliptic_curve_n2(s, secp256k1);
}

static void init_elliptic_secp256r1_n2(fixed s)
{
	init_elliptic_curve_n2(s, secp256r1);
}

static void init_elliptic_ed25519_n2(fixed s)
{
	init_elliptic_curve_n2(s, ed25519);
}

static void init_elliptic_ed448_n2(fixed s)
{
	init_elliptic_curve_n2(s, ed448);
}

void init_elliptic_secp256k1(void)
{
	fixed s;

	s = make_fixed(elliptic_secp256k1_bit, init_elliptic_stack);
	init_elliptic_macro(s, secp256k1, p, 0);
	init_elliptic_macro(s, secp256k1, a, 1);
	init_elliptic_macro(s, secp256k1, b, 2);
	init_elliptic_macro(s, secp256k1, x, 3);
	init_elliptic_macro(s, secp256k1, y, 4);
	init_elliptic_macro(s, secp256k1, n, 5);
	Elliptic_secp256k1_h = 0x01;
	init_elliptic_secp256k1_p2(s);
	init_elliptic_secp256k1_n2(s);
	init_elliptic_secp256k1_g(s);
	init_elliptic_secp256k1_o(s);
	free_fixed(s);
}

void init_elliptic_secp256r1(void)
{
	fixed s;

	s = make_fixed(elliptic_secp256r1_bit, init_elliptic_stack);
	init_elliptic_macro(s, secp256r1, p, 0);
	init_elliptic_macro(s, secp256r1, a, 1);
	init_elliptic_macro(s, secp256r1, b, 2);
	init_elliptic_macro(s, secp256r1, x, 3);
	init_elliptic_macro(s, secp256r1, y, 4);
	init_elliptic_macro(s, secp256r1, n, 5);
	Elliptic_secp256r1_h = 0x01;
	init_elliptic_secp256r1_p2(s);
	init_elliptic_secp256r1_n2(s);
	init_elliptic_secp256r1_g(s);
	init_elliptic_secp256r1_o(s);
	free_fixed(s);
}

static void init_elliptic_ed25519_d2(fixed s)
{
	fixptr curve_d, curve_d2;

	curve_d = (fixptr)elliptic_ed25519_d;
	curve_d2 = (fixptr)elliptic_ed25519_d2;
	dbl_elliptic_ed25519(curve_d, curve_d2, s->word1);
}

void init_elliptic_ed25519(void)
{
	fixed s;

	s = make_fixed(elliptic_ed25519_bit, init_elliptic_stack);
	init_elliptic_macro(s, ed25519, p, 0);
	init_elliptic_macro(s, ed25519, a, 1);
	init_elliptic_macro(s, ed25519, d, 2);
	init_elliptic_macro(s, ed25519, x, 3);
	init_elliptic_macro(s, ed25519, y, 4);
	init_elliptic_macro(s, ed25519, n, 5);
	Elliptic_ed25519_h = 0x08;
	init_elliptic_ed25519_p2(s);
	init_elliptic_ed25519_n2(s);
	init_elliptic_ed25519_d2(s);
	init_elliptic_ed25519_g(s);
	init_elliptic_ed25519_o(s);
	free_fixed(s);
}

void init_elliptic_ed448(void)
{
	fixed s;

	s = make_fixed(elliptic_ed448_bit, init_elliptic_stack);
	init_elliptic_macro(s, ed448, p, 0);
	init_elliptic_macro(s, ed448, a, 1);
	init_elliptic_macro(s, ed448, d, 2);
	init_elliptic_macro(s, ed448, x, 3);
	init_elliptic_macro(s, ed448, y, 4);
	init_elliptic_macro(s, ed448, n, 5);
	Elliptic_ed448_h = 0x04;
	Elliptic_ed448_sha_size = 0;
	init_elliptic_ed448_p2(s);
	init_elliptic_ed448_n2(s);
	init_elliptic_ed448_g(s);
	init_elliptic_ed448_o(s);
	free_fixed(s);
}

void init_elliptic(void)
{
	init_elliptic_secp256k1();
	init_elliptic_secp256r1();
	init_elliptic_ed25519();
	init_elliptic_ed448();
}

