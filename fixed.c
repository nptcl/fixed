#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fixed.h"

#define FIXED_DIVFULL				(1ULL << (FIXED_FULLBIT - 1ULL))
#define FIXED_HIGH(x)				((x) >> FIXED_HALFBIT)
#define FIXED_LOW(x)				(FIXED_HALF & (x))
#define FIXED_HIGHLOW(high,low)		(((high) << FIXED_HALFBIT) | (low))
#define FIXED_RADIX(x)				(2 <= (x) && (x) <= 36)

/***********************************************************************
 *  fixnum
 ***********************************************************************/
/* add */
static inline void add4_fixnum(fixnum a, fixnum b, fixnum *r, fixnum *c)
{
	fixnum x;

	x = FIXED_FULL - b;
	if (x < a) {
		*r = a - x - 1;
		*c = 1;
	}
	else {
		*r = a + b;
		*c = 0;
	}
}

static inline void add2_fixnum(fixnum *r, fixnum *c)
{
	add4_fixnum(*r, *c, r, c);
}

static inline void add3_carry_fixnum(fixnum *r, fixnum x, fixnum *c)
{
	add2_fixnum(r, &x);
	add2_fixnum(r, c);
	*c += x;
}


/* sub */
static inline void sub4_fixnum(fixnum a, fixnum b, fixnum *r, fixnum *c)
{
	fixnum x;

	if (a < b) {
		x = FIXED_FULL - b;
		*r = x + a + 1;
		*c = 1;
	}
	else {
		*r = a - b;
		*c = 0;
	}
}

static inline void sub2_fixnum(fixnum *r, fixnum *c)
{
	sub4_fixnum(*r, *c, r, c);
}

static inline void sub3_carry_fixnum(fixnum *r, fixnum x, fixnum *c)
{
	sub2_fixnum(r, &x);
	sub2_fixnum(r, c);
	*c += x;
}


/* mul */
static void mul4_fixnum(fixnum a, fixnum b, fixnum *r, fixnum *c)
{
	/*             a2 a1
	 *  [*]        b2 b1
	 *  ----------------
	 *          x3 x2 x1
	 *  [+]  y3 y2 y1
	 *  ----------------
	 *       c2 c1 r2 r1
	 */
	fixnum a1, a2, b1, b2, x1, x2, x3, y1, y2, y3;

	if (a == 0 || b == 0) {
		*r = 0;
		*c = 0;
		return;
	}
	if (a == 1) {
		*r = b;
		*c = 0;
		return;
	}
	if (b == 1) {
		*r = a;
		*c = 0;
		return;
	}

	a2 = FIXED_HIGH(a);
	b2 = FIXED_HIGH(b);
	if (a2 == 0 && b2 == 0) {
		*r = a * b;
		*c = 0;
		return;
	}
	a1 = FIXED_LOW(a);
	b1 = FIXED_LOW(b);
	if (b2 == 0) {
		x1 = a1 * b1;
		x2 = a2 * b1;
		x2 += FIXED_HIGH(x1);
		x3 = FIXED_HIGH(x2);
		x2 = FIXED_LOW(x2);
		x1 = FIXED_LOW(x1);
		*r = FIXED_HIGHLOW(x2, x1);
		*c = x3;
		return;
	}
	if (a2 == 0) {
		x1 = a1 * b1;
		x2 = a1 * b2;
		x2 += FIXED_HIGH(x1);
		x3 = FIXED_HIGH(x2);
		x2 = FIXED_LOW(x2);
		x1 = FIXED_LOW(x1);
		*r = FIXED_HIGHLOW(x2, x1);
		*c = x3;
		return;
	}

	/* first */
	x1 = a1 * b1;
	x2 = a2 * b1;
	x2 += FIXED_HIGH(x1);
	x3 = FIXED_HIGH(x2);
	x2 = FIXED_LOW(x2);
	x1 = FIXED_LOW(x1);

	/* second */
	y1 = a1 * b2;
	y2 = a2 * b2;
	y2 += FIXED_HIGH(y1);
	y3 = FIXED_HIGH(y2);
	y2 = FIXED_LOW(y2);
	y1 = FIXED_LOW(y1);

	/*          x3 x2 x1
	 *  [+]  y3 y2 y1
	 *  ----------------
	 *       c2 c1 r2 r1
	 */
	x2 += y1;
	*r = FIXED_HIGHLOW(FIXED_LOW(x2), x1);
	x3 += y2 + FIXED_HIGH(x2);
	*c = FIXED_HIGHLOW(y3 + FIXED_HIGH(x3), FIXED_LOW(x3));
}

static inline void mul3_carry_fixnum(fixnum *r, fixnum x, fixnum *c)
{
	mul4_fixnum(*r, x, r, &x);
	add2_fixnum(r, c);
	*c += x;
}

static inline void mul4_carry_fixnum(fixnum *r, fixnum x, fixnum y, fixnum *c)
{
	mul4_fixnum(x, y, r, &y);
	add2_fixnum(r, c);
	*c += y;
}


/* div */
static void divhalf_fixnum(fixnum *high, fixnum *low, fixnum denom, fixnum *carry)
{
	fixnum v1, v2, n3, n4, a2, a3, a4, a;

	v1 = *high;
	v2 = *low;
	n3 = FIXED_HIGH(v2);
	n4 = FIXED_LOW(v2);

	a2 = v1 / denom;
	a = v1 % denom;
	v1 = FIXED_HIGHLOW(a, n3);
	a3 = v1 / denom;
	a = v1 % denom;
	v1 = FIXED_HIGHLOW(a, n4);
	a4 = v1 / denom;

	*high = a2;
	*low = FIXED_HIGHLOW(a3, a4);
	*carry = v1 % denom;
}

static void divloop_fixnum(fixnum m1, fixnum denom,
		fixnum *quot, fixnum *rem,
		fixnum n1, fixnum n2, fixnum n3)
{
	/*
	 *  a: [n1 n2 n3] / denom
	 */
	fixnum a, nn, v1, v2, v3;

	/* nn = [n2 n3] */
	nn = FIXED_HIGHLOW(n2, n3);
	if (n1 == 0 && nn < denom) {
		*quot = 0;
		*rem = nn;
		return;
	}
	/* a = [n1 n2] / m1; */
	a = FIXED_HIGHLOW(n1, n2) / m1;
	/* a * denom = [v1 v2 v2] */
	v1 = 0;
	mul4_carry_fixnum(&v2, a, denom, &v1);
	/* [n1 n2 n3] - [v1 v2 v2] */
	v3 = 0;
	sub3_carry_fixnum(&nn, v2, &v3);
	sub3_carry_fixnum(&n1, v1, &v3);
	while (v3) {
		a--;
		v3 = 0;
		add3_carry_fixnum(&nn, denom, &v3);
		v3 = (v3 == 0);
	}
	*quot = a;
	*rem = nn;
}

static int getshift_fixnum(fixnum *value)
{
	int count;

#ifdef FIXED_DEBUG
	if (*value == 0) {
		fprintf(stderr, "getshift_fixnum error.\n");
		exit(1);
	}
#endif
	for (count = 0; *value < FIXED_DIVFULL; count++)
		*value <<= 1;

	return count;
}

static void divfull_fixnum(fixnum *high, fixnum *low, fixnum denom, fixnum *carry)
{
	int shift, nshift;
	fixnum m1, a2, a3, a4;
	fixnum nn, s1, s2;

	/* shift denom */
	shift = getshift_fixnum(&denom);
	m1 = FIXED_HIGH(denom);
	s1 = *high;
	s2 = *low;
	if (shift == 0) {
		/* a2: [n1 n2] / denom */
		if (s1 < denom) {
			a2 = 0;
			nn = s1;
		}
		else {
			a2 = s1 / denom;
			nn = s1 % denom;
		}
		shift = 0;
		goto second;
	}

	/* shift */
	nshift = FIXED_FULLBIT - shift;
	nn = s1 >> nshift;
	s1 = (s1 << shift) | (s2 >> nshift);
	s2 = s2 << shift;

	/* a2: [n0 n1 n2] / denom */
	divloop_fixnum(m1, denom, &a2, &nn, nn, FIXED_HIGH(s1), FIXED_LOW(s1));
second:
	/* a3: [n1 n2 n3] / denom */
	divloop_fixnum(m1, denom, &a3, &nn, FIXED_HIGH(nn), FIXED_LOW(nn), FIXED_HIGH(s2));
	/* a4: [n2 n3 n4] / denom */
	divloop_fixnum(m1, denom, &a4, &nn, FIXED_HIGH(nn), FIXED_LOW(nn), FIXED_LOW(s2));

	/* result */
	*high = a2;
	*low = FIXED_HIGHLOW(a3, a4);
	*carry = nn >> shift;
}

static int div_fixnum(fixnum *high, fixnum *low, fixnum denom, fixnum *carry)
{
	/*
	 *  1. ----/00  -> error
	 *  2. aabb/01  -> aabb
	 *  3. 0000/--  -> 0
	 *  4. 00bb/cc  -> b/c
	 *  5. aabb/-c  -> divhalf(aabb/-c)
	 *  6. aabb/cc  -> divfull(aabb/cc)
	 */
	fixnum value;

	/*  1. ----/00  -> error */
	if (denom == 0) {
		*high = *low = *carry = 0;
		return 1;  /* Error */
	}

	/*  2. aabb/01  -> aabb */
	if (denom == 1) {
		*carry = 0;
		return 0;
	}

	/*  5. aabb/-c  -> divhalf(aabb/-c) */
	/*  6. aabb/cc  -> divfull(aabb/cc) */
	if (*high) {
		if (FIXED_HIGH(denom))
			divfull_fixnum(high, low, denom, carry);
		else
			divhalf_fixnum(high, low, denom, carry);
		return 0;
	}

	/*  3. 0000/--  -> 0 */
	value = *low;
	if (value == 0) {
		*carry = 0;
		return 0;
	}

	/*  4. 00bb/cc  -> b/c */
	*low = value / denom;
	*carry = value % denom;
	return 0;
}


/***********************************************************************
 *  fixptr
 ***********************************************************************/
void memcpy_fixdebug(fixptr x, fixptr y, fixsize z)
{
	memcpy(x, y, z * sizeof(fixnum));
}

void memmove_fixdebug(fixptr x, fixptr y, fixsize z)
{
	memmove(x, y, z * sizeof(fixnum));
}

int memcmp_fixdebug(fixptr x, fixptr y, fixsize z)
{
	return memcmp(x, y, z * sizeof(fixnum));
}

void memset_fixdebug(fixptr x, int y, fixsize z)
{
	memset(x, y, z * sizeof(fixnum));
}

void memzero_fixdebug(fixptr x, fixsize z)
{
	memset_fixdebug(x, 0, z);
}

fixsize size_press_fixptr(fixptr x, fixsize size)
{
	fixsize i;

	for (;;) {
		if (size == 0)
			return 1;
		i = size - 1;
		if (x[i])
			break;
		size = i;
	}

	return size;
}

int eqlv_fixptr(fixptr x, fixsize size, fixnum v)
{
	fixnum n;

	if (! getv_fixptr(x, size, &n))
		return 0;

	return v == n;
}

int zerop_fixptr(fixptr x, fixsize size)
{
	return eqlv_fixptr(x, size, 0);
}

int compare_fixnum_fixptr(fixptr x, fixsize word, fixnum y)
{
	fixnum v;

	/* zero */
	word = size_press_fixptr(x, word);
	if (word == 0) {
		if (y == 0)
			return 0;
		else
			return -1;
	}

	/* single */
	v = x[0];
	if (word == 1) {
		if (v < y)
			return -1;
		else if (v > y)
			return 1;
		else
			return 0;
	}

	/* multiple */
	return 1;
}

int compare_fixptr(fixptr x, fixsize size1, fixptr y, fixsize size2)
{
	fixsize i;

	/* left */
	if (size1 < size2) {
		for (i = size1; i < size2; i++) {
			if (y[i])
				return -1;
		}
	}

	/* right */
	if (size1 > size2) {
		for (i = size2; i < size1; i++) {
			if (x[i])
				return 1;
		}
		size1 = size2;
	}

	/* equal */
	if (size1 == 0)
		return 0;
	i = size1 - 1;
	for (;;) {
		if (x[i] > y[i])
			return 1;
		if (x[i] < y[i])
			return -1;
		if (i == 0)
			break;
		i--;
	}

	return 0;
}

void addv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry)
{
	fixsize i;

	for (i = 0; v && i < size; i++)
		add2_fixnum(p + i, &v);
	*carry = v;
}

void subv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry)
{
	fixsize i;

	for (i = 0; v && i < size; i++)
		sub2_fixnum(p + i, &v);
	*carry = v;
}

void mulv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry)
{
	fixsize i;

	*carry = 0;
	for (i = 0; i < size; i++)
		mul3_carry_fixnum(p + i, v, carry);
}

void add_fixptr(fixptr x, fixptr y, fixptr r, fixsize size, fixnum *carry)
{
	fixnum a, b, c;
	fixsize i;

	c = 0;
	for (i = 0; i < size; i++) {
		add4_fixnum(x[i], y[i], &a, &b);
		if (b) {
			r[i] = a + c;
			c = 1;
		}
		else if (c) {
			add4_fixnum(a, 1, &a, &c);
			r[i] = a;
		}
		else {
			r[i] = a;
		}
	}
	*carry = c;
}

void sub2_fixptr(fixptr a, fixsize size1, fixptr b, fixsize size2,
		fixptr r, fixsize size3, fixnum *carry)
{
	fixnum x, y, c;
	fixsize i;

	c = 0;
	for (i = 0; i < size3; i++) {
		x = (i < size1)? a[i]: 0;
		y = (i < size1)? b[i]: 0;
		sub3_carry_fixnum(&x, y, &c);
		r[i] = x;
	}
	*carry = c;
}

void sub_fixptr(fixptr x, fixptr y, fixptr r, fixsize size, fixnum *carry)
{
	fixnum a, b, c;
	fixsize i;

	c = 0;
	for (i = 0; i < size; i++) {
		sub4_fixnum(x[i], y[i], &a, &b);
		if (b) {
			r[i] = a - c;
			c = 1;
		}
		else if (c) {
			sub4_fixnum(a, 1, &a, &c);
			r[i] = a;
		}
		else {
			r[i] = a;
		}
	}
	*carry = c;
}

void shiftl_fixptr(fixptr x, fixsize size, fixsize shift)
{
	fixsize n, p, q, i, k;
	fixnum a, b;

	/* no shift */
	if (shift == 0)
		return;

	/* zero */
	if (zerop_fixptr(x, size))
		return;

	/* all shift */
	n = shift / FIXED_FULLBIT;
	p = shift % FIXED_FULLBIT;
	if (size <= n) {
		memzero_fixptr(x, size);
		return;
	}

	/* byte shift */
	if (p == 0) {
		memmove_fixptr(x + n, x, size - n);
		memzero_fixptr(x, n);
		return;
	}

	/* byte + bit */
	q = FIXED_FULLBIT - p;
	i = size - 1;
	k = i - n;
	a = x[k];
	while (k) {
		k--;
		b = x[k];
		x[i] = (a << p) | (b >> q);
		i--;
		a = b;
	}
	x[i] = a << p;
	if (i)
		memzero_fixptr(x, i);
}

void shiftr_fixptr(fixptr x, fixsize size, fixsize shift)
{
	fixsize n, diff, p, q, i, k;
	fixnum a, b;

	/* no shift */
	if (shift == 0)
		return;

	/* zero */
	if (zerop_fixptr(x, size))
		return;

	/* all shift */
	n = shift / FIXED_FULLBIT;
	p = shift % FIXED_FULLBIT;
	if (size <= n) {
		memzero_fixptr(x, size);
		return;
	}

	/* byte shift */
	if (p == 0) {
		diff = size - n;
		memmove_fixptr(x, x + n, diff);
		memzero_fixptr(x + diff, n);
		return;
	}

	/* byte + bit */
	q = FIXED_FULLBIT - p;
	i = 0;
	k = n;
	a = x[k];
	k++;
	while (k < size) {
		b = x[k];
		k++;
		x[i] = (a >> p) | (b << q);
		i++;
		a = b;
	}
	x[i] = a >> p;
	i++;
	if (i < size)
		memzero_fixptr(x + i, size - i);
}

/* rotate */
static void rotatel1_byte_fixptr(fixptr r, fixsize w, fixsize n)
{
	fixsize i, w1;
	fixnum a;

	w1 = w - 1;
	if (n < (w / 2)) {
		/* left */
		for (i = 0; i < n; i++) {
			a = r[w1];
			memmove_fixptr(r + 1, r, w1);
			r[0] = a;
		}
	}
	else {
		/* right */
		n = w - n;
		for (i = 0; i < n; i++) {
			a = r[0];
			memmove_fixptr(r, r + 1, w1);
			r[w1] = a;
		}
	}
}

static void rotatel2_bit_fixptr(fixptr x, fixptr r, fixsize w, fixsize p)
{
	fixsize q, i;
	fixnum a, b;

	q = FIXED_FULLBIT - p;
	b = x[0];
	for (i = 1; i < w; i++) {
		a = x[i];
		r[i] = (a << p) | (b >> q);
		b = a;
	}
	r[0] = (x[0] << p) | (b >> q);
}

static int rotatel_size_fixptr(fixsize w, fixsize m,
		fixsize *p, fixsize *q)
{
	*p = (m / FIXED_FULLBIT) % w;
	*q = m % FIXED_FULLBIT;
	return *p == 0 && *q == 0;
}

static void rotatel1nm_fixptr(fixptr r, fixsize w, fixsize n,fixsize m)
{
	if (n)
		rotatel1_byte_fixptr(r, w, n);
	if (m)
		rotatel2_bit_fixptr(r, r, w, m);
}

static void rotatel2_byte_fixptr(fixptr x, fixptr r, fixsize w, fixsize n)
{
	fixsize m;

	m = w - n;
	memcpy_fixptr(r + n, x, m);
	memcpy_fixptr(r, x + m, n);
}

static void rotatel2_both_fixptr(fixptr x, fixptr r, fixsize w, fixsize n, fixsize p)
{
	fixsize i, q;
	fixnum a, b;

	q = FIXED_FULLBIT - p;
	b = x[0];
	n++;
	if (w <= n)
		n = 0;
	for (i = 1; i < w; i++) {
		a = x[i];
		r[n] = (a << p) | (b >> q);
		n++;
		if (w <= n)
			n = 0;
		b = a;
	}
	r[n] = (x[0] << p) | (b >> q);
}

static void rotatel2nm_fixptr(fixptr x, fixptr r, fixsize w, fixsize n, fixsize m)
{
	if (n == 0)
		rotatel2_bit_fixptr(x, r, w, m);
	else if (m == 0)
		rotatel2_byte_fixptr(x, r, w, n);
	else
		rotatel2_both_fixptr(x, r, w, n, m);
}

static void rotatel3_byte_fixptr(fixptr x, fixptr y, fixsize w, fixsize n)
{
	fixsize m;

	m = w - n;
	if (n < (w / 2)) {
		memcpy_fixptr(y, x + m, n);
		memmove_fixptr(x + n, x, m);
		memcpy_fixptr(x, y, n);
	}
	else {
		memcpy_fixptr(y, x, m);
		memmove_fixptr(x, x + m, n);
		memcpy_fixptr(x + n, y, m);
	}
}

static void rotatel3nm_fixptr(fixptr x, fixptr y, fixsize w, fixsize n, fixsize m)
{
	if (n == 0)
		rotatel2_bit_fixptr(x, x, w, m);
	else if (m == 0)
		rotatel3_byte_fixptr(x, y, w, n);
	else {
		memcpy_fixptr(y, x, w);
		rotatel2_both_fixptr(y, x, w, n, m);
	}
}

void rotatel1_fixptr(fixptr r, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotatel_size_fixptr(w, m, &n, &m))
		rotatel1nm_fixptr(r, w, n, m);
}

void rotatel2_fixptr(fixptr x, fixptr r, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotatel_size_fixptr(w, m, &n, &m))
		rotatel2nm_fixptr(x, r, w, n, m);
}

void rotatel3_fixptr(fixptr x, fixptr y, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotatel_size_fixptr(w, m, &n, &m))
		rotatel3nm_fixptr(x, y, w, n, m);
}

static int rotater_size_fixptr(fixsize w, fixsize m,
		fixsize *p, fixsize *q)
{
	fixsize right_p, right_q, right_m, left_m;

	right_p = (m / FIXED_FULLBIT) % w;
	right_q = m % FIXED_FULLBIT;
	right_m = right_p * FIXED_FULLBIT + right_q;
	left_m = (w * FIXED_FULLBIT) - right_m;
	*p = (left_m / FIXED_FULLBIT) % w;
	*q = left_m % FIXED_FULLBIT;
	return *p == 0 && *q == 0;
}

void rotater1_fixptr(fixptr r, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotater_size_fixptr(w, m, &n, &m))
		rotatel1nm_fixptr(r, w, n, m);
}

void rotater2_fixptr(fixptr x, fixptr r, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotater_size_fixptr(w, m, &n, &m))
		rotatel2nm_fixptr(x, r, w, n, m);
}

void rotater3_fixptr(fixptr x, fixptr y, fixsize w, fixsize m)
{
	fixsize n;

	if (! rotater_size_fixptr(w, m, &n, &m))
		rotatel3nm_fixptr(x, y, w, n, m);
}


/***********************************************************************
 *  value
 ***********************************************************************/
void setv_fixptr(fixptr x, fixsize size, fixnum v)
{
	if (size) {
		x[0] = v;
		memzero_fixptr(x + 1, size - 1);
	}
}

int getv_fixptr(fixptr x, fixsize size, fixnum *r)
{
	fixsize i;

	for (i = 1; i < size; i++) {
		if (x[i]) {
			*r = FIXED_FULL;
			return 0;
		}
	}
	*r = x[0];
	return 1;
}

#if (UINT_MAX <= FIXED_MAX)
int setu_fixptr(fixptr x, fixsize size, unsigned v)
{
	if (size == 0)
		return 1;
	setv_fixptr(x, size, (fixnum)v);
	return 0;
}
#else
int setu_fixptr(fixptr x, fixsize size, unsigned v)
{
	fixsize i;

	if (size == 0)
		return 1;
	for (i = 0; i < size; i++) {
		x[i] = (fixnum)(FIXED_FULL & v);
		v >>= FIXED_FULLBIT;
	}
	return v? 1: 0;
}
#endif

#if (UINT_MAX < FIXED_MAX)
int getu_fixptr(fixptr x, fixsize size, unsigned *r)
{
	size = size_press_fixptr(x, size);
	if (1 < size || (x[0] >> (sizeof(unsigned) * 8)) != 0) {
		*r = UINT_MAX;
		return 1;
	}
	*r = x[0] & FIXED_FULL;
	return 0;
}
#else
int getu_fixptr(fixptr x, fixsize size, unsigned *r)
{
	unsigned v, byte;
	fixsize count1, count2, i;

	/* overflow */
	size = size_press_fixptr(x, size);
	byte = size * FIXED_FULLBIT / 8;
	if (sizeof(unsigned) < byte) {
		*r = UINT_MAX;
		return 1;
	}

	/* loop */
	count1 = sizeof(unsigned) / byte;
	count2 = sizeof(unsigned) % byte;
	if (count2)
		count1++;
	v = 0;
	for (i = 0; i < count1; i++)
		v |= x[i] << (i * FIXED_FULLBIT);
	*r = v;
	return 0;
}
#endif


/***********************************************************************
 *  fixed
 ***********************************************************************/
/*
 *  macro
 */
#define push_fixrelease(s,w)	((s)->index += (w))
#define pop_fixrelease(s,w)		((s)->index -= (w))
#ifdef FIXED_DEBUG
#if defined(FIXED_8BIT)
#define FIXED_WORD1(w1)			(4 + 4 + (w1) + 4)
#elif defined(FIXED_16BIT)
#define FIXED_WORD1(w1)			(2 + 2 + (w1) + 2)
#else
#define FIXED_WORD1(w1)			(1 + 1 + (w1) + 1)
#endif
#define check1_fixed(s,w)		get1_fixed((s),(w))
#define check2get_fixed(w1)		check2get_fixdebug(w1)
#else
#define FIXED_WORD1(w1)			(w1)
#define check1_fixed(s,w)
#define check2get_fixed(w1)
#endif

#define FIXED_WORD2(w1)			(FIXED_WORD1(w1) * 2)

/*
 *  function
 */
#ifdef FIXED_SIZE_CHECK
#define fixed_size_abort(s, size) { \
	if (s->size < (s->index + size)) { \
		fprintf(stderr, "push error: stack size is too small.\n"); \
		exit(1); \
	} \
}
#else
#define fixed_size_abort(s, size)
#endif

#ifdef FIXED_DEBUG
/* debug */
static fixptr check_fixdebug(fixptr x)
{
#ifdef FIXED_64BIT
	uint64_t a, b, r;
#else
	uint32_t a, b, r;
#endif
	fixptr y;

#if defined(FIXED_8BIT)
	a = *(uint32_t *)x;
	r = *(uint32_t *)(x + 4);
	b = *(uint32_t *)(x + 4 + 4 + r);
	y = x + 4 + 4;
#elif defined(FIXED_16BIT)
	a = *(uint32_t *)x;
	r = *(uint32_t *)(x + 2);
	b = *(uint32_t *)(x + 2 + 2 + r);
	y = x + 2 + 2;
#else
	a = x[0];
	r = x[1];
	b = x[1 + 1 + r];
	y = x + 1 + 1;
#endif
	if (a != b) {
		fprintf(stderr, "check_fixdebug error.\n");
		exit(1);
	}

	return y;
}

static void check2get_fixdebug(fixsize word1)
{
	if (word1 == 0) {
		fprintf(stderr, "check2get_fixed error.\n");
		exit(1);
	}
}

fixptr get1_fixed(fixed s, fixsize word1)
{
	fixsize index;
	fixptr x;

	index = (word1 + 1) * FIXED_WORD1(s->word1);
	if (s->index < index) {
		fprintf(stderr, "get1 error.\n");
		exit(1);
	}
	x = s->stack + s->index - index;
	return check_fixdebug(x);
}

#include <time.h>
static unsigned random_seed_fixdebug = 0;
static uint64_t number64_fixdebug(void)
{
	int i;
	uint64_t v;

	if (random_seed_fixdebug == 0)
		random_seed_fixdebug = (unsigned)time(NULL);
	v = 0;
	for (i = 0; i < sizeof(uint64_t); i++)
		v |= ((uint64_t)(0xFFU & rand_r(&random_seed_fixdebug))) << (i * 8U);

	return v;
}

static void push0_fixed(fixed s, fixsize word, fixsize size)
{
#ifdef FIXED_64BIT
	uint64_t *a, *b, *r;
#else
	uint32_t *a, *b, *r;
#endif
	fixptr x;

	fixed_size_abort(s, size);
	x = s->stack + s->index;
#if defined(FIXED_8BIT)
	a = (uint32_t *)x;
	r = (uint32_t *)(x + 4);
	b = (uint32_t *)(x + 4 + 4 + word);
#elif defined(FIXED_16BIT)
	a = (uint32_t *)x;
	r = (uint32_t *)(x + 2);
	b = (uint32_t *)(x + 2 + 2 + word);
#else
	a = x;
	r = x + 1;
	b = x + 1 + 1 + word;
#endif
#ifdef FIXED_64BIT
	*a = *b = (uint64_t)number64_fixdebug();
	*r = (uint64_t)word;
#else
	*a = *b = (uint32_t)number64_fixdebug();
	*r = (uint32_t)word;
#endif
	push_fixrelease(s, size);
	if (s->index_max < s->index)
		s->index_max = s->index;
}

static void pop0_fixdebug(fixed s, fixsize size)
{
	if (s->index < size) {
		fprintf(stderr, "pop error: index.\n");
		exit(1);
	}
	check_fixdebug(s->stack + s->index - size);
	pop_fixrelease(s, size);
}

void push1_fixed(fixed s)
{
	push0_fixed(s, s->word1, FIXED_WORD1(s->word1));
}

void push2_fixed(fixed s)
{
	push0_fixed(s, s->word2, FIXED_WORD2(s->word1));
}

void pop1_fixed(fixed s)
{
	pop0_fixdebug(s, FIXED_WORD1(s->word1));
}

void pop2_fixed(fixed s)
{
	pop0_fixdebug(s, FIXED_WORD2(s->word1));
}

#else
/* release */
fixptr get1_fixed(fixed s, fixsize word1)
{
	return s->stack + (s->index - (word1 + 1) * s->word1);
}

void push1_fixed(fixed s)
{
	fixed_size_abort(s, s->word1);
	push_fixrelease(s, s->word1);
}

void push2_fixed(fixed s)
{
	fixed_size_abort(s, s->word2);
	push_fixrelease(s, s->word2);
}

void pop1_fixed(fixed s)
{
	pop_fixrelease(s, s->word1);
}

void pop2_fixed(fixed s)
{
	pop_fixrelease(s, s->word2);
}
#endif

fixed make_fixed(fixsize bit1, fixsize size1)
{
	struct fixed_struct *s;
	fixptr stack;
	fixsize word1, byte1, size;

	word1 = bit1 / FIXED_FULLBIT;
	if (bit1 % FIXED_FULLBIT) {
		fprintf(stderr, "bit1 must be FIXED_FULLBIT times.\n");
		return NULL;
	}
	byte1 = bit1 / 8;
	if (bit1 % 8) {
		fprintf(stderr, "bit1 must be 8bit times.\n");
		return NULL;
	}
	size = FIXED_WORD1(word1) * size1;
	if (size == 0) {
		fprintf(stderr, "size too small.\n");
		return NULL;
	}

	/* fixed */
	s = (struct fixed_struct *)malloc(sizeof(struct fixed_struct));
	if (s == NULL)
		return NULL;
	memset(s, 0, sizeof(struct fixed_struct));

	/* stack */
	stack = (fixnum *)malloc(sizeof(fixnum) * size);
	if (stack == NULL) {
		free(s);
		return NULL;
	}

	/* result */
	s->carry = 0;
	s->upper = 1;
	s->stack = stack;
	s->word1 = word1;
	s->word2 = word1 * 2;
	s->size = size;
	s->bit1 = bit1;
	s->bit2 = bit1 * 2;
	s->byte1 = byte1;
	s->byte2 = byte1 * 2;
	s->x = s->y = s->q = s->r = NULL;
	s->sizex = s->sizey = s->sizeq = s->sizer = 0;
#ifdef FIXED_DEBUG
	s->index_max = 0;
#endif

	return s;
}

void free_fixed(fixed s)
{
	if (s) {
		free(s->stack);
		free(s);
	}
}

fixptr top1_fixed(fixed s)
{
	return get1_fixed(s, 0);
}

fixptr top2_fixed(fixed s)
{
	return get1_fixed(s, 1);
}

void pop1n_fixed(fixed s, fixsize n)
{
	fixsize i;
	for (i = 0; i < n; i++)
		pop1_fixed(s);
}

void pop2n_fixed(fixed s, fixsize n)
{
	fixsize i;
	for (i = 0; i < n; i++)
		pop2_fixed(s);
}

fixptr push1get_fixed(fixed s)
{
	push1_fixed(s);
	return top1_fixed(s);
}

fixptr push2get_fixed(fixed s)
{
	push2_fixed(s);
	return top2_fixed(s);
}

fixptr push1ptr_fixed(fixed s, fixptr x)
{
	fixptr y;
	y = push1get_fixed(s);
	memcpy_fixptr(y, x, s->word1);
	return y;
}

fixptr push2ptr_fixed(fixed s, fixptr x)
{
	fixptr y;
	y = push2get_fixed(s);
	memcpy_fixptr(y, x, s->word2);
	return y;
}

fixsize snap_fixed(fixed s)
{
	return s->index;
}

fixsize roll_fixed(fixed s, fixsize index)
{
	fixsize ret;

#ifdef FIXED_DEBUG
	if (s->size <= index) {
		fprintf(stderr, "roll error.\n");
		exit(1);
	}
#endif
	ret = s->index;
	s->index = index;
	return ret;
}

static void dump_fixed(fixed s, fixsize word1, fixsize size)
{
	fixptr x;
	fixsize i;
	fixnum v;

	x = get1_fixed(s, word1);
	for (i = 0; i < size; i++) {
		v = x[i];
		printf("%4u: %0" FIXED_PRINT_LENGTH FIXED_PRINT "\n", i, v);
	}
	fflush(NULL);
}

void dump1_fixed(fixed s, fixsize word1)
{
	dump_fixed(s, word1, s->word1);
}

void dump2_fixed(fixed s, fixsize word1)
{
	check2get_fixed(word1);
	dump_fixed(s, word1, s->word2);
}

int zerop1_fixed(fixed s, fixsize word1)
{
	return zerop_fixptr(get1_fixed(s, word1), s->word1);
}

int zerop2_fixed(fixed s, fixsize word1)
{
	check2get_fixed(word1);
	return zerop_fixptr(get1_fixed(s, word1), s->word2);
}

int onep1_fixed(fixed s, fixsize word1)
{
	return eqlv_fixptr(get1_fixed(s, word1), s->word1, 1);
}

int onep2_fixed(fixed s, fixsize word1)
{
	check2get_fixed(word1);
	return eqlv_fixptr(get1_fixed(s, word1), s->word2, 1);
}

void set1v_fixed(fixed s, fixsize word1, fixnum v)
{
	setv_fixptr(get1_fixed(s, word1), s->word1, v);
}

void set2v_fixed(fixed s, fixsize word1, fixnum v)
{
	check2get_fixed(word1);
	setv_fixptr(get1_fixed(s, word1), s->word2, v);
}

fixptr push1v_fixed(fixed s, fixnum v)
{
	push1_fixed(s);
	set1v_fixed(s, 0, v);
	return top1_fixed(s);
}

fixptr push2v_fixed(fixed s, fixnum v)
{
	push2_fixed(s);
	set2v_fixed(s, 1, v);
	return top2_fixed(s);
}

#define set1macro_fixed(s, word1, v) \
{ \
	fixptr x; \
	fixsize i, size; \
	x = get1_fixed(s, word1); \
	size = s->word1; \
	for (i = 0; i < size; i++) { \
		x[i] = (fixnum)(FIXED_FULL & v); \
		v >>= FIXED_FULLBIT; \
	} \
}

#define set2macro_fixed(s, word1, v) \
{ \
	fixptr x; \
	fixsize i, size; \
	check2get_fixed(word1); \
	x = get1_fixed(s, word1); \
	size = s->word2; \
	for (i = 0; i < size; i++) { \
		x[i] = (fixnum)(FIXED_FULL & v); \
		v >>= FIXED_FULLBIT; \
	} \
}

void set1u_fixed(fixed s, fixsize word1, unsigned v)
{
#if (FIXED_MAX < UINT_MAX)
	set1macro_fixed(s, word1, v);
#else
	set1v_fixed(s, word1, (fixnum)v);
#endif
}
void set2u_fixed(fixed s, fixsize word1, unsigned v)
{
#if (FIXED_MAX < UINT_MAX)
	set2macro_fixed(s, word1, v);
#else
	set2v_fixed(s, word1, (fixnum)v);
#endif
}

void set1u8_fixed(fixed s, fixsize word1, uint8_t v)
{
	set1v_fixed(s, word1, (fixnum)v);
}
void set2u8_fixed(fixed s, fixsize word1, uint8_t v)
{
	set2v_fixed(s, word1, (fixnum)v);
}

void set1u16_fixed(fixed s, fixsize word1, uint16_t v)
{
#if (FIXED_MAX < UINT16_MAX)
	set1macro_fixed(s, word1, v);
#else
	set1v_fixed(s, word1, (fixnum)v);
#endif
}
void set2u16_fixed(fixed s, fixsize word1, uint16_t v)
{
#if (FIXED_MAX < UINT16_MAX)
	set2macro_fixed(s, word1, v);
#else
	set2v_fixed(s, word1, (fixnum)v);
#endif
}

void set1u32_fixed(fixed s, fixsize word1, uint32_t v)
{
#if (FIXED_MAX < UINT32_MAX)
	set1macro_fixed(s, word1, v);
#else
	set1v_fixed(s, word1, (fixnum)v);
#endif
}
void set2u32_fixed(fixed s, fixsize word1, uint32_t v)
{
#if (FIXED_MAX < UINT32_MAX)
	set2macro_fixed(s, word1, v);
#else
	set2v_fixed(s, word1, (fixnum)v);
#endif
}

void set1u64_fixed(fixed s, fixsize word1, uint64_t v)
{
#if (FIXED_MAX < UINT64_MAX)
	set1macro_fixed(s, word1, v);
#else
	set1v_fixed(s, word1, (fixnum)v);
#endif
}
void set2u64_fixed(fixed s, fixsize word1, uint64_t v)
{
#if (FIXED_MAX < UINT64_MAX)
	set2macro_fixed(s, word1, v);
#else
	set2v_fixed(s, word1, (fixnum)v);
#endif
}

fixptr push1u_fixed(fixed s, unsigned v)
{
	fixptr x;

	x = push1get_fixed(s);
	set1u_fixed(s, 0, v);
	return x;
}
fixptr push2u_fixed(fixed s, unsigned v)
{
	fixptr x;

	x = push2get_fixed(s);
	set2u_fixed(s, 1, v);
	return x;
}

void push1u8_fixed(fixed s, uint8_t v)
{
	push1_fixed(s);
	set1u8_fixed(s, 0, v);
}
void push2u8_fixed(fixed s, uint8_t v)
{
	push2_fixed(s);
	set2u8_fixed(s, 1, v);
}

void push1u16_fixed(fixed s, uint16_t v)
{
	push1_fixed(s);
	set1u16_fixed(s, 0, v);
}
void push2u16_fixed(fixed s, uint16_t v)
{
	push2_fixed(s);
	set2u16_fixed(s, 1, v);
}

void push1u32_fixed(fixed s, uint32_t v)
{
	push1_fixed(s);
	set1u32_fixed(s, 0, v);
}
void push2u32_fixed(fixed s, uint32_t v)
{
	push2_fixed(s);
	set2u32_fixed(s, 1, v);
}

void push1u64_fixed(fixed s, uint64_t v)
{
	push1_fixed(s);
	set1u64_fixed(s, 0, v);
}
void push2u64_fixed(fixed s, uint64_t v)
{
	push2_fixed(s);
	set2u64_fixed(s, 1, v);
}

int get1u_fixed(fixed s, fixsize word1, unsigned *r)
{
	return getu_fixptr(get1_fixed(s, word1), s->word1, r);
}

int get2u_fixed(fixed s, fixsize word1, unsigned *r)
{
	check2get_fixed(word1);
	return getu_fixptr(get1_fixed(s, word1), s->word2, r);
}

void copy1_fixed(fixed s, fixsize dst1, fixsize src1)
{
	fixptr x, y;

	x = get1_fixed(s, dst1);
	y = get1_fixed(s, src1);
	memcpy_fixptr(x, y, s->word1);
}

void copy2_fixed(fixed s, fixsize dst1, fixsize src1)
{
	fixptr x, y;

	check2get_fixed(dst1);
	check2get_fixed(src1);
	x = get1_fixed(s, dst1);
	y = get1_fixed(s, src1);
	memcpy_fixptr(x, y, s->word2);
}

void dup1_fixed(fixed s, fixsize word1)
{
	fixptr x, y;

	y = get1_fixed(s, word1);
	x = push1get_fixed(s);
	memcpy_fixptr(x, y, s->word1);
}

void dup2_fixed(fixed s, fixsize word1)
{
	fixptr x, y;

	check2get_fixed(word1);
	y = get1_fixed(s, word1);
	push2_fixed(s);
	x = top2_fixed(s);
	memcpy_fixptr(x, y, s->word2);
}

void shift1_fixed(fixed s, fixsize size1, fixsize pop1)
{
	fixptr dst, src, top;
	fixsize word1, size0, pop0, allsize0;

	if (pop1 == 0)
		return;
	if (size1 == 0) {
		pop1n_fixed(s, pop1);
		return;
	}
	word1 = FIXED_WORD1(s->word1);
	size0 = size1 * word1;
	pop0 = pop1 * word1;
	allsize0 = size0 + pop0;
#ifdef FIXED_DEBUG
	if (s->index < allsize0) {
		fprintf(stderr, "shift0_fixed error.\n");
		exit(1);
	}
#endif
	top = s->stack + s->index;
	dst = top - allsize0;
	src = top - size0;
	memcpy_fixptr(dst, src, size0);
	s->index -= pop0;
}

int compare1_fixed(fixed s, fixsize x1, fixsize y1)
{
	fixptr x, y;

	x = get1_fixed(s, x1);
	y = get1_fixed(s, y1);
	return compare_fixptr(x, s->word1, y, s->word1);
}

int compare2_fixed(fixed s, fixsize x1, fixsize y1)
{
	fixptr x, y;

	check2get_fixed(x1);
	check2get_fixed(y1);
	x = get1_fixed(s, x1);
	y = get1_fixed(s, y1);
	return compare_fixptr(x, s->word2, y, s->word2);
}

void shiftl1_fixed(fixed s, fixsize word1, fixsize shift)
{
	shiftl_fixptr(get1_fixed(s, word1), s->word1, shift);
}

void shiftl2_fixed(fixed s, fixsize word1, fixsize shift)
{
	check2get_fixed(word1);
	shiftl_fixptr(get1_fixed(s, word1), s->word2, shift);
}

void shiftr1_fixed(fixed s, fixsize word1, fixsize shift)
{
	shiftr_fixptr(get1_fixed(s, word1), s->word1, shift);
}

void shiftr2_fixed(fixed s, fixsize word1, fixsize shift)
{
	check2get_fixed(word1);
	shiftr_fixptr(get1_fixed(s, word1), s->word2, shift);
}

void split2_fixed(fixed s, fixsize word1)
{
	fixptr x, y;

	check2get_fixed(word1);
	x = get1_fixed(s, word1);
	y = x + s->word1;
	push1ptr_fixed(s, y);  /* high */
	push1ptr_fixed(s, x);  /* low */
	shift1_fixed(s, 2, 2);
}


/***********************************************************************
 *  multiple
 ***********************************************************************/
void mul2_fixptr(fixptr a, fixsize w1, fixptr b, fixsize w2, fixptr r, fixsize w3)
{
	fixnum v1, v2, c;
	fixsize x, y, z;

	w1 = size_press_fixptr(a, w1);
	w2 = size_press_fixptr(b, w2);
	memzero_fixptr(r, w3);
	for (y = 0; y < w2; y++) {
		v2 = b[y];
		c = 0;
		for (x = 0; x < w1; x++) {
			v1 = a[x];
			mul3_carry_fixnum(&v1, v2, &c);
			for (z = x + y; v1; z++)
				add2_fixnum(&r[z], &v1);
		}
		for (z = x + y; c; z++)
			add2_fixnum(&r[z], &c);
	}
}

void mul_fixptr(fixptr x, fixptr y, fixsize w1, fixptr r, fixsize w2)
{
	mul2_fixptr(x, w1, y, w1, r, w2);
}

void mul_square_fixptr(fixptr x, fixsize w1, fixptr r, fixsize w2)
{
	mul2_fixptr(x, w1, x, w1, r, w2);
}

void mul_square_fixed(fixed s)
{
	fixptr r, x;

	/* r0 -> r1 r0 */
	x = top1_fixed(s);
	push2_fixed(s);
	r = top2_fixed(s);
	mul2_fixptr(x, s->word1, x, s->word1, r, s->word2);
	shift1_fixed(s, 2, 1);
	check1_fixed(s, 1);
}

void mul_fixed(fixed s)
{
	fixptr x, y, r;

	/* x1 y0 -> r1 r0 */
	x = get1_fixed(s, 1);
	y = get1_fixed(s, 0);
	push2_fixed(s);
	r = top2_fixed(s);
	mul2_fixptr(x, s->word1, y, s->word1, r, s->word2);
	shift1_fixed(s, 2, 2);
	check1_fixed(s, 1);
}


/***********************************************************************
 *  division
 ***********************************************************************/
static int div_compare1_fixed(fixed s)
{
	fixptr x, y;
	fixsize sizex, sizey, i, ix, iy;
	fixnum a, b;

	x = s->x;
	y = s->y;
	sizex = s->sizex;
	sizey = s->sizey;
	for (i = 0; i < sizey; i++) {
		ix = sizex - i - 1;
		iy = sizey - i - 1;
		a = x[ix];
		b = y[iy];
		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}

	return 0;
}

static int div_compare2_fixed(fixed s)
{
	fixptr r, y;
	fixsize i, index, sizer, sizey;
	fixnum a, b;

	r = s->r;
	y = s->y;
	sizer = s->sizer;
	sizey = s->sizey;
	for (; sizer && r[sizer - 1] == 0; sizer--)
		continue;
	for (; sizey && y[sizey - 1] == 0; sizey--)
		continue;
	if (sizer < sizey)
		return -1;
	if (sizer > sizey)
		return 1;

	for (i = 0; i < sizer; i++) {
		index = sizer - i - 1;
		a = r[index];
		b = y[index];
		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}

	return 0;
}

static void divrem2_fixed(fixed s, fixnum a, fixnum *carry)
{
	fixptr r, y;
	fixnum m, check;
	fixsize i, sizey;

	r = s->r;
	y = s->y;
	sizey = s->sizey;
	check = 0;
	for (i = 0; i < sizey; i++) {
		mul4_carry_fixnum(&m, y[i], a, &check);
		sub3_carry_fixnum(&r[i], m, carry);
	}
	sub3_carry_fixnum(&r[i], check, carry);
}

static void divrem3_fixed(fixed s, fixnum *carry)
{
	fixptr r, y;
	fixnum check;
	fixsize i, sizey;

	r = s->r;
	y = s->y;
	sizey = s->sizey;
	check = 0;
	for (i = 0; i < sizey; i++)
		add3_carry_fixnum(&r[i], y[i], &check);
	if (check)
		*carry = 0;
}

static void divrem1_fixed(fixed s, fixnum *v)
{
	fixnum carry;

	carry = 0;
	divrem2_fixed(s, *v, &carry);
	while (carry) {
		(*v)--;
		divrem3_fixed(s, &carry);
	}
	s->r[s->sizey] = 0;
}

static void divrem_fixed(fixed s)
{
	int compare;
	fixsize pos, len;
	fixnum dn, v, high, carry;

	pos = 0;
	len = s->sizex - s->sizey + 1;
	dn = s->y[s->sizey - 1];

	/* first check */
	compare = div_compare1_fixed(s);
	if (compare == 0) { /* equal */
		s->q[s->sizeq - pos++ - 1] = 1;
		memzero_fixptr(s->r, s->sizer);
	}
	else if (0 < compare) { /* N division */
		v = s->x[s->sizex - 1] / dn;
		memcpy_fixptr(s->r, s->x + s->sizex - s->sizey, s->sizey);
		s->r[s->sizey] = 0;
		divrem1_fixed(s, &v);
		s->q[s->sizeq - pos++ - 1] = v;
	}
	else { /* N+1 division */
		memcpy_fixptr(s->r, s->x + s->sizex - s->sizey, s->sizey);
		s->r[s->sizey] = 0;
		s->q[s->sizeq - pos++ - 1] = 0;
	}

	/* N+1 division */
	for (; pos < len; pos++) {
		/* shift */
		memmove_fixptr(s->r + 1, s->r, s->sizey);
		s->r[0] = s->x[s->sizex - s->sizey - pos];
		compare = div_compare2_fixed(s);
		if (compare == 0) {
			s->q[s->sizeq - pos - 1] = 1;
			memzero_fixptr(s->r, s->sizer);
			continue;
		}
		else if (compare < 0) {
			s->q[s->sizeq - pos - 1] = 0;
			continue;
		}

		/* quot */
		high = s->r[s->sizer - 1];
		v = s->r[s->sizer - 2];
		div_fixnum(&high, &v, dn, &carry);
		if (high)
			v = FIXED_FULL;
		divrem1_fixed(s, &v);
		s->q[s->sizeq - pos - 1] = v;
	}
}

static void div_copy_fixed(fixed s, fixptr q2, fixsize word2, fixptr r1, fixsize word1)
{
	fixsize diff;

	/* copy q2 */
	s->sizeq = size_press_fixptr(s->q, s->sizeq);
	memcpy_fixptr(q2, s->q, s->sizeq);
	diff = word2 - s->sizeq;
	if (diff)
		memzero_fixptr(q2 + s->sizeq, diff);

	/* copy r1 */
	s->sizer = size_press_fixptr(s->r, s->sizer);
	memcpy_fixptr(r1, s->r, s->sizer);
	diff = word1 - s->sizer;
	if (diff)
		memzero_fixptr(r1 + s->sizer, diff);
}

static void div_shiftl_fixed(int shift, int nshift,
		fixptr dst, fixptr src, fixsize size, int final)
{
	fixsize i;
	fixnum carry, z;

	carry = 0;
	for (i = 0; i < size; i++) {
		z = src[i];
		dst[i] = (z << shift) | (carry >> nshift);
		carry = z;
	}
	if (final)
		dst[i] = carry >> nshift;
}

static void div_shiftr_fixed(int shift, int nshift, fixptr dst, fixsize size)
{
	fixsize i, index;
	fixnum carry, z;

	carry = 0;
	for (i = 0; i < size; i++) {
		index = size - i - 1;
		z = dst[index];
		dst[index] = (carry << nshift) | (z >> shift);
		carry = z;
	}
}

static fixptr div_push_fixed(fixed s, fixsize size)
{
	fixptr x;

#ifdef FIXED_DEBUG
	if (s->size < (s->index + size)) {
		fprintf(stderr, "div_push_fixed error.\n");
		exit(1);
	}
#endif
	x = s->stack + s->index;
	push_fixrelease(s, size);  /* no check */
#ifdef FIXED_DEBUG
	if (s->index_max < s->index)
		s->index_max = s->index;
#endif
	return x;
}

static void div_shift_fixed(fixed s,
		fixptr x2, fixsize sizex,
		fixptr y1, fixsize sizey,
		fixptr q2, fixsize word2,
		fixptr r1, fixsize word1)
{
	int shift, nshift;
	fixnum carry;
	fixptr a, b;
	fixsize sizea, sizeb, rollback;

	rollback = snap_fixed(s);
	carry = y1[sizey - 1];
	shift = getshift_fixnum(&carry);
	if (shift == 0) {
		s->sizex = sizex;
		s->sizey = sizey;
		s->sizeq = sizex - sizey + 1;
		s->sizer = sizey + 1;
		s->x = x2;
		s->y = y1;
		s->q = div_push_fixed(s, s->sizeq);
		s->r = div_push_fixed(s, s->sizer);
		divrem_fixed(s);
	}
	else {
		/* shiftl */
		sizea = sizex + 1;
		sizeb = sizey;
		a = div_push_fixed(s, sizea);
		b = div_push_fixed(s, sizeb);
		nshift = FIXED_FULLBIT - shift;
		div_shiftl_fixed(shift, nshift, a, x2, sizex, 1);
		div_shiftl_fixed(shift, nshift, b, y1, sizey, 0);
		sizea = size_press_fixptr(a, sizea);

		/* calculate */
		s->sizex = sizea;
		s->sizey = sizeb;
		s->sizeq = sizea - sizey + 1;
		s->sizer = sizey + 1;
		s->x = a;
		s->y = b;
		s->q = div_push_fixed(s, s->sizeq);
		s->r = div_push_fixed(s, s->sizer);
		divrem_fixed(s);

		/* shiftr */
		div_shiftr_fixed(shift, nshift, s->r, s->sizer);
	}

	/* result */
	div_copy_fixed(s, q2, word2, r1, word1);
	roll_fixed(s, rollback);
}

/* division single */
static void div4_full_fixnum(fixnum *quot, fixnum x, fixnum y, fixnum *rem)
{
	fixnum high;

	if (*rem == 0) {
		*quot = x / y;
		*rem = x % y;
		return;
	}

	high = *rem;
	divfull_fixnum(&high, &x, y, rem);
#ifdef FIXED_DEBUG
	if (high) {
		fprintf(stderr, "div4_full_fixnum error.\n");
		exit(1);
	}
#endif
	*quot = x;
}

static void div4_half_fixnum(fixnum *quot, fixnum x, fixnum y, fixnum *rem)
{
	fixnum n1;
#ifndef FIXED_DEBUG
	fixnum n2;
#endif

#ifdef FIXED_DEBUG
	if (y <= *rem) {
		fprintf(stderr, "div4_half_fixnum error. (rem).\n");
		exit(1);
	}
	if (FIXED_HIGH(y)) {
		fprintf(stderr, "div4_half_fixnum error. (denom).\n");
		exit(1);
	}
#endif

	if (*rem == 0) {
		*quot = x / y;
		*rem = x % y;
		return;
	}

#ifdef FIXED_DEBUG
	n1 = *rem;
	divhalf_fixnum(&n1, &x, y, rem);
	if (n1) {
		fprintf(stderr, "divhalf_fixnum error.\n");
		exit(1);
	}
	*quot = x;
#else
	n1 = FIXED_HIGHLOW(*rem, FIXED_HIGH(x));
	n2 = n1 / y;
	n1 = n1 % y;
	n1 = FIXED_HIGHLOW(n1, FIXED_LOW(x));
	*rem = n1 % y;
	*quot = FIXED_HIGHLOW(n2, n1 / y);
#endif
}

static void div_single_fixed(
		fixptr x, fixsize wordx, fixnum y,
		fixptr r, fixsize wordr, fixnum *rem)
{
	fixnum carry;
	fixsize i;
	void (*div4)(fixnum *, fixnum, fixnum, fixnum *);

#ifdef FIXED_DEBUG
	if (wordx < 1) {
		fprintf(stderr, "div_single_fixed error: wordx.\n");
		exit(1);
	}
	if (wordr < wordx) {
		fprintf(stderr, "div_single_fixed error: wordr.\n");
		exit(1);
	}
#endif

	div4 = FIXED_HIGH(y)?
		div4_full_fixnum:
		div4_half_fixnum;
	carry = 0;
	for (i = wordr - 1; ; i--) {
		if (wordx <= i)
			r[i] = 0;
		else
			(*div4)(&r[i], x[i], y, &carry);
		if (i == 0)
			break;
	}
	*rem = carry;
}

static void div_size_fixptr(fixed s,
		fixptr x2, fixptr y1,
		fixptr q2, fixptr r1,
		fixsize word2, fixsize word1)
{
	int checkx, checky, diff;
	fixnum a2, b1;
	fixsize wordx, wordy;

	/* stack: x2 x1 y0 -> q2 q1 r0 */
	wordx = size_press_fixptr(x2, word2);
	wordy = size_press_fixptr(y1, word1);

	/* y=0 (x/0), error */
	if (zerop_fixptr(y1, wordy)) {
		fprintf(stderr, "division by zero.\n");
		exit(1);
	}

	/* x=0 (0/y), 0...0 */
	if (zerop_fixptr(x2, wordx)) {
		memzero_fixptr(q2, word2); /* q=0 */
		memzero_fixptr(r1, word1); /* r=0 */
		return;
	}

	/* single, single */
	checkx = (wordx <= 1);
	checky = (wordy <= 1);
	if (checkx && checky) {
		a2 = x2[0];
		b1 = y1[0];
		setv_fixptr(q2, word2, a2 / b1); /* q */
		setv_fixptr(r1, word1, a2 % b1); /* r */
		return;
	}

	/* multiple, single */
	if (checky) {
		b1 = y1[0];
		if (b1 == 1) {
			memmove_fixptr(q2, x2, word2); /* q=x, move */
			memzero_fixptr(r1, word1); /* r=0 */
		}
		else {
			div_single_fixed(x2, wordx, b1, q2, word2, &b1);
			setv_fixptr(r1, word1, b1); /* r=b */
		}
		return;
	}

	/* x/y and x=y, 1...0 */
	diff = compare_fixptr(x2, wordx, y1, wordy);
	if (diff == 0) {
		setv_fixptr(q2, word2, 1); /* q=1 */
		memzero_fixptr(r1, word1); /* r=0 */
		return;
	}

	/* x/y and x<y, 0...x */
	if (diff < 0) {
		memcpy_fixptr(r1, x2, word1); /* r=x */
		memzero_fixptr(q2, word2); /* q=0 */
		return;
	}

	/* x/y and x>y, q...r */
	div_shift_fixed(s, x2, wordx, y1, wordy, q2, word2, r1, word1);
}

void div1_fixptr(fixed s, fixptr x1, fixptr y1, fixptr q1, fixptr r1)
{
	div_size_fixptr(s, x1, y1, q1, r1, s->word1, s->word1);
}

void rem1_fixptr(fixed s, fixptr x1, fixptr y1, fixptr r1)
{
	fixptr q1;

	q1 = push1get_fixed(s);
	div1_fixptr(s, x1, y1, q1, r1);
	pop1_fixed(s);
}

void div_fixptr(fixed s, fixptr x2, fixptr y1, fixptr q2, fixptr r1)
{
	div_size_fixptr(s, x2, y1, q2, r1, s->word2, s->word1);
}

void rem_fixptr(fixed s, fixptr x2, fixptr y1, fixptr r1)
{
	fixptr q2;

	q2 = push2get_fixed(s);
	div_fixptr(s, x2, y1, q2, r1);
	pop2_fixed(s);
}

void div_fixed(fixed s)
{
	fixptr x2, y1;

	x2 = get1_fixed(s, 2);
	y1 = get1_fixed(s, 0);
	div_fixptr(s, x2, y1, x2, y1);
	check1_fixed(s, 2);
	check1_fixed(s, 0);
}

void rem_fixed(fixed s)
{
	fixptr x2, y1;

	x2 = get1_fixed(s, 2);
	y1 = get1_fixed(s, 0);
	rem_fixptr(s, x2, y1, y1);
	shift1_fixed(s, 1, 2);
	check1_fixed(s, 0);
}


/***********************************************************************
 *  read
 ***********************************************************************/
static int readset_char_fixed(fixsize size, fixnum r, fixptr x, fixnum y)
{
	int check;
	fixnum carry;

	/* x*r -> x */
	check = 0;
	mulv_fixptr(x, size, r, &carry);
	if (carry)
		check = 1;

	/* x+y -> x */
	addv_fixptr(x, size, y, &carry);
	if (carry)
		check = 1;

	return check;
}

static int radix_fixed(char c, fixnum *y)
{
	if ('0' <= c && c <= '9')
		*y = (fixnum)(c - '0');
	else if ('a' <= c && c <= 'z')
		*y = (fixnum)(10 + c - 'a');
	else if ('A' <= c && c <= 'Z')
		*y = (fixnum)(10 + c - 'A');
	else {
		*y = 0;
		return 1;
	}

	return 0;
}

static int read_char_fixptr(fixptr x, fixsize size, unsigned radix, char p)
{
	fixnum y, r;

	if (! FIXED_RADIX(radix))
		return 1;
	r = (fixnum)radix;
	if (radix_fixed(p, &y))
		return 2;
	if (r <= y)
		return 3;
	if (readset_char_fixed(size, r, x, y))
		return -1;

	return 0;
}

int read1_char_fixed(fixed s, fixsize word1, unsigned r, char p)
{
	return read_char_fixptr(get1_fixed(s, word1), s->word1, r, p);
}

int read2_char_fixed(fixed s, fixsize word1, unsigned r, char p)
{
	check2get_fixed(word1);
	return read_char_fixptr(get1_fixed(s, word1), s->word2, r, p);
}

static int readset_fixed(fixsize size, const char *str, unsigned radix, fixptr x)
{
	char c;
	size_t i;
	fixnum r, y;

#ifdef FIXED_DEBUG
	if (! FIXED_RADIX(radix)) {
		fprintf(stderr, "radix error, %u\n", radix);
		return 1;
	}
#endif
	memzero_fixptr(x, size);
	r = (fixnum)radix;
	for (i = 0; ; i++) {
		c = str[i];
		if (c == '\0')
			break;
		if (radix_fixed(c, &y)) {
			fprintf(stderr, "character error, %s\n", str);
			return 1;
		}
		if (r <= y) {
			fprintf(stderr, "radix error, %s\n", str);
			return 1;
		}
		if (readset_char_fixed(size, r, x, y)) {
			fprintf(stderr, "overflow, %s\n", str);
			return 1;
		}
	}

	return 0;
}

int read1s_fixed(fixed s, fixsize word1, const char *str, unsigned radix)
{
	return readset_fixed(s->word1, str, radix, get1_fixed(s, word1));
}

int read2s_fixed(fixed s, fixsize word1, const char *str, unsigned radix)
{
	check2get_fixed(word1);
	return readset_fixed(s->word2, str, radix, get1_fixed(s, word1));
}

int read1p_fixed(fixed s, const char *str, unsigned radix)
{
	push1_fixed(s);
	return read1s_fixed(s, 0, str, radix);
}

int read2p_fixed(fixed s, const char *str, unsigned radix)
{
	push2_fixed(s);
	return read2s_fixed(s, 1, str, radix);
}

int read1_compare_fixed(fixed s, fixsize word1,
		const char *str, unsigned radix, int *ret)
{
	if (read1p_fixed(s, str, radix)) {
		*ret = -1;
		return 1;
	}
	*ret = compare1_fixed(s, word1 + 1, 0);
	pop1_fixed(s);
	return 0;
}


/***********************************************************************
 *  print
 ***********************************************************************/
fixprint make_fixprint(void)
{
	struct fixed_print *ptr;

	ptr = (struct fixed_print *)malloc(sizeof(struct fixed_print));
	if (ptr == NULL)
		return NULL;
	ptr->upper = 1;
	ptr->root = ptr->tail = NULL;
	ptr->size = 0;

	return ptr;
}

void free_fixprint(fixprint print)
{
	struct fixed_print_child *x, *y;

	for (x = print->root; x; x = y) {
		y = x->next;
		free(x);
	}
	free(print);
}

/* child */
static struct fixed_print_child *make_fixed_print_child(char c)
{
	struct fixed_print_child *ptr;

	ptr = (struct fixed_print_child *)malloc(sizeof(struct fixed_print_child));
	if (ptr == NULL)
		return NULL;
	ptr->next = NULL;
	ptr->str[0] = c;
	ptr->size = 1;

	return ptr;
}

static int push_fixprint(fixprint print, char c)
{
	struct fixed_print_child *child;

	/* root */
	if (print->root == NULL) {
		child = make_fixed_print_child(c);
		if (child == NULL)
			return 1;
		print->root = print->tail = child;
		print->size = 1;
		return 0;
	}

	/* next */
	child = print->tail;
	if (FIXED_PRINT_SIZE <= child->size) {
		child = make_fixed_print_child(c);
		if (child == NULL)
			return 1;
		print->tail->next = child;
		print->tail = child;
		print->size++;
		return 0;
	}

	/* child */
	child->str[child->size] = c;
	child->size++;
	print->size++;
	return 0;
}

static int fixnum_fixprint(fixprint print, fixnum v)
{
	char c;

	if (v <= 9)
		c = (char)('0' + v);
	else if (print->upper)
		c = (char)(v - 10 + 'A');
	else
		c = (char)(v - 10 + 'a');

	return push_fixprint(print, c);
}


/* read */
static int div_fixprint(fixprint print, fixptr x, fixsize size, fixnum y)
{
	fixnum carry;

	size = size_press_fixptr(x, size);
	div_single_fixed(x, size, y, x, size, &carry);
	if (fixnum_fixprint(print, carry)) {
		fprintf(stderr, "print push error.\n");
		return 1;
	}

	return 0;
}

static int read_fixprint(fixprint print, fixptr x, fixsize size, unsigned radix)
{
	int check;
	fixnum r;

#ifdef FIXED_DEBUG
	if (! FIXED_RADIX(radix)) {
		fprintf(stderr, "radix error, %u\n", radix);
		return 1;
	}
#endif
	r = (fixnum)radix;
	for (;;) {
		check = div_fixprint(print, x, size, r);
		if (check)
			break;
		if (zerop_fixptr(x, size))
			break;
	}

	return check;
}

int read1_fixprint(fixprint print, fixed s, fixsize word1, unsigned radix)
{
	int check;
	fixptr x;

	dup1_fixed(s, word1);
	x = top1_fixed(s);
	check = read_fixprint(print, x, s->word1, radix);
	pop1_fixed(s);

	return check;
}

int read2_fixprint(fixprint print, fixed s, fixsize word1, unsigned radix)
{
	int check;
	fixptr x;

	check2get_fixed(word1);
	dup2_fixed(s, word1);
	x = top2_fixed(s);
	check = read_fixprint(print, x, s->word2, radix);
	pop2_fixed(s);

	return check;
}

fixprint make1_fixprint(fixed s, fixsize word1, unsigned radix)
{
	fixprint print;

	print = make_fixprint();
	print->upper = s->upper;
	if (print == NULL) {
		fprintf(stderr, "make_fixprint error.\n");
		return NULL;
	}
	if (read1_fixprint(print, s, word1, radix)) {
		fprintf(stderr, "read1_fixprint error.\n");
		free_fixprint(print);
		return NULL;
	}

	return print;
}

fixprint make2_fixprint(fixed s, fixsize word1, unsigned radix)
{
	fixprint print;

	check2get_fixed(word1);
	print = make_fixprint();
	print->upper = s->upper;
	if (print == NULL) {
		fprintf(stderr, "make_fixprint error.\n");
		return NULL;
	}
	if (read2_fixprint(print, s, word1, radix)) {
		fprintf(stderr, "read2_fixprint error.\n");
		free_fixprint(print);
		return NULL;
	}

	return print;
}

static void string_fixed_print_child(struct fixed_print_child *ptr,
		char *str, size_t *rindex, size_t size)
{
	unsigned n;

	if (ptr == NULL)
		return;
	string_fixed_print_child(ptr->next, str, rindex, size);
	if (size <= *rindex)
		return;
	if (ptr->size) {
		n = ptr->size - 1;
		for (;;) {
			str[*rindex] = ptr->str[n];
			(*rindex)++;
			if (n == 0)
				break;
			n--;
		}
	}
}

void string_fixprint(fixprint print, char *str, size_t size)
{
	size_t index;

	if (size == 0)
		return;
	size--;
	index = 0;
	string_fixed_print_child(print->root, str, &index, size);
	str[index] = 0;
}

static void file_fixed_print_child(struct fixed_print_child *ptr, FILE *file)
{
	unsigned n;

	if (ptr == NULL)
		return;
	file_fixed_print_child(ptr->next, file);
	if (ptr->size) {
		n = ptr->size - 1;
		for (;;) {
			fputc(ptr->str[n], file);
			if (n == 0)
				break;
			n--;
		}
	}
}

void file_fixprint(fixprint print, FILE *file)
{
	file_fixed_print_child(print->root, file);
}

int print1_fixed(fixed s, fixsize word1, FILE *file, unsigned radix)
{
	fixprint print;

	print = make1_fixprint(s, word1, radix);
	if (print == NULL)
		return 1;
	file_fixprint(print, file);
	free_fixprint(print);

	return 0;
}

int print2_fixed(fixed s, fixsize word1, FILE *file, unsigned radix)
{
	fixprint print;

	check2get_fixed(word1);
	print = make2_fixprint(s, word1, radix);
	if (print == NULL)
		return 1;
	file_fixprint(print, file);
	free_fixprint(print);

	return 0;
}

int println1_fixed(fixed s, fixsize word1, FILE *file, unsigned radix)
{
	int check;

	check = print1_fixed(s, word1, file, radix);
	if (check)
		return check;
	fprintf(file, "\n");
	return 0;
}

int println2_fixed(fixed s, fixsize word1, FILE *file, unsigned radix)
{
	int check;

	check = print2_fixed(s, word1, file, radix);
	if (check)
		return check;
	fprintf(file, "\n");
	return 0;
}

int println1_fixptr(fixed s, fixptr x, FILE *file, unsigned radix)
{
	int check;

	push1ptr_fixed(s, x);
	check = println1_fixed(s, 0, file, radix);
	pop1_fixed(s);

	return check;
}

int println2_fixptr(fixed s, fixptr x, FILE *file, unsigned radix)
{
	int check;

	push2ptr_fixed(s, x);
	check = println2_fixed(s, 1, file, radix);
	pop2_fixed(s);

	return check;
}


/***********************************************************************
 * binary I/O
 ***********************************************************************/
void input_fixptr(fixptr r, fixsize word, const void *p, size_t size, int little)
{
	uint8_t u;
	const uint8_t *input;
	fixnum value;
	size_t i, k, x, y, byte;

	input = (const uint8_t *)p;
	byte = FIXED_FULLBIT / 8;
	i = 0;
	for (x = 0; x < word; x++) {
		value = 0;
		if (i < size) {
			for (y = 0; y < byte; y++) {
				k = little? i: (size - i - 1);
				u = (i < size)? input[k]: 0;
				i++;
				value |= ((fixnum)u) << (y * 8);
			}
		}
		r[x] = value;
	}
}

void output_fixptr(fixptr x, fixsize word, void *p, size_t size, int little)
{
	uint8_t u, *output;
	size_t i, k, byte, allsize, m, n;

	output = (uint8_t *)p;
	byte = FIXED_FULLBIT / 8;
	allsize = word * byte;
	for (i = 0; i < size; i++) {
		if (i < allsize) {
			n = i / byte;
			m = i % byte;
			u = 0xFFU & (x[n] >> (m * 8));
		}
		else {
			u = 0;
		}
		k = little? i: (size - i - 1);
		output[k] = u;
	}
}


/***********************************************************************
 *  operator
 ***********************************************************************/
/* x -> x */
void inc1s_fixed(fixed s)
{
	fixptr x;
	fixnum c;

	x = top1_fixed(s);
	addv_fixptr(x, s->word1, 1, &c);
	s->carry = c? 1: 0;
}

/* x -> x r */
void inc1p_fixed(fixed s)
{
	dup1_fixed(s, 0);
	inc1s_fixed(s);
}

void dec1s_fixed(fixed s)
{
	fixptr x;
	fixnum c;

	x = top1_fixed(s);
	subv_fixptr(x, s->word1, 1, &c);
	s->carry = c? 1: 0;
}

void dec1p_fixed(fixed s)
{
	dup1_fixed(s, 0);
	dec1s_fixed(s);
}

void add1s_fixed(fixed s)
{
	fixptr x, y;
	fixnum c;

	x = get1_fixed(s, 0);  /* result */
	y = get1_fixed(s, 1);  /* delete */
	add_fixptr(x, y, x, s->word1, &c);
	pop1_fixed(s);
	s->carry = c? 1: 0;
}

void add1p_fixed(fixed s)
{
	fixptr x, y, z;
	fixnum c;

	x = get1_fixed(s, 0);
	y = get1_fixed(s, 1);
	z = push1get_fixed(s);
	add_fixptr(x, y, z, s->word1, &c);
	s->carry = c? 1: 0;
}

void sub1s_fixed(fixed s)
{
	fixptr x, y;
	fixnum c;

	x = get1_fixed(s, 0);  /* result */
	y = get1_fixed(s, 1);  /* delete */
	sub_fixptr(x, y, x, s->word1, &c);
	pop1_fixed(s);
	s->carry = c? 1: 0;
}

void sub1p_fixed(fixed s)
{
	fixptr x, y, z;
	fixnum c;

	x = get1_fixed(s, 0);
	y = get1_fixed(s, 1);
	z = push1get_fixed(s);
	sub_fixptr(x, y, z, s->word1, &c);
	s->carry = c? 1: 0;
}

void sub1s_reverse_fixed(fixed s)
{
	fixptr x, y;
	fixnum c;

	x = get1_fixed(s, 0);  /* delete */
	y = get1_fixed(s, 1);  /* result */
	sub_fixptr(y, x, x, s->word1, &c);
	pop1_fixed(s);
	s->carry = c? 1: 0;
}

void sub1p_reverse_fixed(fixed s)
{
	fixptr x, y, z;
	fixnum c;

	x = get1_fixed(s, 0);
	y = get1_fixed(s, 1);
	z = push1get_fixed(s);
	sub_fixptr(y, x, z, s->word1, &c);
	s->carry = c? 1: 0;
}

void not_fixptr(fixptr x, fixptr r, fixsize size)
{
	fixsize i;

	for (i = 0; i < size; i++)
		r[i] = ~x[i];
}

void and_fixptr(fixptr x, fixptr y, fixptr r, fixsize size)
{
	fixsize i;

	for (i = 0; i < size; i++)
		r[i] = x[i] & y[i];
}

void or_fixptr(fixptr x, fixptr y, fixptr r, fixsize size)
{
	fixsize i;

	for (i = 0; i < size; i++)
		r[i] = x[i] | y[i];
}

void xor_fixptr(fixptr x, fixptr y, fixptr r, fixsize size)
{
	fixsize i;

	for (i = 0; i < size; i++)
		r[i] = x[i] ^ y[i];
}

void not1_fixed(fixed s)
{
	/* x -> r */
	not_fixptr(get1_fixed(s, 1), get1_fixed(s, 0), s->word1);
}

void and1_fixed(fixed s)
{
	fixptr x, r;

	/* x y -> r */
	x = get1_fixed(s, 0);
	r = get1_fixed(s, 1);
	and_fixptr(x, x, r, s->word1);
	pop1_fixed(s);
}

void or1_fixed(fixed s)
{
	fixptr x, r;

	/* x y -> r */
	x = get1_fixed(s, 0);
	r = get1_fixed(s, 1);
	or_fixptr(x, x, r, s->word1);
	pop1_fixed(s);
}

void xor1_fixed(fixed s)
{
	fixptr x, r;

	/* x y -> r */
	x = get1_fixed(s, 0);
	r = get1_fixed(s, 1);
	xor_fixptr(x, x, r, s->word1);
	pop1_fixed(s);
}

