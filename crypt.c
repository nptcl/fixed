#include "fixed.h"
#include "random.h"
#include <stdlib.h>

/***********************************************************************
 *  random
 ***********************************************************************/
static fixnum random_number_fixnum(struct fixed_random *state)
{
	return (fixnum)number64_sha_fixrandom(state);
}

static fixnum random_equal_fixnum(struct fixed_random *state, fixnum value)
{
	return (fixnum)equal64_sha_fixrandom(state, (uint64_t)value);
}

static int random_loop_fixptr(struct fixed_random *state,
		fixptr r, fixsize size, int less)
{
	fixsize index, i;
	fixnum x, y;

	/* r -> 0...r */
	index = size - 1;
	x = r[index];
	y = random_equal_fixnum(state, x);
	if (x != y)
		goto tail;
	for (i = 1; i < size; i++) {
		index = size - i - 1;
		x = r[index];
		y = random_number_fixnum(state);
		if (x < y)
			return 1;
		if (x > y)
			goto tail;
	}
	return less;

tail:
	r[index] = y;
	for (i = 0; i < index; i++)
		r[i] = random_number_fixnum(state);
	return 0;
}

static void random_fixptr(struct fixed_random *state,
		fixptr x, fixptr r, fixsize size, int less)
{
	if (x != r)
		memcpy_fixptr(r, x, size);

	/* size */
	size = size_press_fixptr(r, size);
	if (size == 0) /* all zero */
		return;

	/* random */
	while (random_loop_fixptr(state, r, size, less))
		continue;
}

void random_equal_fixptr(struct fixed_random *state, fixptr x, fixptr r, fixsize size)
{
	random_fixptr(state, x, r, size, 0);
}

void random_less_fixptr(struct fixed_random *state, fixptr x, fixptr r, fixsize size)
{
	random_fixptr(state, x, r, size, 1);
}

void random_equal_fixed(fixed s, struct fixed_random *state)
{
	fixptr x, r;

	/* stack: x -> r */
	x = top1_fixed(s);
	r = push1get_fixed(s);
	random_equal_fixptr(state, x, r, s->word1);
	shift1_fixed(s, 1, 1);
}

void random_less_fixed(fixed s, struct fixed_random *state)
{
	fixptr x, r;

	/* stack: x -> r */
	x = top1_fixed(s);
	r = push1get_fixed(s);
	random_less_fixptr(state, x, r, s->word1);
	shift1_fixed(s, 1, 1);
}

void random_full_fixptr(struct fixed_random *state, fixptr x, fixsize size)
{
	fixsize i;
	for (i = 0; i < size; i++)
		x[i] = (fixnum)random_number_fixnum(state);
}

void random_full_fixed(fixed s, struct fixed_random *state)
{
	random_full_fixptr(state, push1get_fixed(s), s->word1);
}


/***********************************************************************
 *  power_mod
 ***********************************************************************/
/* x[destroy], y[destroy], n[input], r[output] */
static void power_mod_recall(fixed s, fixptr x, fixptr y, fixptr n, fixptr r)
{
	fixptr z;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	z = push2get_fixed(s);
	while (! zerop_fixptr(y, word1)) {
		/* 3: (mod (* r x) n), or r */
		if ((y[0] & 0x01) != 0) {
			mul_fixptr(r, x, word1, z, word2);
			rem_fixptr(s, z, n, r);
		}

		/* 1: (mod (* x x) n) */
		mul_square_fixptr(x, word1, z, word2);
		rem_fixptr(s, z, n, x);

		/* 2: (ash y -1) */
		shiftr_fixptr(y, word1, 1);
	}
	pop2_fixed(s);
}

/* x y n -> r */
void power_mod_fixptr(fixed s, fixptr x, fixptr y, fixptr n, fixptr r)
{
	fixptr x1, y1;

	x1 = push1ptr_fixed(s, x);
	y1 = push1ptr_fixed(s, y);
	setv_fixptr(r, s->word1, 1); /* r=1 */
	power_mod_recall(s, x1, y1, n, r);
	pop1n_fixed(s, 2);
}

/* x y n -> r */
void power_mod_fixed(fixed s)
{
	fixptr x, y, n, r;

	x = get1_fixed(s, 2);
	y = get1_fixed(s, 1);
	n = get1_fixed(s, 0);
	r = push1v_fixed(s, 1);
	power_mod_recall(s, x, y, n, r);
	shift1_fixed(s, 1, 3);
}


/***********************************************************************
 *  prime
 ***********************************************************************/
static int prime_loop_p(fixed s, struct fixed_random *state, fixptr x, int k)
{
	int i, check, result;
	fixptr n1, n2, a, b, c, z;
	fixsize word1, word2;
	fixnum ignore;

	/* memory */
	word1 = s->word1;
	word2 = s->word2;
	n1 = push1ptr_fixed(s, x);  /* 1 */
	dec1s_fixed(s);
	n2 = push1ptr_fixed(s, n1);  /* 1 */
	a = push1get_fixed(s);  /* 1 */
	b = push1get_fixed(s);  /* 1 */
	c = push1get_fixed(s);  /* 1 */
	z = push2get_fixed(s);  /* 2 */

	/* shift */
	while ((n2[0] & 0x01) == 0)
		shiftr_fixptr(n2, word1, 1);

	/* dotimes */
	result = 1;
	for (i = 0; i < k; i++) {
		/* a */
		memcpy_fixptr(a, x, word1);
		subv_fixptr(a, word1, 1, &ignore);
		random_equal_fixptr(state, a, a, word1);
		addv_fixptr(a, word1, 1, &ignore);
		/* b */
		memcpy_fixptr(b, n2, word1);
		/* c */
		power_mod_fixptr(s, a, b, x, c);

		for (;;) {
			if (compare_fixnum_fixptr(c, word1, 1) == 0)
				break;
			if (compare_fixptr(b, word1, n1, word1) == 0)
				break;
			if (compare_fixptr(c, word1, n1, word1) == 0)
				break;
			/* (mod (* c c) x) */
			mul_square_fixptr(c, word1, z, word2);
			rem_fixptr(s, z, x, c);
			/* (ash b 1) */
			shiftl_fixptr(b, word1, 1);
		}

		check = ((b[0] & 0x01) == 0)
			&& (compare_fixptr(c, word1, n1, word1) != 0);
		if (check) {
			result = 0;
			break;
		}
	}

	pop2_fixed(s);  /* z */
	pop1n_fixed(s, 5);  /* n1, n2, a, b, c */
	return result;
}

static int prime_p(fixed s, struct fixed_random *state, fixptr x, int k)
{
	if (compare_fixnum_fixptr(x, s->word1, 2) == 0)
		return 1; /* 2 */
	if (compare_fixnum_fixptr(x, s->word1, 1) == 0)
		return 0; /* 1 */
	if ((x[0] & 0x01) == 0)
		return 0; /* even */

	return prime_loop_p(s, state, x, k);
}

static void prime_random(fixed s, struct fixed_random *state, fixptr x, unsigned bit)
{
	fixsize word1, q, r;
	fixnum ignore;

	/* full */
	word1 = s->word1;
	if (s->bit1 <= bit) {
		random_full_fixptr(state, x, word1);
		x[0] |= 1;
		x[word1 - 1] |= 1ULL << (FIXED_FULLBIT - 1ULL);
		return;
	}

	/* bit */
	setv_fixptr(x, word1, 1);
	shiftl_fixptr(x, word1, bit);
	subv_fixptr(x, word1, 1, &ignore);
	random_equal_fixptr(state, x, x, s->word1);
	x[0] |= 1;
	bit--;
	q = bit / FIXED_FULLBIT;
	r = bit % FIXED_FULLBIT;
	x[q] |= (1ULL << r);
}

static int prime_times(fixsize bit)
{
	if (bit >= 1300) return 2;
	if (bit >= 850) return 3;
	if (bit >= 650) return 4;
	if (bit >= 550) return 5;
	if (bit >= 450) return 6;
	if (bit >= 400) return 7;
	if (bit >= 350) return 8;
	if (bit >= 300) return 9;
	if (bit >= 250) return 12;
	if (bit >= 200) return 15;
	if (bit >= 150) return 18;
	return 27;
}

/* (empty) -> r */
int make_prime_output = 0;
void make_prime_fixptr(fixed s, struct fixed_random *state, unsigned bit, fixptr r)
{
	int k, i;

	if (bit == 0 || s->bit1 < bit)
		bit = s->bit1;
	if (bit == 1) {
		setv_fixptr(r, s->word1, 1);
		return;
	}
	k = prime_times(bit);
	for (i = 0; ; i++) {
		if (make_prime_output) {
			fprintf(stdout, ".");
			fflush(stdout);
		}
		prime_random(s, state, r, bit);
		if (prime_p(s, state, r, k))
			break;
	}
	if (make_prime_output) {
		fprintf(stdout, "\nmake_prime: %d\n", i);
		fflush(stdout);
	}
}

void make_prime_fixed(fixed s, struct fixed_random *state, unsigned bit)
{
	fixptr r;
	r = push1get_fixed(s);
	make_prime_fixptr(s, state, bit, r);
}


/***********************************************************************
 *  rsa-key
 ***********************************************************************/
static int rsa_addsign(int sign_x, fixptr x, int sign_y, fixptr y,
		fixptr r, fixsize size)
{
	int compare;
	fixnum ignore;

	/* add */
	if (sign_x == sign_y) {
		add_fixptr(x, y, r, size, &ignore);
		return sign_x;
	}

	/* sub */
	compare = compare_fixptr(x, size, y, size);
	if (compare < 0) {
		sub_fixptr(y, x, r, size, &ignore);
		return sign_y;
	}
	else if (compare > 0) {
		sub_fixptr(x, y, r, size, &ignore);
		return sign_x;
	}
	else {
		memzero_fixptr(r, size);
		return 0;  /* plus */
	}
}

static int rsa_subsign(int sign_x, fixptr x, int sign_y, fixptr y,
		fixptr r, fixsize size)
{
	return rsa_addsign(sign_x, x, (! sign_y), y, r, size);
}

#ifdef FIXED_DEBUG
static void rsa_check_debug(fixptr q, fixsize word1, int id)
{
	if (! zerop_fixptr(q + word1, word1)) {
		fprintf(stderr, "number_d error: debug%d.\n", id);
		exit(1);
	}
}
#else
#define rsa_check_debug(q, word1, id)
#endif

static void rsa_number_d(fixed s, fixptr d, fixptr e, fixptr pq1)
{
	int a0, a1, b0, b1, c;
	fixptr x, y, z, x0, x1, y0, y1, q, w;
	fixsize word1, word2;
	fixnum ignore;

	/* extended euclidean */
	word1 = s->word1;
	word2 = s->word2;
	q = push2get_fixed(s);
	z = push2get_fixed(s);
	x = push1ptr_fixed(s, e);
	y = push1ptr_fixed(s, pq1);
	x0 = push1v_fixed(s, 1);
	x1 = push1v_fixed(s, 0);
	y0 = push1v_fixed(s, 0);
	y1 = push1v_fixed(s, 1);
	a0 = a1 = b0 = b1 = 0;  /* plus */
	while (! zerop_fixptr(y, word1)) {
		memzero_fixptr(z, word2);
		memcpy_fixptr(z, x, word1);
		memcpy_fixptr(x, y, word1);
		div_fixptr(s, z, y, q, y);
		rsa_check_debug(q, word1, 1);

		/* x2 */
		mul_fixptr(q, x1, word1, z, word2);
		rsa_check_debug(z, word1, 2);
		a0 = rsa_subsign(a0, x0, a1, z, x0, word1);
		w = x0; x0 = x1; x1 = w;
		c = a0; a0 = a1; a1 = c;

		/* y2 */
		mul_fixptr(q, y1, word1, z, word2);
		rsa_check_debug(z, word1, 3);
		b0 = rsa_subsign(b0, y0, b1, z, y0, word1);
		w = y0; y0 = y1; y1 = w;
		c = b0; b0 = b1; b1 = c;
	}

	/* minus */
	memcpy_fixptr(d, x0, word1);
	if (a0) {
		/* pq1 - d */
		sub_fixptr(pq1, d, d, word1, &ignore);
	}

	/* pop */
	pop1n_fixed(s, 6);
	pop2n_fixed(s, 2);
}

void make_rsakey_fixed(fixed s, struct fixed_random *state,
		unsigned bit, unsigned value_e)
{
	unsigned half_bit;
	fixptr e, d, n, p, q, z, pq1, p1, q1;
	fixsize word1, word2;
	fixnum ignore;

	if (value_e == 0)
		value_e = 65537;
	half_bit = bit >> 1;
	word1 = s->word1;
	word2 = s->word2;
	e = push1get_fixed(s); /* e */
	d = push1get_fixed(s); /* d */
	n = push1get_fixed(s); /* n */
	p = push1get_fixed(s); /* p */
	q = push1get_fixed(s); /* q */
	/* temporary */
	p1 = push1get_fixed(s); /* 1 */
	q1 = push1get_fixed(s); /* 1 */
	pq1 = push1get_fixed(s); /* 1 */
	z = push2get_fixed(s); /* 2 */
	/* e, p, q, n */
	setu_fixptr(e, word1, value_e);
	make_prime_fixptr(s, state, half_bit, p);
	make_prime_fixptr(s, state, half_bit, q);
	mul_fixptr(p, q, word1, z, word2);
	memcpy_fixptr(n, z, word1);
	/* p-1, q-1 */
	memcpy_fixptr(p1, p, word1);
	memcpy_fixptr(q1, q, word1);
	subv_fixptr(p1, word1, 1, &ignore);
	subv_fixptr(q1, word1, 1, &ignore);
	mul_fixptr(p1, q1, word1, z, word2);
	memcpy_fixptr(pq1, z, word1);
	/* d */
	rsa_number_d(s, d, e, pq1);
	pop2_fixed(s);
	pop1n_fixed(s, 3);
}


/***********************************************************************
 *  rsa
 ***********************************************************************/
void rsa_translate_fixptr(fixed s, fixptr x, fixptr ed, fixptr n, fixptr r)
{
	power_mod_fixptr(s, x, ed, n, r);
}

void rsa_replace_fixptr(fixed s, fixptr x, fixptr ed, fixptr n)
{
	fixptr r;

	r = push1get_fixed(s);
	rsa_translate_fixptr(s, x, ed, n, r);
	memcpy_fixptr(x, r, s->word1);
	pop1_fixed(s);
}

