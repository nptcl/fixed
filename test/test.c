#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "fixed.h"
#include "crypt.h"

/***********************************************************************
 *  test function
 ***********************************************************************/
#define test(x, y) { if (test_execute((x) != 0, (y))) goto error; }
#define Return { return 0; error: return 1; }
#define TestCall(x) { if (x()) {test_error++; return 1; }}
#define FIXED_DEGRADE_WIDTH		70

static int test_count = 0;
static int test_error = 0;
static int test_switch = 0;
static int test_position = 0;

static int test_execute(int check, const char *name)
{
	test_count++;
	if (check) {
		if (test_switch) {
			printf(".");
			test_position++;
			if (FIXED_DEGRADE_WIDTH <= test_position) {
				printf("\n");
				test_position = 0;
			}
		}
		else {
			printf("[OK] %7d: %s\n", test_count, name);
		}
		return 0;
	}
	else {
		if (test_switch) {
			if (test_position != 0) {
				printf("\n");
				test_position = 0;
			}
		}
		printf("[ERROR] %7d: %s\n", test_count, name);
		test_error++;
		return 1;
	}
}

static void test_abort(void)
{
	printf("\n");
	fflush(NULL);
	printf("*************\n");
	printf("**  ERROR  **\n");
	printf("*************\n");
	fflush(NULL);
	exit(1);
}


/***********************************************************************
 *  fixed
 ***********************************************************************/
static int test_make_fixed(void)
{
	fixed s;

	s = make_fixed(1024, 10);
	test(s, "make_fixed.1");
	test(s->carry == 0, "make_fixed.2");
	test(s->stack != NULL, "make_fixed.3");
	test(s->bit1 == 1024, "make_fixed.4");
	test(s->bit2 == 2048, "make_fixed.5");
#if defined(FIXED_8BIT)
	test(s->word1 == 128, "make_fixed.6");
	test(s->word2 == 256, "make_fixed.7");
#elif defined(FIXED_16BIT)
	test(s->word1 == 64, "make_fixed.6");
	test(s->word2 == 128, "make_fixed.7");
#elif defined(FIXED_32BIT)
	test(s->word1 == 32, "make_fixed.6");
	test(s->word2 == 64, "make_fixed.7");
#else
	test(s->word1 == 16, "make_fixed.6");
	test(s->word2 == 32, "make_fixed.7");
#endif
	test(s->byte1 == 128, "make_fixed.8");
	test(s->byte2 == 256, "make_fixed.9");
	free_fixed(s);
	test(1, "free_fixed.1");

	Return;
}

static int test_set1u_fixed()
{
	int x, y;
	fixed s;

	s = make_fixed(1024, 10);
	push1_fixed(s);
	/* 0 */
	set1u_fixed(s, 0, 0);
	test(zerop1_fixed(s, 0), "set1u_fixed.1");
	/* 1 */
	set1u_fixed(s, 0, 1);
	test(onep1_fixed(s, 0), "set1u_fixed.2");
	/* 2 */
	set1u_fixed(s, 0, 2);
	x = read1_compare_fixed(s, 0, "2", 10, &y);
	test(x == 0 && y == 0, "set1u_fixed.3");
	/* 0xFF */
	set1u_fixed(s, 0, 0xFF);
	x = read1_compare_fixed(s, 0, "255", 10, &y);
	test(x == 0 && y == 0, "set1u_fixed.4");
	/* 0xABCD */
	set1u_fixed(s, 0, 0xABCD);
	x = read1_compare_fixed(s, 0, "ABCD", 16, &y);
	test(x == 0 && y == 0, "set1u_fixed.5");
	free_fixed(s);

	Return;
}

static int test_get1u_fixed()
{
	fixed s;
	unsigned u;

	s = make_fixed(1024, 10);
	push1_fixed(s);
	/* 0 */
	set1u_fixed(s, 0, 0);
	u = 123;
	test(get1u_fixed(s, 0, &u) == 0, "get1u_fixed.1");
	test(u == 0, "get1u_fixed.2");
	/* 1 */
	set1u_fixed(s, 0, 1);
	u = 123;
	test(get1u_fixed(s, 0, &u) == 0, "get1u_fixed.3");
	test(u == 1, "get1u_fixed.4");
	/* 2 */
	set1u_fixed(s, 0, 2);
	u = 123;
	test(get1u_fixed(s, 0, &u) == 0, "get1u_fixed.5");
	test(u == 2, "get1u_fixed.6");
	/* 0xFF */
	set1u_fixed(s, 0, 0xFF);
	u = 123;
	test(get1u_fixed(s, 0, &u) == 0, "get1u_fixed.7");
	test(u == 0xFF, "get1u_fixed.8");
	/* 0xABCD */
	set1u_fixed(s, 0, 0xABCD);
	u = 123;
	test(get1u_fixed(s, 0, &u) == 0, "get1u_fixed.9");
	test(u == 0xABCD, "get1u_fixed.10");
	free_fixed(s);

	Return;
}

#define file_isspace(x)  ((c) == ' ' || (c) == '\t')

static int file_space(FILE *file)
{
	char c;

first:
	c = fgetc(file);
	if (c == EOF)
		return EOF;
	if (file_isspace(c))
		goto first;
	ungetc(c, file);
	return c;
}

#define FIXED_TEST_SIZE		64
static void file_int(FILE *file, int radix, int *ret)
{
	int i;
	char c, str[FIXED_TEST_SIZE], *p;

	c = file_space(file);
	if (c == EOF || c == '\n') {
		printf("file_int EOF error.\n");
		test_abort();
	}
	i = 0;
	for (;;) {
		c = fgetc(file);
		if (c == EOF)
			break;
		if (isdigit(c) || isalpha(c)) {
			if (FIXED_TEST_SIZE <= i) {
				printf("file_int buffer error.\n");
				test_abort();
			}
			str[i++] = c;
			continue;
		}
		ungetc(c, file);
		break;
	}
	if (i == 0) {
		printf("file_int format error.\n");
		test_abort();
	}
	str[i] = 0;
	*ret = (int)strtol(str, &p, radix);
	if (*p) {
		printf("file_int strtol error: %s.\n", str);
		test_abort();
	}
}

static void file_next(FILE *file)
{
	char c;

first:
	c = fgetc(file);
	if (c == EOF || c == '\n')
		return;
	if (! file_isspace(c)) {
		printf("file_next error.\n");
		test_abort();
	}
	goto first;
}


static void test_file_open(fixed *rs, FILE **rfile, const char *filename)
{
	int bit;
	FILE *file;
	fixed s;

	file = fopen(filename, "r");
	if (file == NULL) {
		printf("Cannot open file %s.\n", filename);
		test_abort();
	}

	/* bit */
	file_int(file, 10, &bit);
	s = make_fixed(bit, 100);
	file_next(file);

	*rfile = file;
	*rs = s;
}

static void test_file_close(fixed s, FILE *file)
{
	free_fixed(s);
	fclose(file);
}

static void file_push_value(fixed s, FILE *file, int radix)
{
	int size2, check;
	char c;

	/* push */
	c = fgetc(file);
	if (c == '=') {
		size2 = 1;
		push2v_fixed(s, 0);
	}
	else {
		size2 = 0;
		push1v_fixed(s, 0);
		ungetc(c, file);
	}

	/* loop */
	for (;;) {
		c = fgetc(file);
		if (c == EOF)
			break;
		if (file_isspace(c) || c == '\n') {
			ungetc(c, file);
			break;
		}
		if (isdigit(c) || isalpha(c)) {
			check = size2?
				read2_char_fixed(s, 1, (unsigned)radix, c):
				read1_char_fixed(s, 0, (unsigned)radix, c);
			if (check) {
				printf("read_char_fixed error: %c.\n", c);
				test_abort();
			}
			continue;
		}
		printf("file_push_value error: %c.\n", c);
		test_abort();
	}
}

static int test_file_push(fixed s, FILE *file)
{
	int c, radix, x;

retry:
	c = file_space(file);
	if (c == EOF)
		return -1;
	if (c == '\n') {
		file_next(file);
		goto retry;
	}
	file_int(file, 10, &radix);
	if (feof(file))
		return -1;  /* radix, EOF */
	for (x = 0; ; x++) {
		c = file_space(file);
		if (c == EOF)
			break;
		if (c == '\n') {
			file_next(file);
			break;
		}
		file_push_value(s, file, radix);
	}

	return x;
}

static int test_inc1s(void)
{
	int x;
	FILE *file;
	fixed s;
	fixsize a, b;

	/* testcase */
	s = make_fixed(1024, 100);
	push1u_fixed(s, 100);
	a = s->index;
	inc1s_fixed(s);
	b = s->index;
	read1_compare_fixed(s, 0, "101", 10, &x);
	test(x == 0, "inc1s.1");
	pop1_fixed(s);
	test(a == b, "inc1s.2");
	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "inc.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("inc1s: ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		dup1_fixed(s, 1);
		inc1s_fixed(s);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "inc1s.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "inc1s.data");

	Return;
}

static int test_inc1p(void)
{
	int x;
	FILE *file;
	fixed s;
	fixsize a, b;

	/* testcase */
	s = make_fixed(1024, 100);
	push1u_fixed(s, 100);
	a = s->index;
	inc1p_fixed(s);
	read1_compare_fixed(s, 0, "101", 10, &x);
	test(x == 0, "inc1p.1");
	pop1_fixed(s);
	b = s->index;
	test(a == b, "inc1p.2");
	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "inc.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("inc1p: ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		dup1_fixed(s, 1);
		inc1p_fixed(s);
		if (compare1_fixed(s, 0, 2)) {
			test(0, "inc1p.data");
		}
		pop1n_fixed(s, 2);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "inc1p.data");

	Return;
}

static int test_shiftl1(void)
{
	int x;
	unsigned shift;
	FILE *file;
	fixed s;
	fixsize a, b;

	/* testcase */
	s = make_fixed(1024, 100);
	push1u_fixed(s, 100);
	a = s->index;
	shiftl1_fixed(s, 0, 0);
	b = s->index;
	read1_compare_fixed(s, 0, "100", 10, &x);
	test(a == b && x == 0, "shiftl1.1");

	set1u_fixed(s, 0, 100);
	a = s->index;
	shiftl1_fixed(s, 0, 1);
	b = s->index;
	read1_compare_fixed(s, 0, "200", 10, &x);
	test(a == b && x == 0, "shiftl1.2");

	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "shiftl.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("shiftl1: ");
		output1_fixed(s, 2, stdout, 16);
		printf(" ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		get1u_fixed(s, 1, &shift);
		dup1_fixed(s, 2);
		shiftl1_fixed(s, 0, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "shiftl1.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "shiftl1.data");

	Return;
}

static int test_shiftr1(void)
{
	int x;
	unsigned shift;
	FILE *file;
	fixed s;
	fixsize a, b;

	/* testcase */
	s = make_fixed(1024, 100);
	push1u_fixed(s, 100);
	a = s->index;
	shiftr1_fixed(s, 0, 0);
	b = s->index;
	read1_compare_fixed(s, 0, "100", 10, &x);
	test(a == b && x == 0, "shiftr1.1");

	set1u_fixed(s, 0, 100);
	a = s->index;
	shiftr1_fixed(s, 0, 1);
	b = s->index;
	read1_compare_fixed(s, 0, "50", 10, &x);
	test(a == b && x == 0, "shiftr1.2");

	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "shiftr.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("shiftr1: ");
		output1_fixed(s, 2, stdout, 16);
		printf(" ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		get1u_fixed(s, 1, &shift);
		dup1_fixed(s, 2);
		shiftr1_fixed(s, 0, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "shiftr1.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "shiftr1.data");

	Return;
}

static int test_div(void)
{
	int x;
	unsigned u;
	FILE *file;
	fixed s;
	fixsize a, b;

	s = make_fixed(128, 100);

	/* 1/0 */
	push2u_fixed(s, 0);
	push1u_fixed(s, 1);
	a = s->index;
	div_fixed(s);
	b = s->index;
	test(get2u_fixed(s, 2, &u) == 0, "div.1");
	test(u == 0, "div.2");
	test(get1u_fixed(s, 0, &u) == 0, "div.3");
	test(u == 0, "div.4");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.5");

	/* 10/3 */
	push2u_fixed(s, 10);
	push1u_fixed(s, 3);
	a = s->index;
	div_fixed(s);
	b = s->index;
	get2u_fixed(s, 2, &u);
	test(u == 3, "div.6");
	get1u_fixed(s, 0, &u);
	test(u == 1, "div.7");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.8");

	/* FEDCBA9876543210FEDCBA9876543210/1 */
	read2p_fixed(s, "FEDCBA9876543210FEDCBA9876543210", 16);
	push1u_fixed(s, 1);
	a = s->index;
	div_fixed(s);
	b = s->index;
	x = 100;
	read1_compare_fixed(s, 2,"FEDCBA9876543210FEDCBA9876543210", 16, &x);
	test(x == 0, "div.9");
	get1u_fixed(s, 0, &u);
	test(u == 0, "div.10");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.11");

	/* FEDCBA9876543210FEDCBA9876543210/7
	 *  -> 2468ACF13579BE026D8D3F3A5A0C0726, 6
	 */
	read2p_fixed(s, "FEDCBA9876543210FEDCBA9876543210", 16);
	push1u_fixed(s, 7);
	a = s->index;
	div_fixed(s);
	b = s->index;
	x = 100;
	read1_compare_fixed(s, 2,"2468ACF13579BE026D8D3F3A5A0C0726", 16, &x);
	test(x == 0, "div.12");
	get1u_fixed(s, 0, &u);
	test(u == 6, "div.13");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.14");

	/* FE.../FE... */
	read2p_fixed(s, "FEDCBA9876543210FEDCBA9876543210", 16);
	read1p_fixed(s, "FEDCBA9876543210FEDCBA9876543210", 16);
	a = s->index;
	div_fixed(s);
	b = s->index;
	get2u_fixed(s, 2, &u);
	test(u == 1, "div.15");
	get1u_fixed(s, 0, &u);
	test(u == 0, "div.16");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.17");

	/* 7/FEDCBA9876543210FEDCBA9876543210 -> 0, 7 */
	push2u_fixed(s, 7);
	read1p_fixed(s, "FEDCBA9876543210FEDCBA9876543210", 16);
	a = s->index;
	div_fixed(s);
	b = s->index;
	get2u_fixed(s, 2, &u);
	test(u == 0, "div.18");
	get1u_fixed(s, 0, &u);
	test(u == 7, "div.19");
	pop1_fixed(s);
	pop2_fixed(s);
	test(a == b, "div.20");
	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "div.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("div: ");
		output2_fixed(s, 5, stdout, 16); /* x2 */
		printf(" ");
		output1_fixed(s, 3, stdout, 16); /* y1 */
		printf(" ");
		output2_fixed(s, 2, stdout, 16); /* q2 */
		printf(" ");
		output1_fixed(s, 0, stdout, 16); /* r1 */
		printf("\n");

		dup2_fixed(s, 5);    /* 2: q2 */
		dup1_fixed(s, 3+2);  /* 0: r1 */
		a = s->index;
		div_fixed(s);
		b = s->index;
		if (compare2_fixed(s, 2, 2+3)) {
			test(0, "div.quot");
		}
		if (compare1_fixed(s, 0, 0+3)) {
			test(0, "div.rem");
		}
		if (a != b) {
			test(0, "div.index");
		}
		pop1n_fixed(s, 1);  /* r */
		pop2n_fixed(s, 1);  /* q */
		pop1n_fixed(s, 1);  /* r */
		pop2n_fixed(s, 1);  /* q */
		pop1n_fixed(s, 1);  /* y */
		pop2n_fixed(s, 1);  /* x */
	}
	test_file_close(s, file);
	test(1, "div.data");

	Return;
}

static int test_rem(void)
{
	unsigned u;
	fixed s;
	fixsize a, b;

	s = make_fixed(128, 100);
	a = s->index;
	push2u_fixed(s, 10);
	push1u_fixed(s, 7);
	rem_fixed(s);
	test(get1u_fixed(s, 0, &u) == 0, "rem.1");
	test(u == 3, "rem.2");
	pop1_fixed(s);
	b = s->index;
	test(a == b, "rem.3");
	free_fixed(s);

	Return;
}

static int test_power_mod(void)
{
	int x;
	FILE *file;
	fixed s;
	fixsize a, b;
	fixptr p;

	/* testcase */
	s = make_fixed(1024, 100);
	a = s->index;
	push1u_fixed(s, 10);
	push1u_fixed(s, 20);
	push1u_fixed(s, 7);
	power_mod_fixed(s);
	p = top1_fixed(s);
	test(compare_fixnum_fixptr(p, s->word1, 2) == 0, "power_mod.1");
	pop1_fixed(s);
	b = s->index;
	test(a == b, "power_mod.2");
	free_fixed(s);

	/* data */
	test_file_open(&s, &file, "power_mod.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("power_mod: ");
		output1_fixed(s, 3, stdout, 16);  /* x */
		printf(" ");
		output1_fixed(s, 2, stdout, 16);  /* y */
		printf(" ");
		output1_fixed(s, 1, stdout, 16);  /* n */
		printf(" ");
		output1_fixed(s, 0, stdout, 16);  /* r */
		printf("\n");

		dup1_fixed(s, 3);  /* x */
		dup1_fixed(s, 3);  /* y */
		dup1_fixed(s, 3);  /* n */
		power_mod_fixed(s);
		if (compare1_fixed(s, 0, 1)) {
			output1_fixed(s, 0, stdout, 16);
			printf("\n");
			output1_fixed(s, 1, stdout, 16);
			printf("\n");
			test(0, "power_mod.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "power_mod.data");

	Return;
}

static int test_rotatel(void)
{
	int x;
	unsigned shift;
	FILE *file;
	fixed s;
	fixptr a, b;

	test_file_open(&s, &file, "rotatel.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("rotatel: ");
		output1_fixed(s, 2, stdout, 16);
		printf(" ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		get1u_fixed(s, 1, &shift);

		/* 1 */
		dup1_fixed(s, 2);
		a = top1_fixed(s);
		rotatel1_fixptr(a, s->word1, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotatel1.data");
		}
		pop1_fixed(s);

		/* 2 */
		a = get1_fixed(s, 2);
		b = push1get_fixed(s);
		rotatel2_fixptr(a, b, s->word1, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotatel2.data");
		}
		pop1_fixed(s);

		/* 3 */
		dup1_fixed(s, 2);
		a = top1_fixed(s);
		b = push1get_fixed(s);
		rotatel3_fixptr(a, b, s->word1, (fixsize)shift);
		pop1_fixed(s);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotatel3.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "rotatel.data");

	Return;
}

static int test_rotater(void)
{
	int x;
	unsigned shift;
	FILE *file;
	fixed s;
	fixptr a, b;

	test_file_open(&s, &file, "rotater.txt");
	for (;;) {
		x = test_file_push(s, file);
		if (x < 0)
			break;
		/* test */
		printf("rotater: ");
		output1_fixed(s, 2, stdout, 16);
		printf(" ");
		output1_fixed(s, 1, stdout, 16);
		printf(" ");
		output1_fixed(s, 0, stdout, 16);
		printf("\n");
		get1u_fixed(s, 1, &shift);

		/* 1 */
		dup1_fixed(s, 2);
		a = top1_fixed(s);
		rotater1_fixptr(a, s->word1, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotater1.data");
		}
		pop1_fixed(s);

		/* 2 */
		a = get1_fixed(s, 2);
		b = push1get_fixed(s);
		rotater2_fixptr(a, b, s->word1, (fixsize)shift);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotater2.data");
		}
		pop1_fixed(s);

		/* 3 */
		dup1_fixed(s, 2);
		a = top1_fixed(s);
		b = push1get_fixed(s);
		rotater3_fixptr(a, b, s->word1, (fixsize)shift);
		pop1_fixed(s);
		if (compare1_fixed(s, 0, 1)) {
			test(0, "rotater3.data");
		}
		pop1_fixed(s);
		pop1n_fixed(s, x);
	}
	test_file_close(s, file);
	test(1, "rotater.data");

	Return;
}

static int test_fixed(void)
{
	TestCall(test_make_fixed);
	TestCall(test_set1u_fixed);
	TestCall(test_get1u_fixed);
	TestCall(test_inc1s);
	TestCall(test_inc1p);
	TestCall(test_shiftl1);
	TestCall(test_shiftr1);
	TestCall(test_div);
	TestCall(test_rem);
	TestCall(test_power_mod);
	TestCall(test_rotatel);
	TestCall(test_rotater);

	return 0;
}


/***********************************************************************
 *  main
 ***********************************************************************/
int main(void)
{
	/* infomation */
#ifdef FIXED_DEBUG
	printf("Debug: ");
#else
	printf("Release: ");
#endif
	printf("%dbit\n", FIXED_FULLBIT);

	/* test */
	init_fixed();
	test_fixed();
	if (test_error)
		test_abort();
	printf("OK: %d.\n", test_count);

	return 0;
}

