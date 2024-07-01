#include <stdio.h>
#include "addition.h"
#include "fixed.h"
#include "crypt.h"
#include "elliptic.h"
#include "public.h"
#include "random.h"
#include "signature.h"

/*
 *  main
 */
static void output_main(fixed s, fixsize word1, const char *x)
{
	printf("%s", x);
	print1_fixed(s, word1, stdout, 16);
	printf("\n");
}

int main_rsa(void)
{
	fixed s;
	fixsize bit_count, stack_size;
	fixptr e, d, n;
	fixptr x1, x2, x3, x4, x5;
	struct fixed_random state;

	bit_count = 256;
	stack_size = 100;

	init_fixrandom();
	make_fixrandom(&state);

	s = make_fixed(bit_count, stack_size);
	if (s == NULL) {
		fprintf(stderr, "make_fixed error.\n");
		return 0;
	}

	/* rsakey */
	make_prime_output = 1;
	make_rsakey_fixed(s, &state, bit_count, 0);
	output_main(s, 4, "e: ");
	output_main(s, 3, "d: ");
	output_main(s, 2, "n: ");
	output_main(s, 1, "p: ");
	output_main(s, 0, "q: ");
	e = get1_fixed(s, 4);
	d = get1_fixed(s, 3);
	n = get1_fixed(s, 2);

	/* data */
	x1 = push1u_fixed(s, 0x10);
	x2 = push1u_fixed(s, 0x20);
	x3 = push1u_fixed(s, 0x30);
	x4 = push1u_fixed(s, 0x40);
	x5 = push1u_fixed(s, 0x50);
	output_main(s, 4, "x1: ");
	output_main(s, 3, "x2: ");
	output_main(s, 2, "x3: ");
	output_main(s, 1, "x4: ");
	output_main(s, 0, "x5: ");

	/* encode */
	rsa_replace_fixptr(s, x1, e, n);
	rsa_replace_fixptr(s, x2, e, n);
	rsa_replace_fixptr(s, x3, e, n);
	rsa_replace_fixptr(s, x4, e, n);
	rsa_replace_fixptr(s, x5, e, n);
	output_main(s, 4, "x1.encode: ");
	output_main(s, 3, "x2.encode: ");
	output_main(s, 2, "x3.encode: ");
	output_main(s, 1, "x4.encode: ");
	output_main(s, 0, "x5.encode: ");

	/* decode */
	rsa_replace_fixptr(s, x1, d, n);
	rsa_replace_fixptr(s, x2, d, n);
	rsa_replace_fixptr(s, x3, d, n);
	rsa_replace_fixptr(s, x4, d, n);
	rsa_replace_fixptr(s, x5, d, n);
	output_main(s, 4, "x1.decode: ");
	output_main(s, 3, "x2.decode: ");
	output_main(s, 2, "x3.decode: ");
	output_main(s, 1, "x4.decode: ");
	output_main(s, 0, "x5.decode: ");

	free_fixed(s);

	return 0;
}

int main(void)
{
	printf("*** RSA\n");
	main_rsa();
	printf("\n\n*** ECDSA, EdDSA\n");
	genkey_elliptic();
	return 0;
}

