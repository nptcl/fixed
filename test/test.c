#include <stdio.h>
#include <stdlib.h>
#include "elliptic.h"
#include "fixed.h"
#include "random.h"
#include "test.h"

/***********************************************************************
 *  test function
 ***********************************************************************/
int test_count = 0;
int test_error = 0;
int test_switch = 0;
int test_position = 0;

int test_execute(int check, const char *name)
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

void test_abort(void)
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
 *  main
 ***********************************************************************/
struct fixed_random random_state;

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
	init_fixrandom();
	init_elliptic();
	make_fixrandom(&random_state);

	test_fixed();
	test_elliptic();
	test_encode();
	if (test_error)
		test_abort();
	printf("OK: %d.\n", test_count);

	return 0;
}

