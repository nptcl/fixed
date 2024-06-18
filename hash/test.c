#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"

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
 *  MD5
 ***********************************************************************/
static int test_sha1str(const char *input, const char *check)
{
	uint8_t y[BYTE_SHA1ENCODE];
	char z[BYTE_SHA1ENCODE * 2 + 1];
	int i;
	struct sha32encode x;

	init_sha1encode(&x);
	read_sha1encode(&x, input, strlen(input));
	calc_sha1encode(&x, y);
	for (i = 0; i < BYTE_SHA1ENCODE; i++)
		sprintf(z + (i * 2), "%02x", (int)y[i]);
	z[BYTE_SHA1ENCODE * 2] = 0;

	if (strcmp(check, z) == 0)
		return 1;
	printf("ERROR: SHA1\n");
	printf("  Input: %s\n", z);
	printf("  Check: %s\n", check);

	return 0;
}

static int test_md5str(const char *input, const char *check)
{
	uint8_t y[BYTE_MD5ENCODE];
	char z[BYTE_MD5ENCODE * 2 + 1];
	int i;
	struct sha32encode x;

	init_md5encode(&x);
	read_md5encode(&x, input, strlen(input));
	calc_md5encode(&x, y);
	for (i = 0; i < BYTE_MD5ENCODE; i++)
		sprintf(z + (i * 2), "%02x", (int)y[i]);
	z[BYTE_MD5ENCODE * 2] = 0;

	if (strcmp(check, z) == 0)
		return 1;
	printf("ERROR: MD5\n");
	printf("  Input: %s\n", z);
	printf("  Check: %s\n", check);

	return 0;
}

static int test_hash_call(void)
{
	test(test_md5str("", "d41d8cd98f00b204e9800998ecf8427e"), "md5.1");
	test(test_md5str("a", "0cc175b9c0f1b6a831c399e269772661"), "md5.2");
	test(test_sha1str("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1.1");
	test(test_sha1str("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"), "sha1.2");

	Return;
}

static int test_hash_read(const char *name, int size,
	void (*call)(const char *, void *))
{
	uint8_t a[0x010000];
	char x[0x010000], y[0x010000], z[0x01000];
	FILE *file;
	int i, check;

	file = fopen(name, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen error\n");
		exit(1);
	}
	while (! feof(file)) {
		if (fscanf(file, "%s", x) == EOF)
			break;
		if (fscanf(file, "%s", y) == EOF) {
			fprintf(stderr, "fscanf error\n");
			exit(1);
		}
		(*call)(x, a);
		for (i = 0; i < size; i++)
			sprintf(z + (i * 2), "%02x", (int)a[i]);
		z[size * 2] = 0;

		check = strcmp(y, z);
		if (check != 0) {
			printf("ERROR: %s\n", name);
			printf("  Input1: %s\n", x);
			printf("  Input2: %s\n", y);
			printf("  Check1: %s\n", z);
			test(0, name);
		}
	}
	fclose(file);
	test(1, name);

	Return;
}

static void test_sha3_256_encode(const char *str, void *ret)
{
	struct sha3encode hash;

	init_sha3_256_encode(&hash);
	read_sha3encode(&hash, (const void *)str, strlen(str));
	calc_sha3encode(&hash, ret);
}

static void test_sha3_512_encode(const char *str, void *ret)
{
	struct sha3encode hash;

	init_sha3_512_encode(&hash);
	read_sha3encode(&hash, (const void *)str, strlen(str));
	calc_sha3encode(&hash, ret);
}

static void test_shake_256_256_encode(const char *str, void *ret)
{
	struct sha3encode hash;

	init_shake_256_encode(&hash);
	read_sha3encode(&hash, (const void *)str, strlen(str));
	result_sha3encode(&hash, ret, 256 / 8);
}

static void test_shake_256_800_encode(const char *str, void *ret)
{
	struct sha3encode hash;

	init_shake_256_encode(&hash);
	read_sha3encode(&hash, (const void *)str, strlen(str));
	result_sha3encode(&hash, ret, 800 / 8);
}

static int test_hash_md5(void)
{
	return test_hash_read("hash.md5", BYTE_MD5ENCODE, string_md5encode);
}

static int test_hash_sha1(void)
{
	return test_hash_read("hash.sha1", BYTE_SHA1ENCODE, string_sha1encode);
}

static int test_hash_sha256(void)
{
	return test_hash_read("hash.sha256", BYTE_SHA256ENCODE, string_sha256encode);
}

static int test_hash_sha512(void)
{
	return test_hash_read("hash.sha512", BYTE_SHA512ENCODE, string_sha512encode);
}

static int test_hash_sha3_256(void)
{
	return test_hash_read("hash.sha3-256", BYTE_SHA256ENCODE, test_sha3_256_encode);
}

static int test_hash_sha3_512(void)
{
	return test_hash_read("hash.sha3-512", BYTE_SHA512ENCODE, test_sha3_512_encode);
}

static int test_hash_shake_256_256(void)
{
	return test_hash_read("hash.shake-256-256", BYTE_SHA256ENCODE,
			test_shake_256_256_encode);
}

static int test_hash_shake_256_800(void)
{
	return test_hash_read("hash.shake-256-800", 800/8, test_shake_256_800_encode);
}

static int test_hash(void)
{
	TestCall(test_hash_call);
	TestCall(test_hash_md5);
	TestCall(test_hash_sha1);
	TestCall(test_hash_sha256);
	TestCall(test_hash_sha512);
	TestCall(test_hash_sha3_256);
	TestCall(test_hash_sha3_512);
	TestCall(test_hash_shake_256_256);
	TestCall(test_hash_shake_256_800);

	return 0;
}


/***********************************************************************
 *  main
 ***********************************************************************/
int main(void)
{
	test_hash();
	if (test_error)
		test_abort();
	printf("OK: %d.\n", test_count);

	return 0;
}

