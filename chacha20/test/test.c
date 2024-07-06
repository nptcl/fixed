#include <stdio.h>
#include <stdlib.h>
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
 *  test_chacha20
 ***********************************************************************/
#include "chacha20.h"
#include "chacha20.c"

#if 0
static void test_setkey(struct aes *a, const char *str)
{
	int i, k, x, y;

	memset(a->key, 0, 32);
	for (i = 0; ; i++) {
		k = i * 2;
		if (str[k] == 0)
			break;
		x = test_setkey_char(str[k]);
		y = test_setkey_char(str[k + 1]);
		a->key[i] = ((x & 0x0F) << 4) | (y & 0x0F);
	}
}

static void test_setstate(struct aes *a, const char *str)
{
	int i, k, x, y;

	memset(a->state, 0, 16);
	for (i = 0; ; i++) {
		k = i * 2;
		if (str[k] == 0)
			break;
		x = test_setkey_char(str[k]);
		y = test_setkey_char(str[k + 1]);
		a->state[i] = ((x & 0x0F) << 4) | (y & 0x0F);
	}
}
#endif

static int test_setkey_char(char x)
{
	if ('0' <= x && x <= '9')
		return x - '0';
	if ('a' <= x && x <= 'f')
		return x - 'a' + 10;
	if ('A' <= x && x <= 'F')
		return x - 'A' + 10;

	return 0;  /* error */
}

static int test_string(const uint8_t *mem, const char *str)
{
	uint8_t r;
	int i, x, y;

	for (i = 0; ; i++) {
		x = str[i * 2];
		if (x == 0)
			break;
		y = str[i * 2 + 1];
		if (y == 0)
			return 0;
		x = test_setkey_char(x);
		y = test_setkey_char(y);
		r = ((x & 0x0F) << 4) | (y & 0x0F);
		if (mem[i] != r)
			return 0;
	}

	return 1;
}

static int test_key(void)
{
	struct chacha20 c;

	memset(&c, 0xAA, sizeof(c));
	chacha20_key(&c, "a", 1);
	test(c.key[0] == 0x61, "key.1");
	test(c.key[1] == 0x00, "key.2");
	test(c.key[7] == 0x00, "key.3");

	memset(&c, 0xAA, sizeof(c));
	chacha20_key(&c, "ab", 2);
	test(c.key[0] == 0x6261, "key.4");
	test(c.key[1] == 0x00, "key.5");
	test(c.key[7] == 0x00, "key.6");

	Return;
}

void println_memory(const uint8_t *mem, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (i && ((i % 16) == 0))
			printf("\n");
		printf(" %02x", mem[i]);
	}
	printf("\n");
}

static int test_example(void)
{
	uint8_t key[32];
	int i, check;
	struct chacha20 c;
	static const char message[] =
		"Ladies and Gentlemen of the class of '99: "
		"If I could offer you only one tip for the future, "
		"sunscreen would be it.";
	uint8_t output[sizeof(message)];

	for (i = 0; i < 32; i++)
		key[i] = i;
	chacha20_key(&c, key, 32);
	chacha20_nonce(&c,
			"\x00\x00\x00\x00"
			"\x00\x00\x00\x4a"
			"\x00\x00\x00\x00",
			12);
	chacha20_encrypt(&c, message, output, sizeof(message));
	check = test_string(output,
			"6e2e359a2568f98041ba0728dd0d6981"
			"e97e7aec1d4360c20a27afccfd9fae0b"
			"f91b65c5524733ab8f593dabcd62b357"
			"1639d624e65152ab8f530c359f0861d8"
			"07ca0dbf500d6a6156a38e088a22b65e"
			"52bc514d16ccf806818ce91ab7793736"
			"5af90bbf74a35be6b40b8eedf2785e42"
			"874d");
	test(check, "example.1");

	c.counter = 1;
	chacha20_replace(&c, output, sizeof(message));
	test(strcmp(message, (const char *)output) == 0, "example.2");

	Return;
}

static int test_chacha20(void)
{
	TestCall(test_key);
	TestCall(test_example);

	return 0;
}


/***********************************************************************
 *  main
 ***********************************************************************/
int main(void)
{
	test_chacha20();
	if (test_error)
		test_abort();
	printf("OK: %d.\n", test_count);

	return 0;
}

