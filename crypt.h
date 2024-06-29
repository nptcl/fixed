#ifndef __CRYPT_HEADER__
#define __CRYPT_HEADER__

#include "fixed.h"
#include "random.h"

void random_equal_fixptr(struct fixed_random *state, fixptr x, fixptr r, fixsize size);
void random_less_fixptr(struct fixed_random *state, fixptr x, fixptr r, fixsize size);
void random_equal_fixed(fixed s, struct fixed_random *state);
void random_less_fixed(fixed s, struct fixed_random *state);
void random_full_fixptr(struct fixed_random *state, fixptr x, fixsize size);
void random_full_fixed(fixed s, struct fixed_random *state);

void power_mod_fixed(fixed s);
void power_mod_fixptr(fixed s, fixptr x, fixptr y, fixptr n, fixptr r);
extern int make_prime_output;
void make_prime_fixptr(fixed s, struct fixed_random *state, unsigned bit, fixptr r);
void make_prime_fixed(fixed s, struct fixed_random *state, unsigned bit);
void make_rsakey_fixed(fixed s, struct fixed_random *state,
		unsigned bit, unsigned value_e);
void rsa_translate_fixptr(fixed s, fixptr x, fixptr ed, fixptr n, fixptr r);
void rsa_replace_fixptr(fixed s, fixptr x, fixptr ed, fixptr n);

#endif

