#ifndef __CRYPT_HEADER__
#define __CRYPT_HEADER__

#include "fixed.h"

void power_mod_fixed(fixed s);
void power_mod_fixptr(fixed s, fixptr x, fixptr y, fixptr n, fixptr r);
extern int make_prime_output;
void make_prime_fixptr(fixed s, unsigned bit, fixptr r);
void make_prime_fixed(fixed s, unsigned bit);
void make_rsakey_fixed(fixed s, unsigned bit, unsigned value_e);
void rsa_translate_fixptr(fixed s, fixptr x, fixptr ed, fixptr n, fixptr r);
void rsa_replace_fixptr(fixed s, fixptr x, fixptr ed, fixptr n);

#endif

