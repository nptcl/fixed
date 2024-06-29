#ifndef __FIXED_ADDITION_HEADER__
#define __FIXED_ADDITION_HEADER__

#include "elliptic.h"
#include "fixed.h"

void addition_secp256k1(fixed s, fixptr3 a, fixptr3 b, fixptr3 r);
void addition_secp256r1(fixed s, fixptr3 a, fixptr3 b, fixptr3 r);
void addition_ed25519(fixed s, fixptr4 a, fixptr4 b, fixptr4 r);
void addition_ed448(fixed s, fixptr3 a, fixptr3 b, fixptr3 r);

void doubling_secp256k1(fixed s, fixptr3 a, fixptr3 r);
void doubling_secp256r1(fixed s, fixptr3 a, fixptr3 r);
void doubling_ed25519(fixed s, fixptr4 a, fixptr4 r);
void doubling_ed448(fixed s, fixptr3 a, fixptr3 r);

void multiple_secp256k1(fixed s, fixptr n, fixptr3 a, fixptr3 r);
void multiple_secp256r1(fixed s, fixptr n, fixptr3 a, fixptr3 r);
void multiple_ed25519(fixed s, fixptr n, fixptr4 a, fixptr4 r);
void multiple_ed448(fixed s, fixptr n, fixptr3 a, fixptr3 r);

#endif

