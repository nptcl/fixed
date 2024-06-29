#include "elliptic.h"
#include "fixed.h"

#define elliptic_x1		(a[0])
#define elliptic_y1		(a[1])
#define elliptic_z1		(a[2])
#define elliptic_t1		(a[3])

#define elliptic_x2		(b[0])
#define elliptic_y2		(b[1])
#define elliptic_z2		(b[2])
#define elliptic_t2		(b[3])

#define elliptic_x3		(r[0])
#define elliptic_y3		(r[1])
#define elliptic_z3		(r[2])
#define elliptic_t3		(r[3])

/***********************************************************************
 *  secp256k1, addition
 ***********************************************************************/
/*
 *  Projective coordinates for short Weierstrass curves
 *  https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-2007-bl
 *
 *  U1 = X1*Z2
 *  U2 = X2*Z1
 *  S1 = Y1*Z2
 *  S2 = Y2*Z1
 *  ZZ = Z1*Z2
 *  T1 = U1+U2
 *  T2 = T1^2
 *  M = S1+S2
 *  R = T2-U1*U2+a*ZZ^2
 *  F = ZZ*M
 *  K1 = M*F
 *  K2 = K1^2
 *  G = (T1+K1)^2-T2-K2
 *  W = 2*R^2-G
 *  X3 = 2*F*W
 *  Y3 = R*(G-2*W)-2*K2
 *  Z3 = 4*F*F^2
 */
static void addition_weierstrass_elliptic(fixed s,
		fixptr3 a, fixptr3 b, fixptr3 r,
		fixptr curve_p, fixptr curve_a)
{
	fixptr w2, u1, u2, s1, s2, zz, t1, t2, m, r1, f, k1, k2, g, w;
	fixptr x, y;
	fixsize word1, word2;

	word1 = s->word1;
	if (zerop_fixptr(elliptic_z1, word1)) {
		memcpy3_fixed(s, r, b);
		return;
	}
	if (zerop_fixptr(elliptic_z2, word1)) {
		memcpy3_fixed(s, r, a);
		return;
	}
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	u1 = push1get_fixed(s); /* 1 */
	u2 = push1get_fixed(s); /* 1 */
	s1 = push1get_fixed(s); /* 1 */
	s2 = push1get_fixed(s); /* 1 */
	zz = push1get_fixed(s); /* 1 */
	t1 = push1get_fixed(s); /* 1 */
	t2 = push1get_fixed(s); /* 1 */
	m = push1get_fixed(s); /* 1 */
	r1 = push1get_fixed(s); /* 1 */
	f = push1get_fixed(s); /* 1 */
	k1 = push1get_fixed(s); /* 1 */
	k2 = push1get_fixed(s); /* 1 */
	w = push1get_fixed(s); /* 1 */
	g = push1get_fixed(s); /* 1 */
	x = push1get_fixed(s); /* 1 */
	y = push1get_fixed(s); /* 1 */

	/*  U1 = X1*Z2  */
	mul_fixptr(elliptic_x1, elliptic_z2, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u1, curve_p);

	/*  U2 = X2*Z1  */
	mul_fixptr(elliptic_x2, elliptic_z1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u2, curve_p);

	/*  S1 = Y1*Z2  */
	mul_fixptr(elliptic_y1, elliptic_z2, word1, w2, word2);
	rem2_elliptic_curve(s, w2, s1, curve_p);

	/*  S2 = Y2*Z1  */
	mul_fixptr(elliptic_y2, elliptic_z1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, s2, curve_p);

	/*  ZZ = Z1*Z2  */
	mul_fixptr(elliptic_z1, elliptic_z2, word1, w2, word2);
	rem2_elliptic_curve(s, w2, zz, curve_p);

	/*  T1 = U1+U2  */
	add_elliptic_curve(u1, u2, t1, curve_p, word1);

	/*  T2 = T1^2  */
	mul_square_fixptr(t1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, t2, curve_p);

	/*  M = S1+S2  */
	add_elliptic_curve(s1, s2, m, curve_p, word1);

	/*  R = T2-U1*U2+a*ZZ^2  */
	mul_fixptr(u1, u2, word1, w2, word2);
	rem2_elliptic_curve(s, w2, r1, curve_p);
	sub_elliptic_curve(t2, r1, r1, curve_p, word1);
	if (curve_a) {
		mul_square_fixptr(zz, word1, w2, word2);
		rem2_elliptic_curve(s, w2, x, curve_p);
		mul_fixptr(curve_a, x, word1, w2, word2);
		rem2_elliptic_curve(s, w2, x, curve_p);
		add_elliptic_curve(r1, x, r1, curve_p, word1);
	}

	/*  F = ZZ*M  */
	mul_fixptr(zz, m, word1, w2, word2);
	rem2_elliptic_curve(s, w2, f, curve_p);

	/*  K1 = M*F  */
	mul_fixptr(m, f, word1, w2, word2);
	rem2_elliptic_curve(s, w2, k1, curve_p);

	/*  K2 = K1^2  */
	mul_square_fixptr(k1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, k2, curve_p);

	/*  G = (T1+K1)^2-T2-K2  */
	add_elliptic_curve(t1, k1, g, curve_p, word1);
	mul_square_fixptr(g, word1, w2, word2);
	rem2_elliptic_curve(s, w2, g, curve_p);
	sub_elliptic_curve(g, t2, g, curve_p, word1);
	sub_elliptic_curve(g, k2, g, curve_p, word1);

	/*  W = 2*R^2-G  */
	mul_square_fixptr(r1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, w, curve_p);
	dbl_elliptic_curve(w, w, curve_p, word1);
	sub_elliptic_curve(w, g, w, curve_p, word1);

	/*  X3 = 2*F*W  */
	mul_fixptr(f, w, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	dbl_elliptic_curve(x, elliptic_x3, curve_p, word1);

	/*  Y3 = R*(G-2*W)-2*K2  */
	dbl_elliptic_curve(w, x, curve_p, word1);
	sub_elliptic_curve(g, x, x, curve_p, word1);
	mul_fixptr(r1, x, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	dbl_elliptic_curve(k2, y, curve_p, word1);
	sub_elliptic_curve(x, y, elliptic_y3, curve_p, word1);

	/*  Z3 = 4*F*F^2  */
	mul_fixptr(f, f, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	mul_fixptr(x, f, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	dbl_elliptic_curve(x, x, curve_p, word1);
	dbl_elliptic_curve(x, elliptic_z3, curve_p, word1);

	pop1n_fixed(s, 16);
	pop2_fixed(s);
}

void addition_secp256k1(fixed s, fixptr3 a, fixptr3 b, fixptr3 r)
{
	addition_weierstrass_elliptic(s, a, b, r,
			Elliptic_secp256k1_p,
			NULL);
}


/***********************************************************************
 *  secp256r1, addition
 ***********************************************************************/
void addition_secp256r1(fixed s, fixptr3 a, fixptr3 b, fixptr3 r)
{
	addition_weierstrass_elliptic(s, a, b, r,
			Elliptic_secp256r1_p,
			Elliptic_secp256r1_a);
}


/***********************************************************************
 *  ed25519, addition
 ***********************************************************************/
/*
 *  Extended coordinates with a=-1 for twisted Edwards curves
 *  https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
 *
 *  RFC8032
 *  https://datatracker.ietf.org/doc/html/rfc8032
 *
 *  A = (Y1-X1)*(Y2-X2)
 *  B = (Y1+X1)*(Y2+X2)
 *  C = T1*2*d*T2
 *  D = Z1*2*Z2
 *  E = B-A
 *  F = D-C
 *  G = D+C
 *  H = B+A
 *  X3 = E*F
 *  Y3 = G*H
 *  T3 = E*H
 *  Z3 = F*G
 */
void addition_ed25519(fixed s, fixptr4 a, fixptr4 b, fixptr4 r)
{
	fixptr curve_d2;
	fixptr w2, x, y, c, d, e, f, g, h;
	fixsize word1, word2;

	curve_d2 = Elliptic_ed25519_d2;
	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	x = push1get_fixed(s); /* 1 */
	y = push1get_fixed(s); /* 1 */
	c = push1get_fixed(s); /* 1 */
	d = push1get_fixed(s); /* 1 */
	e = push1get_fixed(s); /* 1 */
	f = push1get_fixed(s); /* 1 */
	g = push1get_fixed(s); /* 1 */
	h = push1get_fixed(s); /* 1 */

	/*  A = (Y1-X1)*(Y2-X2)  */
	sub_elliptic_ed25519(elliptic_y1, elliptic_x1, c, word1);
	sub_elliptic_ed25519(elliptic_y2, elliptic_x2, d, word1);
	mul_fixptr(c, d, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, x);

	/*  B = (Y1+X1)*(Y2+X2)  */
	add_elliptic_ed25519(elliptic_y1, elliptic_x1, c, word1);
	add_elliptic_ed25519(elliptic_y2, elliptic_x2, d, word1);
	mul_fixptr(c, d, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, y);

	/*  C = T1*2*d*T2  */
	mul_fixptr(elliptic_t1, elliptic_t2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, c);
	mul_fixptr(c, curve_d2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, c);

	/*  D = Z1*2*Z2  */
	mul_fixptr(elliptic_z1, elliptic_z2, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, d);
	dbl_elliptic_ed25519(d, d, word1);

	/*  E = B-A  */
	sub_elliptic_ed25519(y, x, e, word1);

	/*  F = D-C  */
	sub_elliptic_ed25519(d, c, f, word1);

	/*  G = D+C  */
	add_elliptic_ed25519(d, c, g, word1);

	/*  H = B+A  */
	add_elliptic_ed25519(y, x, h, word1);

	/*  X3 = E*F  */
	mul_fixptr(e, f, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_x3);

	/*  Y3 = G*H  */
	mul_fixptr(g, h, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_y3);

	/*  T3 = E*H  */
	mul_fixptr(e, h, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_t3);

	/*  Z3 = F*G  */
	mul_fixptr(f, g, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_z3);

	/* pop */
	pop1n_fixed(s, 8);
	pop2_fixed(s);
}


/***********************************************************************
 *  ed448, addition
 ***********************************************************************/
/*
 *  Projective coordinates for Edwards curves
 *  https://www.hyperelliptic.org/EFD/g1p/auto-edwards-projective.html
 *
 *  RFC8032
 *  https://datatracker.ietf.org/doc/html/rfc8032
 *
 *  A = Z1*Z2
 *  B = A^2
 *  C = X1*X2
 *  D = Y1*Y2
 *  E = d*C*D
 *  F = B-E
 *  G = B+E
 *  H = (X1+Y1)*(X2+Y2)
 *  X3 = A*F*(H-C-D)
 *  Y3 = A*G*(D-C)
 *  Z3 = F*G
 */
void addition_ed448(fixed s, fixptr3 a, fixptr3 b, fixptr3 r)
{
	fixptr w2, x, y, c, d, e, f, g, h, z;
	fixptr curve_d;
	fixsize word1, word2;

	curve_d = Elliptic_ed448_d;
	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	x = push1get_fixed(s); /* 1 */
	y = push1get_fixed(s); /* 1 */
	c = push1get_fixed(s); /* 1 */
	d = push1get_fixed(s); /* 1 */
	e = push1get_fixed(s); /* 1 */
	f = push1get_fixed(s); /* 1 */
	g = push1get_fixed(s); /* 1 */
	h = push1get_fixed(s); /* 1 */
	z = push1get_fixed(s); /* 1 */

	/*  A = Z1*Z2  */
	mul_fixptr(elliptic_z1, elliptic_z2, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, x);

	/*  B = A^2  */
	mul_square_fixptr(x, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, y);

	/*  C = X1*X2  */
	mul_fixptr(elliptic_x1, elliptic_x2, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, c);

	/*  D = Y1*Y2  */
	mul_fixptr(elliptic_y1, elliptic_y2, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, d);

	/*  E = d*C*D  */
	mul_fixptr(c, d, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, e);
	mul_fixptr(curve_d, e, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, e);

	/*  F = B-E  */
	sub_elliptic_ed448(y, e, f, word1);

	/*  G = B+E  */
	add_elliptic_ed448(y, e, g, word1);

	/*  H = (X1+Y1)*(X2+Y2)  */
	add_elliptic_ed448(elliptic_x1, elliptic_y1, h, word1);
	add_elliptic_ed448(elliptic_x2, elliptic_y2, z, word1);
	mul_fixptr(h, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, h);

	/*  X3 = A*F*(H-C-D)  */
	sub_elliptic_ed448(h, c, z, word1);
	sub_elliptic_ed448(z, d, z, word1);
	mul_fixptr(f, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, z);
	mul_fixptr(x, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_x3);

	/*  Y3 = A*G*(D-C)  */
	sub_elliptic_ed448(d, c, z, word1);
	mul_fixptr(g, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, z);
	mul_fixptr(x, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_y3);

	/*  Z3 = F*G  */
	mul_fixptr(f, g, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_z3);

	/* pop */
	pop1n_fixed(s, 9);
	pop2_fixed(s);
}


/***********************************************************************
 *  secp256k1, doubling
 ***********************************************************************/
/*
 *  Projective coordinates for short Weierstrass curves
 *  https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
 *
 *  XX = X1^2
 *  ZZ = Z1^2  [a!=0]
 *  q = a*ZZ+3*XX  [a!=0]
 *  s1 = 2*Y1*Z1
 *  s2 = s1^2
 *  s3 = s1*s2  [Z3]
 *  r1 = Y1*s1
 *  r2 = r1^2
 *  u = (X1+r1)^2-XX-r2
 *  h = q^2-2*u
 *  X3 = h*s1
 *  Y3 = q*(u-h)-2*r2
 *  Z3 = s3
 */
static void doubling_weierstrass_elliptic(fixed s,
		fixptr3 a, fixptr3 r, fixptr curve_p, fixptr curve_a)
{
	fixptr w2, xx, q, s1, s2, r1, r2, u, h, x, y;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	xx = push1get_fixed(s); /* 1 */
	q = push1get_fixed(s); /* 1 */
	s1 = push1get_fixed(s); /* 1 */
	s2 = push1get_fixed(s); /* 1 */
	r1 = push1get_fixed(s); /* 1 */
	r2 = push1get_fixed(s); /* 1 */
	u = push1get_fixed(s); /* 1 */
	h = push1get_fixed(s); /* 1 */
	x = push1get_fixed(s); /* 1 */
	y = push1get_fixed(s); /* 1 */

	/*  XX = X1^2  */
	mul_square_fixptr(elliptic_x1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, xx, curve_p);

	/*  q = a*ZZ+3*XX  */
	dbl_elliptic_curve(xx, q, curve_p, word1);
	add_elliptic_curve(q, xx, q, curve_p, word1);
	if (curve_a) {
		/*  ZZ = Z1^2  */
		mul_square_fixptr(elliptic_z1, word1, w2, word2);
		rem2_elliptic_curve(s, w2, x, curve_p);
		/*  q += a*ZZ  */
		mul_fixptr(curve_a, x, word1, w2, word2);
		rem2_elliptic_curve(s, w2, x, curve_p);
		add_elliptic_curve(q, x, q, curve_p, word1);
	}

	/*  s1 = 2*Y1*Z1  */
	mul_fixptr(elliptic_y1, elliptic_z1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, s1, curve_p);
	dbl_elliptic_curve(s1, s1, curve_p, word1);

	/*  s2 = s1^2  */
	mul_square_fixptr(s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, s2, curve_p);

	/*  s3 = s1*s2  [Z3 = s3]  */
	mul_fixptr(s1, s2, word1, w2, word2);
	rem2_elliptic_curve(s, w2, elliptic_z3, curve_p);

	/*  r1 = Y1*s1  */
	mul_fixptr(elliptic_y1, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, r1, curve_p);

	/*  r2 = r1^2  */
	mul_square_fixptr(r1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, r2, curve_p);

	/*  u = (X1+r1)^2-XX-r2  */
	add_elliptic_curve(elliptic_x1, r1, u, curve_p, word1);
	mul_square_fixptr(u, word1, w2, word2);
	rem2_elliptic_curve(s, w2, u, curve_p);
	sub_elliptic_curve(u, xx, u, curve_p, word1);
	sub_elliptic_curve(u, r2, u, curve_p, word1);

	/*  h = q^2-2*u  */
	mul_square_fixptr(q, word1, w2, word2);
	rem2_elliptic_curve(s, w2, h, curve_p);
	dbl_elliptic_curve(u, x, curve_p, word1);
	sub_elliptic_curve(h, x, h, curve_p, word1);

	/*  X3 = h*s1  */
	mul_fixptr(h, s1, word1, w2, word2);
	rem2_elliptic_curve(s, w2, elliptic_x3, curve_p);

	/*  Y3 = q*(u-h)-2*r2  */
	sub_elliptic_curve(u, h, x, curve_p, word1);
	mul_fixptr(q, x, word1, w2, word2);
	rem2_elliptic_curve(s, w2, x, curve_p);
	dbl_elliptic_curve(r2, y, curve_p, word1);
	sub_elliptic_curve(x, y, elliptic_y3, curve_p, word1);

	/*  Z3 = s3  */

	/* pop */
	pop1n_fixed(s, 10);
	pop2_fixed(s);
}

void doubling_secp256k1(fixed s, fixptr3 a, fixptr3 r)
{
	doubling_weierstrass_elliptic(s, a, r,
			Elliptic_secp256k1_p,
			NULL);
}


/***********************************************************************
 *  secp256r1, doubling
 ***********************************************************************/
void doubling_secp256r1(fixed s, fixptr3 a, fixptr3 r)
{
	doubling_weierstrass_elliptic(s, a, r,
			Elliptic_secp256r1_p,
			Elliptic_secp256r1_a);
}


/***********************************************************************
 *  ed25519, doubling
 ***********************************************************************/
/*
 *  Extended coordinates with a=-1 for twisted Edwards curves
 *  https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
 *
 *  RFC8032
 *  https://datatracker.ietf.org/doc/html/rfc8032
 *
 *  A = X1^2
 *  B = Y1^2
 *  C = 2*Z1^2
 *  H = A+B
 *  E = H-(X1+Y1)^2
 *  G = A-B
 *  F = C+G
 *  X3 = E*F
 *  Y3 = G*H
 *  T3 = E*H
 *  Z3 = F*G
 */
void doubling_ed25519(fixed s, fixptr4 a, fixptr4 r)
{
	fixptr w2, x, y, c, e, f, g, h;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	x = push1get_fixed(s); /* 1 */
	y = push1get_fixed(s); /* 1 */
	c = push1get_fixed(s); /* 1 */
	e = push1get_fixed(s); /* 1 */
	f = push1get_fixed(s); /* 1 */
	g = push1get_fixed(s); /* 1 */
	h = push1get_fixed(s); /* 1 */

	/*  A = X1^2  */
	mul_square_fixptr(elliptic_x1, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, x);

	/*  B = Y1^2  */
	mul_square_fixptr(elliptic_y1, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, y);

	/*  C = 2*Z1^2  */
	mul_square_fixptr(elliptic_z1, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, c);
	dbl_elliptic_ed25519(c, c, word1);

	/*  H = A+B  */
	add_elliptic_ed25519(x, y, h, word1);

	/*  E = H-(X1+Y1)^2  */
	add_elliptic_ed25519(elliptic_x1, elliptic_y1, e, word1);
	mul_square_fixptr(e, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, e);
	sub_elliptic_ed25519(h, e, e, word1);

	/*  G = A-B  */
	sub_elliptic_ed25519(x, y, g, word1);

	/*  F = C+G  */
	add_elliptic_ed25519(c, g, f, word1);

	/*  X3 = E*F  */
	mul_fixptr(e, f, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_x3);

	/*  Y3 = G*H  */
	mul_fixptr(g, h, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_y3);

	/*  T3 = E*H  */
	mul_fixptr(e, h, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_t3);

	/*  Z3 = F*G  */
	mul_fixptr(f, g, word1, w2, word2);
	rem2_elliptic_ed25519(s, w2, elliptic_z3);

	/* pop */
	pop1n_fixed(s, 7);
	pop2_fixed(s);
}


/***********************************************************************
 *  ed448, doubling
 ***********************************************************************/
/*
 *  Projective coordinates for Edwards curves
 *  https://www.hyperelliptic.org/EFD/g1p/auto-edwards-projective.html
 *
 *  RFC8032
 *  https://datatracker.ietf.org/doc/html/rfc8032
 *
 *  B = (X1+Y1)^2
 *  C = X1^2
 *  D = Y1^2
 *  E = C+D
 *  H = Z1^2
 *  J = E-2*H
 *  X3 = (B-E)*J
 *  Y3 = E*(C-D)
 *  Z3 = E*J
 */
void doubling_ed448(fixed s, fixptr3 a, fixptr3 r)
{
	fixptr w2, x, c, d, e, h, j, z;
	fixsize word1, word2;

	word1 = s->word1;
	word2 = s->word2;
	w2 = push2get_fixed(s); /* 2 */
	x = push1get_fixed(s); /* 1 */
	c = push1get_fixed(s); /* 1 */
	d = push1get_fixed(s); /* 1 */
	e = push1get_fixed(s); /* 1 */
	h = push1get_fixed(s); /* 1 */
	j = push1get_fixed(s); /* 1 */
	z = push1get_fixed(s); /* 1 */

	/*  B = (X1+Y1)^2  */
	add_elliptic_ed448(elliptic_x1, elliptic_y1, x, word1);
	mul_square_fixptr(x, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, x);

	/*  C = X1^2  */
	mul_square_fixptr(elliptic_x1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, c);

	/*  D = Y1^2  */
	mul_square_fixptr(elliptic_y1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, d);

	/*  E = C+D  */
	add_elliptic_ed448(c, d, e, word1);

	/*  H = Z1^2  */
	mul_square_fixptr(elliptic_z1, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, h);

	/*  J = E-2*H  */
	dbl_elliptic_ed448(h, j, word1);
	sub_elliptic_ed448(e, j, j, word1);

	/*  X3 = (B-E)*J  */
	sub_elliptic_ed448(x, e, z, word1);
	mul_fixptr(z, j, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_x3);

	/*  Y3 = E*(C-D)  */
	sub_elliptic_ed448(c, d, z, word1);
	mul_fixptr(e, z, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_y3);

	/*  Z3 = E*J  */
	mul_fixptr(e, j, word1, w2, word2);
	rem2_elliptic_ed448(s, w2, elliptic_z3);

	/* pop */
	pop1n_fixed(s, 7);
	pop2_fixed(s);
}


/***********************************************************************
 *  multiple
 ***********************************************************************/
static void mul3_elliptic_curve(fixed s,
		fixptr n, fixptr3 a, fixptr3 r,
		void (*addition)(fixed, fixptr3, fixptr3, fixptr3),
		void (*doubling)(fixed, fixptr3, fixptr3),
		fixptr3 curve_o)
{
	unsigned size, i;
	fixptr3 z;
	fixsize word1;

	word1 = s->word1;
	size = logsize_fixptr(n, word1);
	if (size == 0) {
		memcpy3_fixed(s, r, curve_o);
		return;
	}
	if (size == 1) {
		memcpy3_fixed(s, r, a);
		return;
	}

	/* binary loop */
	push3_fixed(s, z);
	memcpy3_fixed(s, z, a);
	memcpy3_fixed(s, r, curve_o);
	i = 0;
	for (;;) {
		if (logbitp_fixptr(n, word1, i))
			(*addition)(s, r, z, r);
		i++;
		if (size <= i)
			break;
		(*doubling)(s, z, z);
	}
	pop3_fixed(s);
}

void multiple_secp256k1(fixed s, fixptr n, fixptr3 a, fixptr3 r)
{
	mul3_elliptic_curve(s, n, a, r,
			addition_secp256k1,
			doubling_secp256k1,
			Elliptic_secp256k1_o);
}

void multiple_secp256r1(fixed s, fixptr n, fixptr3 a, fixptr3 r)
{
	mul3_elliptic_curve(s, n, a, r,
			addition_secp256r1,
			doubling_secp256r1,
			Elliptic_secp256r1_o);
}

static void mul4_elliptic_curve(fixed s,
		fixptr n, fixptr4 a, fixptr4 r,
		void (*addition)(fixed, fixptr4, fixptr4, fixptr4),
		void (*doubling)(fixed, fixptr4, fixptr4),
		fixptr4 curve_o)
{
	unsigned size, i;
	fixptr4 z;
	fixsize word1;

	word1 = s->word1;
	size = logsize_fixptr(n, word1);
	if (size == 0) {
		memcpy4_fixed(s, r, curve_o);
		return;
	}
	if (size == 1) {
		memcpy4_fixed(s, r, a);
		return;
	}

	/* binary loop */
	push4_fixed(s, z);
	memcpy4_fixed(s, z, a);
	memcpy4_fixed(s, r, curve_o);
	i = 0;
	for (;;) {
		if (logbitp_fixptr(n, word1, i))
			(*addition)(s, r, z, r);
		i++;
		if (size <= i)
			break;
		(*doubling)(s, z, z);
	}
	pop4_fixed(s);
}

void multiple_ed25519(fixed s, fixptr n, fixptr4 a, fixptr4 r)
{
	mul4_elliptic_curve(s, n, a, r,
			addition_ed25519,
			doubling_ed25519,
			Elliptic_ed25519_o);
}

void multiple_ed448(fixed s, fixptr n, fixptr3 a, fixptr3 r)
{
	mul3_elliptic_curve(s, n, a, r,
			addition_ed448,
			doubling_ed448,
			Elliptic_ed448_o);
}

