#ifndef __FIXED_HEADER__
#define __FIXED_HEADER__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#if defined(FIXED_DEBUG)
#undef FIXED_RELEASE
#elif defined(FIXED_RELEASE)
#undef FIXED_DEBUG
#else
#define FIXED_DEBUG
#endif

#ifdef FIXED_DEBUG
#ifndef FIXED_SIZE_CHECK
#define FIXED_SIZE_CHECK
#endif
#endif

/***********************************************************************
 *  typedef
 ***********************************************************************/
#if defined(FIXED_8BIT)
/* 8bit */
#define FIXED_MAX				UINT8_MAX
#define FIXED_FULL				0xFFUL
#define FIXED_HALF				0xFUL
#define FIXED_FULLBIT			8
#define FIXED_HALFBIT			4
#define FIXED_PRINT_LENGTH		"2"
#define FIXED_PRINT				"u"
#undef FIXED_16BIT
#undef FIXED_32BIT
#undef FIXED_64BIT
typedef uint8_t fixnum;
#elif defined(FIXED_16BIT)
/* 16 bit */
#define FIXED_MAX				UINT16_MAX
#define FIXED_FULL				0xFFFFUL
#define FIXED_HALF				0xFFUL
#define FIXED_FULLBIT			16
#define FIXED_HALFBIT			8
#define FIXED_PRINT_LENGTH		"4"
#define FIXED_PRINT				"u"
#undef FIXED_8BIT
#undef FIXED_32BIT
#undef FIXED_64BIT
typedef uint16_t fixnum;
#elif defined(FIXED_32BIT)
/* 32 bit */
#define FIXED_MAX				UINT32_MAX
#define FIXED_FULL				0xFFFFFFFFUL
#define FIXED_HALF				0xFFFFUL
#define FIXED_FULLBIT			32
#define FIXED_HALFBIT			16
#define FIXED_PRINT_LENGTH		"8"
#define FIXED_PRINT				"ul"
#undef FIXED_8BIT
#undef FIXED_16BIT
#undef FIXED_64BIT
typedef uint32_t fixnum;
#else
/* 64 bit */
#define FIXED_MAX				UINT64_MAX
#define FIXED_FULL				0xFFFFFFFFFFFFFFFFULL
#define FIXED_HALF				0xFFFFFFFFULL
#define FIXED_FULLBIT			64
#define FIXED_HALFBIT			32
#define FIXED_PRINT_LENGTH		"16"
#define FIXED_PRINT				PRIX64
#undef FIXED_8BIT
#undef FIXED_16BIT
#undef FIXED_32BIT
#ifndef FIXED_64BIT
#define FIXED_64BIT
#endif
typedef uint64_t fixnum;
#endif

typedef fixnum *fixptr;
typedef unsigned fixsize;

struct fixed_struct {
	unsigned carry : 1;
	unsigned upper : 1;
	fixptr stack;
	fixsize index, size, word1, word2, bit1, bit2, byte1, byte2;

	fixptr x, y, q, r;
	fixsize sizex, sizey, sizeq, sizer;
#ifdef FIXED_DEBUG
	fixsize index_max;
#endif
};

typedef struct fixed_struct *fixed;


/* print */
#ifdef FIXED_DEBUG
#define FIXED_PRINT_SIZE		3
#else
#define FIXED_PRINT_SIZE		32
#endif

struct fixed_print_child {
	struct fixed_print_child *next;
	char str[FIXED_PRINT_SIZE];
	size_t size;
};
struct fixed_print {
	unsigned upper : 1;
	struct fixed_print_child *root, *tail;
	size_t size;
};

typedef struct fixed_print *fixprint;


/*
 *  fixptr
 */
#ifdef FIXED_DEBUG
#define memcpy_fixptr			memcpy_fixdebug
#define memmove_fixptr			memmove_fixdebug
#define memcmp_fixptr			memcmp_fixdebug
#define memset_fixptr			memset_fixdebug
#define memzero_fixptr			memzero_fixdebug
#else
#define memcpy_fixptr(x,y,z)	memcpy((x), (y), sizeof(fixnum) * (z))
#define memmove_fixptr(x,y,z)	memmove((x), (y), sizeof(fixnum) * (z))
#define memcmp_fixptr(x,y,z)	memcmp((x), (y), sizeof(fixnum) * (z))
#define memset_fixptr(x,y,z)	memset((x), (y), sizeof(fixnum) * (z))
#define memzero_fixptr(x,z)		memset_fixptr((x), 0, (z))
#endif

void memcpy_fixdebug(fixptr x, fixptr y, fixsize z);
void memmove_fixdebug(fixptr x, fixptr y, fixsize z);
int memcmp_fixdebug(fixptr x, fixptr y, fixsize z);
void memset_fixdebug(fixptr x, int y, fixsize z);
void memzero_fixdebug(fixptr x, fixsize z);
fixsize size_press_fixptr(fixptr x, fixsize size);
int eqlv_fixptr(fixptr x, fixsize size, fixnum v);
int zerop_fixptr(fixptr x, fixsize size);
int compare_fixnum_fixptr(fixptr x, fixsize word, fixnum y);
int compare_fixptr(fixptr x, fixsize size1, fixptr y, fixsize size2);
void addv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry);
void subv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry);
void mulv_fixptr(fixptr p, fixsize size, fixnum v, fixnum *carry);
void add_fixptr(fixptr a, fixptr b, fixptr r, fixsize size, fixnum *carry);
void sub2_fixptr(fixptr a, fixsize size1, fixptr b, fixsize size2,
		fixptr r, fixsize size3, fixnum *carry);
void sub_fixptr(fixptr a, fixptr b, fixptr r, fixsize size, fixnum *carry);
void shiftl_fixptr(fixptr x, fixsize size, fixsize shift);
void shiftr_fixptr(fixptr x, fixsize size, fixsize shift);
void rotatel1_fixptr(fixptr r, fixsize w, fixsize m);
void rotatel2_fixptr(fixptr x, fixptr r, fixsize w, fixsize m);
void rotatel3_fixptr(fixptr x, fixptr y, fixsize w, fixsize m);
void rotater1_fixptr(fixptr r, fixsize w, fixsize m);
void rotater2_fixptr(fixptr x, fixptr r, fixsize w, fixsize m);
void rotater3_fixptr(fixptr x, fixptr y, fixsize w, fixsize m);

void setv_fixptr(fixptr x, fixsize size, fixnum v);
int getv_fixptr(fixptr x, fixsize size, fixnum *r);
int setu_fixptr(fixptr x, fixsize size, unsigned v);
int getu_fixptr(fixptr x, fixsize size, unsigned *r);

unsigned logsize_fixptr(fixptr x, fixsize word);
int logbitp_fixptr(fixptr x, fixsize word, unsigned i);
void setbit_fixptr(fixptr x, fixsize word, int on, unsigned i);


/*
 *  fixed
 */
fixed make_fixed(fixsize bit1, fixsize size1);
void free_fixed(fixed s);

fixptr get1_fixed(fixed s, fixsize word1);
fixptr top1_fixed(fixed s);
fixptr top2_fixed(fixed s);
void push1_fixed(fixed s);
void push2_fixed(fixed s);
void pop1_fixed(fixed s);
void pop2_fixed(fixed s);
void pop1n_fixed(fixed s, fixsize n);
void pop2n_fixed(fixed s, fixsize n);
fixptr push1get_fixed(fixed s);
fixptr push2get_fixed(fixed s);
fixptr push1ptr_fixed(fixed s, fixptr x);
fixptr push2ptr_fixed(fixed s, fixptr x);
fixsize snap_fixed(fixed s);
fixsize roll_fixed(fixed s, fixsize index);
void dump1_fixed(fixed s, fixsize word1);
void dump2_fixed(fixed s, fixsize word1);
int zerop1_fixed(fixed s, fixsize word1);
int zerop2_fixed(fixed s, fixsize word1);
int onep1_fixed(fixed s, fixsize word1);
int onep2_fixed(fixed s, fixsize word1);

void set1v_fixed(fixed s, fixsize word1, fixnum v);
void set2v_fixed(fixed s, fixsize word1, fixnum v);
fixptr push1v_fixed(fixed s, fixnum v);
fixptr push2v_fixed(fixed s, fixnum v);
void set1u_fixed(fixed s, fixsize word1, unsigned v);
void set2u_fixed(fixed s, fixsize word1, unsigned v);
void set1u8_fixed(fixed s, fixsize word1, uint8_t v);
void set2u8_fixed(fixed s, fixsize word1, uint8_t v);
void set1u16_fixed(fixed s, fixsize word1, uint16_t v);
void set2u16_fixed(fixed s, fixsize word1, uint16_t v);
void set1u32_fixed(fixed s, fixsize word1, uint32_t v);
void set2u32_fixed(fixed s, fixsize word1, uint32_t v);
void set1u64_fixed(fixed s, fixsize word1, uint64_t v);
void set2u64_fixed(fixed s, fixsize word1, uint64_t v);
fixptr push1u_fixed(fixed s, unsigned v);
fixptr push2u_fixed(fixed s, unsigned v);
void push1u8_fixed(fixed s, uint8_t v);
void push2u8_fixed(fixed s, uint8_t v);
void push1u16_fixed(fixed s, uint16_t v);
void push2u16_fixed(fixed s, uint16_t v);
void push1u32_fixed(fixed s, uint32_t v);
void push2u32_fixed(fixed s, uint32_t v);
void push1u64_fixed(fixed s, uint64_t v);
void push2u64_fixed(fixed s, uint64_t v);

int get1u_fixed(fixed s, fixsize word1, unsigned *r);
int get2u_fixed(fixed s, fixsize word1, unsigned *r);

void copy1_fixed(fixed s, fixsize dst1, fixsize src1);
void copy2_fixed(fixed s, fixsize dst1, fixsize src1);
void dup1_fixed(fixed s, fixsize word1);
void dup2_fixed(fixed s, fixsize word1);
void shift1_fixed(fixed s, fixsize size1, fixsize pop1);
int compare1_fixed(fixed s, fixsize x1, fixsize y1);
int compare2_fixed(fixed s, fixsize x1, fixsize y1);
void shiftl1_fixed(fixed s, fixsize word1, fixsize shift);
void shiftl2_fixed(fixed s, fixsize word1, fixsize shift);
void shiftr1_fixed(fixed s, fixsize word1, fixsize shift);
void shiftr2_fixed(fixed s, fixsize word1, fixsize shift);
void split2_fixed(fixed s, fixsize word1);

/* multiple */
void mul2_fixptr(fixptr a, fixsize w1, fixptr b, fixsize w2, fixptr r, fixsize w3);
void mul_fixptr(fixptr x, fixptr y, fixsize w1, fixptr r, fixsize w2);
void mul_square_fixptr(fixptr x, fixsize w1, fixptr r, fixsize w2);
void mul_fixed(fixed s);
void mul_square_fixed(fixed s);

/* division */
void div1_fixptr(fixed s, fixptr x1, fixptr y1, fixptr q1, fixptr r1);
void rem1_fixptr(fixed s, fixptr x1, fixptr y1, fixptr r1);
void div_fixptr(fixed s, fixptr x2, fixptr y1, fixptr q2, fixptr r1);
void rem_fixptr(fixed s, fixptr x2, fixptr y1, fixptr r1);
void div_fixed(fixed s);
void rem_fixed(fixed s);

/* read */
int read1_char_fixed(fixed s, fixsize word1, unsigned r, char p);
int read2_char_fixed(fixed s, fixsize word1, unsigned r, char p);
int read1s_fixed(fixed s, fixsize word1, const char *str, unsigned radix);
int read2s_fixed(fixed s, fixsize word1, const char *str, unsigned radix);
int read1p_fixed(fixed s, const char *str, unsigned radix);
int read2p_fixed(fixed s, const char *str, unsigned radix);
int read1_compare_fixed(fixed s, fixsize word1,
		const char *str, unsigned radix, int *ret);

/* print */
fixprint make_fixprint(void);
void free_fixprint(fixprint print);
int read1_fixprint(fixprint print, fixed s, fixsize word1, unsigned radix);
int read2_fixprint(fixprint print, fixed s, fixsize word1, unsigned radix);
fixprint make1_fixprint(fixed s, fixsize word1, unsigned radix);
fixprint make2_fixprint(fixed s, fixsize word1, unsigned radix);
void string_fixprint(fixprint print, char *str, size_t size);
void file_fixprint(fixprint print, FILE *file);
int print1_fixed(fixed s, fixsize word1, FILE *file, unsigned radix);
int print2_fixed(fixed s, fixsize word1, FILE *file, unsigned radix);
int println1_fixed(fixed s, fixsize word1, FILE *file, unsigned radix);
int println2_fixed(fixed s, fixsize word1, FILE *file, unsigned radix);
int println1_fixptr(fixed s, fixptr x, FILE *file, unsigned radix);
int println2_fixptr(fixed s, fixptr x, FILE *file, unsigned radix);

/* binary I/O */
void input_fixptr(fixptr r, fixsize word, const void *p, size_t size, int little);
void output_fixptr(fixptr x, fixsize word, void *p, size_t size, int little);

/* operator */
void inc1s_fixed(fixed s);
void inc1p_fixed(fixed s);
void dec1s_fixed(fixed s);
void dec1p_fixed(fixed s);
void add1s_fixed(fixed s);
void add1p_fixed(fixed s);
void sub1s_fixed(fixed s);
void sub1p_fixed(fixed s);
void sub1s_reverse_fixed(fixed s);
void sub1p_reverse_fixed(fixed s);

void not_fixptr(fixptr x, fixptr r, fixsize size);
void and_fixptr(fixptr x, fixptr y, fixptr r, fixsize size);
void or_fixptr(fixptr x, fixptr y, fixptr r, fixsize size);
void xor_fixptr(fixptr x, fixptr y, fixptr r, fixsize size);
void not1_fixed(fixed s);
void and1_fixed(fixed s);
void or1_fixed(fixed s);
void xor1_fixed(fixed s);

#endif

