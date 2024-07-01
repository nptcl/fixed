#ifndef __FIXED_RANDOM_HEADER__
#define __FIXED_RANDOM_HEADER__

#if defined(FIXED_LINUX) || defined(FIXED_FREEBSD) || defined(FIXED_UNIX)
#undef FIXED_LINUX
#undef FIXED_FREEBSD
#undef FIXED_UNIX
#undef FIXED_WINDOWS
#undef FIXED_DEFAULT
#define FIXED_UNIX
#elif defined(FIXED_WINDOWS)
#undef FIXED_LINUX
#undef FIXED_FREEBSD
#undef FIXED_UNIX
#undef FIXED_DEFAULT
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__unix__)
#undef FIXED_LINUX
#undef FIXED_FREEBSD
#undef FIXED_UNIX
#undef FIXED_WINDOWS
#undef FIXED_DEFAULT
#define FIXED_UNIX
#elif defined(_WIN32) || defined(_WIN64)
#undef FIXED_LINUX
#undef FIXED_FREEBSD
#undef FIXED_UNIX
#undef FIXED_WINDOWS
#undef FIXED_DEFAULT
#define FIXED_WINDOWS
#else
#undef FIXED_LINUX
#undef FIXED_FREEBSD
#undef FIXED_UNIX
#undef FIXED_WINDOWS
#undef FIXED_DEFAULT
#define FIXED_DEFAULT
#endif

#include <stddef.h>
#include <stdint.h>

struct fixed_random {
	union {
		uint64_t u64[2];
		uint32_t u32[4];
	} seed;
};

uint64_t number64_fixrandom(struct fixed_random *state);
uint64_t equal64_fixrandom(struct fixed_random *state, uint64_t value);
uint64_t number64_sha_fixrandom(struct fixed_random *state);
uint64_t equal64_sha_fixrandom(struct fixed_random *state, uint64_t value);

void init_fixrandom(void);
void seed_fixrandom(const void *ptr, size_t size);
int update_fixrandom(void);
int make_fixrandom(struct fixed_random *ptr);

#endif

