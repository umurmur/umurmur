#ifndef TYPES_H_90878954
#define TYPES_H_90878954

#if __STDC_VERSION__ >= 199901L

#include <stdbool.h>
typedef bool bool_t;

#else // __STDC_VERSION__

typedef enum {
	false,
	true
} bool_t;

#endif // __STDC_VERSION

#endif

