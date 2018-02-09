#ifndef LIBC_TYPES_SELECT_H_
#define LIBC_TYPES_SELECT_H_

#define FD_SETSIZE 1024

#include <stdbool.h>

typedef struct {
        char fds_bits[FD_SETSIZE];
} fd_set;

#endif
