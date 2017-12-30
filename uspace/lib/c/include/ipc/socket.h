#ifndef LIBC_IPC_SOCKET_H_
#define LIBC_IPC_SOCKET_H_

#include <ipc/common.h>

typedef enum {
    SOCKET_CREATE = IPC_FIRST_USER_METHOD,
    SOCKET_BIND,
    SOCKET_CONNECT,
    SOCKET_SETSOCKOPT,
    SOCKET_SENDMSG,
    SOCKET_RECVMSG,
    SOCKET_FDISSET,
    SOCKET_CLOSE
} socket_request_t;

#endif

