#ifndef LIBC_IPC_SOCKET_H_
#define LIBC_IPC_SOCKET_H_

#include <ipc/common.h>

typedef enum {
        SOCKET_CREATE = IPC_FIRST_USER_METHOD,
        SOCKET_BIND,
        SOCKET_LISTEN,
        SOCKET_CONNECT,
        SOCKET_ACCEPT,
        SOCKET_SETSOCKOPT,
        SOCKET_GETSOCKNAME,
        SOCKET_SENDMSG,
        SOCKET_RECVMSG,
        SOCKET_WRITE,
        SOCKET_READ,
        SOCKET_FDISSET,
        SOCKET_SELECT,
        SOCKET_CLOSE
} socket_request_t;

#endif

