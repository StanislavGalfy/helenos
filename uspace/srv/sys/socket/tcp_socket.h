/*
 * Copyright (c) 2017 Stanislav Galfy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @addtogroup socket
 * @{
 */
/** @file
 */

#ifndef TCP_SOCKET_H_
#define TCP_SOCKET_H_

#include <types/socket/in.h>

#include "common_socket.h"

/** TCP socket connection */
typedef struct {
        /** Link to connection queue of listener socket */
        link_t conn_queue_link;
        /** TCP connection */
        tcp_conn_t *tcp_conn;
        /** Is connection incoming */
        bool is_incoming;
        /** Condition variable to prevent destroying of TCP connection*/
        fibril_condvar_t tcp_conn_fcv;
} tcp_sock_conn_t;

/** TCP socket*/
typedef struct {
        /** Common socket attributes */
        common_socket_t socket;
        /** Is socket listener */
        bool is_listener;
        /** Local address and port of the socket */
        inet_ep_t ep;
        /** TCP socket connection, only used by non listener sockets */
        tcp_sock_conn_t *tcp_sock_conn;
        /** TCP socket connection queue, only used by listener sockets */
        list_t tcp_conn_queue;
        /** TCP listener, only used by listener sockets */
        tcp_listener_t *tcp_listener;
} tcp_socket_t;

extern errno_t tcp_socket(int, int, int, int, int *);
extern errno_t tcp_socket_setsockopt(common_socket_t *, int, int, const void *,
    socklen_t);
extern errno_t tcp_socket_bind(common_socket_t *, const struct sockaddr *,
    socklen_t);
extern errno_t tcp_socket_listen(common_socket_t *, int);
extern errno_t tcp_socket_connect(common_socket_t *, const struct sockaddr *,
    socklen_t);
extern errno_t tcp_socket_getsockname(common_socket_t *,
    const struct sockaddr *, socklen_t *);
extern errno_t tcp_socket_accept(common_socket_t *, const struct sockaddr *,
    socklen_t *, int *);
extern errno_t tcp_socket_read_avail(common_socket_t *, bool *);
extern errno_t tcp_socket_write_avail(common_socket_t *, bool *);
extern errno_t tcp_socket_write(common_socket_t *, void *, size_t, size_t *);
extern errno_t tcp_socket_read(common_socket_t *, void *, size_t, size_t *);
extern errno_t tcp_socket_close(common_socket_t *);

#endif

/** @}
 */
