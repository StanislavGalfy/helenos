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

#ifndef UNIX_SOCKET_H_
#define UNIX_SOCKET_H_

#include "common_socket.h"
#include <types/socket/socket.h>

/** UNIX socket identification that maps a path to a port */
typedef struct {
        /** Link to list of identifications */
        link_t list_link;
        /** UNIX socket path */
        char *path;
        /** Port corresponding to the path */
        uint16_t port;
} unix_socket_ident_t;

/** UNIX socket */
typedef struct {
        /** Common socket attributes */
        common_socket_t socket;
        /** TCP socket for emulating UNIX socket */
        common_socket_t *tcp_socket;
        /** Unix socket identification */
        unix_socket_ident_t ident;
} unix_socket_t;

extern errno_t unix_socket(int, int, int, int, int *);
extern errno_t unix_socket_bind(common_socket_t *, const struct sockaddr *,
    socklen_t);
extern errno_t unix_socket_listen(common_socket_t *, int);
extern errno_t unix_socket_connect(common_socket_t *, const struct sockaddr *,
    socklen_t);
extern errno_t unix_socket_accept(common_socket_t *, const struct sockaddr *,
    socklen_t *, int *);
extern errno_t unix_socket_read_avail(common_socket_t *, bool *);
extern errno_t unix_socket_write(common_socket_t *, void *, size_t, size_t *);
extern errno_t unix_socket_read(common_socket_t *, void *, size_t, size_t *);
extern errno_t unix_socket_close(common_socket_t *);

#endif

/** @}
 */