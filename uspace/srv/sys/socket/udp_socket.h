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

#ifndef UDP_SOCKET_H_
#define UDP_SOCKET_H_

#include <types/socket/in.h>

#include "common_socket.h"

/** UDP socket*/
typedef struct {
    /** Common socket attributes */
    common_socket_t socket;
    /** Ip link service ID socket is bound to */
    service_id_t iplink;
    /** UDP association socket uses to send and receive messages */
    udp_assoc_t *udp_assoc;
    /** Queue of messages received by the socket */
    list_t msg_queue; 
} udp_socket_t;

int udp_socket(int, int, int, int);
int udp_socket_setsockopt(common_socket_t *, int, int, const void *, socklen_t);
int udp_socket_bind(common_socket_t *, const struct sockaddr *, socklen_t);
bool udp_socket_read_avail(common_socket_t *);
int udp_socket_sendmsg(common_socket_t *, const struct msghdr *, int);
int udp_socket_recvmsg(common_socket_t *, struct msghdr *, int, size_t *);
int udp_socket_close(common_socket_t *);

#endif

/** @}
 */