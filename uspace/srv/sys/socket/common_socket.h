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

#ifndef COMMON_SOCKET_H_
#define COMMON_SOCKET_H_

#include <fibril_synch.h>
#include <inet/inet.h>
#include <inet/udp.h>
#include <inet/tcp.h>

/** Structure with attributes common for all types of sockets */
typedef struct {
        /** Link to list of all sockets */
        link_t link;
        /** Socket id or file descriptor, used by clients to access sockets */
        int id;
        /** Session id, same for sockets from one client*/
        int session_id;
        /** Socket domain */
        int domain;
        /** Socket type */
        int type;
        /** Socket protocol */
        int protocol;
} common_socket_t;

/** List of all sockets */
extern list_t socket_list;
/** Global socket lock */
extern fibril_mutex_t socket_lock;
/** UDP structure used for communication with UDP service */
extern udp_t *socket_udp;
/** TCP structure used for communication with TCP service */
extern tcp_t *socket_tcp;

extern int sockets_init(void);
extern void common_socket_init(common_socket_t*, int, int, int, int);

#endif

/** @}
 */
