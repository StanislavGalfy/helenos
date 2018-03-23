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

#include <inet/inet.h>
#include <stdio.h>
#include <errno.h>
#include <io/log.h>
#include <types/socket/in.h>

#include "tools.h"
#include "common_socket.h"
#include "raw_socket.h"

#define IP_PROTO_OSPF 89

/** List of all sockets */
list_t socket_list;
/** Global socket lock */
fibril_mutex_t socket_lock;
/** UDP structure used for communication with UDP service */
udp_t *socket_udp;
/** TCP structure used for communication with TCP service */
tcp_t *socket_tcp;

/** Structure with callback passed when initializing inet */
static inet_ev_ops_t inet_ev_ops = {
	.recv = raw_socket_inet_ev_recv
};

/** Initialize socket implementation.
 *
 * @return	EOK on success, error code on failure.
 */
errno_t sockets_init()
{
	log_msg(LOG_DEFAULT, LVL_DEBUG, "Initializing sockets");

	list_initialize(&socket_list);

	fibril_mutex_initialize(&socket_lock);

	errno_t rc = inet_init(IP_PROTO_OSPF, &inet_ev_ops);
	if (rc != EOK) {
		log_msg(LOG_DEFAULT, LVL_ERROR, "Error initializing inet");
		return rc;
	}
	rc = udp_create(&socket_udp);
	if (rc != EOK) {
		log_msg(LOG_DEFAULT, LVL_ERROR, "Error initializing UDP");
		return rc;
	};
	rc = tcp_create(&socket_tcp);
	if (rc != EOK) {
		log_msg(LOG_DEFAULT, LVL_ERROR, "Error initializing TCP");
		return rc;
	};
	return rc;
}

/** Initialize common socket structure.
 *
 * @param socket	The structure to initialize.
 * @param domain	Socket domain.
 * @param type		Socket type.
 * @param protocol	Socket protocol.
 * @param session_id	Session id.
 */
void common_socket_init(common_socket_t *socket, int domain, int type,
    int protocol, int session_id)
{
	socket->id = generate_socket_id();
	socket->session_id = session_id;

	socket->domain = domain;
	socket->type = type;
	socket->protocol = protocol;

	link_initialize(&socket->link);

	list_append(&socket->link, &socket_list);
}

/** @}
 */
