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
/** @file Unix socket
 */

/** DISCLAIMER - main purpose of unix socket implementation is BIRD port.
 * It is not fully POSIX compliant, most features are not implemented.
 */

#include <stdlib.h>
#include <errno.h>

#include "unix_socket.h"

/** Creates new UNIX socket.
 *
 * @param domain	Socket domain.
 * @param type		Socket type.
 * @param protocol	Socket protocol.
 * @param session_id	Session ID.
 * @return		Socket ID.
 */
errno_t unix_socket(int domain, int type, int protocol, int session_id, int *fd)
{
	unix_socket_t *unix_socket = (unix_socket_t *)calloc(1,
	    sizeof(unix_socket_t));
	common_socket_init(&unix_socket->socket, domain, type, protocol,
	    session_id);
	*fd = unix_socket->socket.id;
	return EOK;
}

/** Returns EOK for BIRD compatibility. */
errno_t unix_socket_bind(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen)
{
	return EOK;
}

/** Returns EOK for BIRD compatibility. */
errno_t unix_socket_listen(common_socket_t *socket, int backlog)
{
	return EOK;
}

/** Returns ECONNREFUSED for BIRD compatibility. */
errno_t unix_socket_connect(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen)
{
	return ECONNREFUSED;
}

/** Sets read_avail to false and returns EOK for BIRD compatibility. */
errno_t unix_socket_read_avail(common_socket_t *socket, bool *read_avail)
{
	*read_avail = false;
	return EOK;
}

/** Closes UNIX socket.
 *
 * @param socket	Socket to close.
 * @return		EOK.
 */
errno_t unix_socket_close(common_socket_t *socket)
{
	unix_socket_t *unix_socket = (unix_socket_t*)socket;
	free(unix_socket);
	return EOK;
}

/** @}
 */
