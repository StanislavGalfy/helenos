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
#include <byteorder.h>
#include <io/log.h>
#include <types/socket/un.h>
#include <str.h>

#include "unix_socket.h"
#include "tcp_socket.h"
#include "tools.h"

static in_addr_t localhost = 0x7F000001;
static in_port_t local_port = 9900;

LIST_INITIALIZE(unix_socket_listener_mapping);

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
	unix_socket_t *unix_socket = (unix_socket_t *) calloc(1,
	    sizeof(unix_socket_t));
	common_socket_init(&unix_socket->socket, domain, type, protocol,
	    session_id);
	*fd = unix_socket->socket.id;

	int tcp_socket_id;
	errno_t rc = tcp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, session_id,
	    &tcp_socket_id);
	if (rc != EOK) {
		return rc;
	}

	unix_socket->tcp_socket = get_socket_by_id(
	    tcp_socket_id);

	link_initialize(&unix_socket->ident.list_link);
	unix_socket->ident.path = NULL;
	unix_socket->ident.port = 0;

	return EOK;
}

/** Binds UNIX socket to given address and port.
 *
 * @param socket	Socket to bind.
 * @param addr		Address to bind to.
 * @param addrlen	Address length.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_bind(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen)
{
	unix_socket_t *unix_socket = (unix_socket_t *) socket;

	struct sockaddr saddr;
	((struct sockaddr_in*)&saddr)->sin_addr.s_addr = ntohl(localhost);
	((struct sockaddr_in*)&saddr)->sin_port = ntohs(local_port);
	((struct sockaddr_in*)&saddr)->sin_family = AF_INET;

	struct sockaddr_un *addr_un = (struct sockaddr_un *) addr;
	list_foreach(unix_socket_listener_mapping, list_link,
	    unix_socket_ident_t, ident) {
		if (str_cmp(addr_un->sun_path, ident->path) == 0) {
			return EADDRINUSE;
		}
	}


	size_t path_len = str_size(addr_un->sun_path) + 1;
	unix_socket->ident.path = malloc(path_len);
	memcpy(unix_socket->ident.path, addr_un->sun_path, path_len);
	unix_socket->ident.port = local_port;

	log_msg(LOG_DEFAULT, LVL_FATAL, "UNIX bind path: %s, port: %d", unix_socket->ident.path, local_port);

	local_port++;

	return tcp_socket_bind(unix_socket->tcp_socket, &saddr,
	    sizeof(struct sockaddr_in));
}

/** Starts listening for incoming connection on UNIX socket.
 *
 * @param socket	Socket to listen on.
 * @param backlog	UNUSED.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_listen(common_socket_t *socket, int backlog)
{
	unix_socket_t *unix_socket = (unix_socket_t *) socket;
	errno_t rc = tcp_socket_listen(unix_socket->tcp_socket, backlog);
	if (rc != EOK) {
		return rc;
	}
	list_append(&unix_socket->ident.list_link, &unix_socket_listener_mapping);
	return EOK;
}

/** Creates UNIX socket connection.
 *
 * @param socket	Socket to connect.
 * @param addr		Remote address and port to connect to.
 * @param addrlen	Address length.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_connect(common_socket_t *socket,
    const struct sockaddr *addr, socklen_t addrlen)
{
	unix_socket_t *unix_socket = (unix_socket_t *) socket;

	struct sockaddr local_addr;
	((struct sockaddr_in*)&local_addr)->sin_addr.s_addr = ntohl(localhost);
	((struct sockaddr_in*)&local_addr)->sin_port = ntohs(local_port);
	((struct sockaddr_in*)&local_addr)->sin_family = AF_INET;
	local_port++;

	errno_t rc = tcp_socket_bind(unix_socket->tcp_socket, &local_addr,
	    sizeof(struct sockaddr_in));
	if (rc != EOK) {
		return rc;
	}

	struct sockaddr_un *addr_un = (struct sockaddr_un *) addr;
	uint16_t remote_port = 0;
	list_foreach(unix_socket_listener_mapping, list_link,
	    unix_socket_ident_t, ident) {
		if (str_cmp(addr_un->sun_path, ident->path) == 0) {
			remote_port = ident->port;
			break;
		}
	}
	log_msg(LOG_DEFAULT, LVL_FATAL, "UNIX connect port: %d", remote_port);
	if (remote_port == 0) {
		return ECONNREFUSED;
	}

	struct sockaddr remote_addr;
	((struct sockaddr_in*)&remote_addr)->sin_addr.s_addr = ntohl(localhost);
	((struct sockaddr_in*)&remote_addr)->sin_port = ntohs(remote_port);
	((struct sockaddr_in*)&remote_addr)->sin_family = AF_INET;

	rc = tcp_socket_connect(unix_socket->tcp_socket, &remote_addr,
	    sizeof(struct sockaddr_in));

	if (rc == EINPROGRESS) {
		rc = tcp_conn_wait_connected(((tcp_socket_t *)
		    unix_socket->tcp_socket)->tcp_sock_conn->tcp_conn);
		log_msg(LOG_DEFAULT, LVL_FATAL, "Returning: %d", rc);
		return rc;
	}
	return rc;
}

/** Accepts UNIX socket connection and creates new socket for it.
 *
 * @param socket	Socket to accept connection from.
 * @param addr		Pointer where will be stored remote address and port.
 * @param addrlen	Address length.
 * @param fd		Pointer to file descriptor of newly created socket.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_accept(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t *addrlen, int *fd)
{
	unix_socket_t *unix_socket = (unix_socket_t *) socket;
	return tcp_socket_accept(unix_socket->tcp_socket, addr, addrlen, fd);
}

/** Sets read_avail to false and returns EOK for BIRD compatibility. */
errno_t unix_socket_read_avail(common_socket_t *socket, bool *read_avail)
{
	unix_socket_t *unix_socket = (unix_socket_t *) socket;

	return tcp_socket_read_avail(unix_socket->tcp_socket, read_avail);
}

/** Writes data to UNIX socket.
 *
 * @param socket	Socket to write to.
 * @param buf		Buffer with data to write.
 * @param count		Byte count to write.
 * @param nsent		Pointer where will be store number of bytes actually
 *			sent.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_write(common_socket_t *socket, void *buf, size_t count,
    size_t *nsent)
{
	unix_socket_t* unix_socket = (unix_socket_t*) socket;
	errno_t rc = tcp_socket_write(unix_socket->tcp_socket, buf, count,
	    nsent);
	return rc;
}

/** Reads data from UNIX socket.
 *
 * @param socket	Socket to read from.
 * @param buf		Buffer to store read data.
 * @param count		Count of bytes to receive.
 * @param nrecv		Pointer to number of actually received bytes.
 * @return		EOK on success, error code on failure.
 */
errno_t unix_socket_read(common_socket_t *socket, void *buf, size_t count,
    size_t *nrecv)
{
	unix_socket_t* unix_socket = (unix_socket_t*) socket;
	errno_t rc = tcp_socket_read(unix_socket->tcp_socket, buf, count, nrecv);
	return rc;
}

/** Closes UNIX socket.
 *
 * @param socket	Socket to close.
 * @return		EOK.
 */
errno_t unix_socket_close(common_socket_t *socket)
{
	unix_socket_t *unix_socket = (unix_socket_t*) socket;
	tcp_socket_close(unix_socket->tcp_socket);
	if (unix_socket->ident.path != NULL) {
		free(unix_socket->ident.path);
	}
	list_remove(&unix_socket->ident.list_link);
	free(unix_socket);
	return EOK;
}

/** @}
 */
