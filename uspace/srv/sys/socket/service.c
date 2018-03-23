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
/** @file Service
 */

#include <errno.h>
#include <io/log.h>
#include <async.h>
#include <ipc/services.h>
#include <ipc/socket.h>
#include <loc.h>
#include <stdlib.h>
#include <types/socket/socket.h>
#include <types/socket/select.h>
#include <macros.h>
#include <stdio.h>
#include <mem.h>

#include "service.h"
#include "tools.h"
#include "common_socket.h"
#include "raw_socket.h"
#include "udp_socket.h"
#include "unix_socket.h"
#include "tcp_socket.h"

#define NAME "socket"

/** Maximum socket domain */
#define SOCK_DOMAIN_MAX 11
/** Maximum socket type */
#define SOCK_TYPE_MAX 4

/** Handles return value after asynchronous read/write */
#define CHECK_RV() \
        if (!rv) { \
                async_answer_0(callid, EREFUSED); \
                async_answer_0(iid, EREFUSED); \
                free_msghdr(msg); \
                return; \
        }

/** Handles return value after asynchronous read/write finalize*/
#define CHECK_RC() \
        if (rc != EOK) { \
                async_answer_0(callid, rc); \
                async_answer_0(iid, rc); \
                free_msghdr(msg); \
                return; \
        }

/** Array of socket create functions */
errno_t(*socket_create[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (int, int, int, int,
    int *);

/** Array of socket bind functions */
errno_t(*socket_bind[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    const struct sockaddr *, socklen_t);

/** Array of socket listen functions */
errno_t(*socket_listen[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX])(common_socket_t *, int);

/** Array of socket connect functions */
errno_t(*socket_connect[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    const struct sockaddr *, socklen_t);

/** Array of socket accept functions */
errno_t(*socket_accept[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    const struct sockaddr *, socklen_t *, int *);

/** Array of socket setsockopt functions */
errno_t(*socket_setsockopt[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    int, int, const void *, socklen_t);

/** Array of socket getsockname functions */
errno_t(*socket_getsockname[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX])(common_socket_t *,
    const struct sockaddr *, socklen_t *);

/** Array of socket fdisset functions */
errno_t(*socket_read_avail[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (
    common_socket_t *, bool *);

/** Array of socket fdisset functions */
errno_t(*socket_write_avail[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (
    common_socket_t *, bool *);

/** Array of socket sendmsg functions */
errno_t(*socket_sendmsg[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    const struct msghdr *, int, size_t *);

/** Array of socket recvmsg functions */
errno_t(*socket_recvmsg[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    struct msghdr *, int, size_t *);

/** Array of socket sendmsg functions */
errno_t(*socket_write[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    void *, size_t, size_t *);

/** Array of socket recvmsg functions */
errno_t(*socket_read[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    void *, size_t, size_t *);

/** Array of socket close functions */
int (*socket_close[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX])(common_socket_t *);

/** Deallocates all parts of msghdr structure.
 *
 * @param msg	Message to deallocate.
 */
static void free_msghdr(struct msghdr *msg)
{
	if (msg != NULL) {
		if (msg->msg_name != NULL)
			free(msg->msg_name);

		if (msg->msg_iov != NULL) {
			for (size_t i = 0; i < msg->msg_iovlen; i++)
				if (msg->msg_iov[i].iov_base != NULL)
					free(msg->msg_iov[i].iov_base);

			free(msg->msg_iov);
		}

		if (msg->msg_control != NULL)
			free(msg->msg_control);

		free(msg);
	}
}

/** Creates new socket.
 *
 * @param iid		Async request ID.
 * @param icall		Async request data.
 * @param session_id	Session ID.
 */
static void socket_create_srv(ipc_callid_t iid, ipc_call_t *icall,
    int session_id)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_create_srv()");

	/* Get parameters transfered as sysarg_t */
	int domain = IPC_GET_ARG1(*icall);
	int type = IPC_GET_ARG2(*icall);
	int protocol = IPC_GET_ARG3(*icall);

	if (socket_create[domain][type] == NULL) {
		async_answer_0(iid, ESOCKTNOSUPPORT);
		return;
	}

	fibril_mutex_lock(&socket_lock);
	int fd;
	errno_t retval = socket_create[domain][type](domain, type, protocol,
	    session_id, &fd);
	fibril_mutex_unlock(&socket_lock);

	async_answer_1(iid, retval, fd);
}

/** Binds socket to socket address.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_bind_srv(ipc_callid_t iid, ipc_call_t *icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_bind_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);

	/* Receive socket address */
	ipc_callid_t callid;
	size_t addrlen;
	errno_t rv = async_data_write_receive(&callid, &addrlen);
	if (!rv) {
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		return;
	}

	void *addr = malloc(addrlen);
	if (addr == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	errno_t rc = async_data_write_finalize(callid, addr, addrlen);
	if (rc != EOK) {
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(addr);
		return;
	}

	/* Find socket and call bind implementation based on domain and type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free(addr);
		return;
	}

	if (socket_bind[socket->domain][socket->type] == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free(addr);
		return;
	}
	errno_t retval = socket_bind[socket->domain][socket->type](socket, addr,
	    addrlen);
	fibril_mutex_unlock(&socket_lock);

	async_answer_0(iid, retval);
	free(addr);
}

/** Listens on socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_listen_srv(ipc_callid_t iid, ipc_call_t *icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_listen_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	int backlog = IPC_GET_ARG2(*icall);

	/* Find socket and call close implementation based on domain and type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(iid, EBADF);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	if (socket_listen[socket->domain][socket->type] == NULL) {
		async_answer_0(iid, EOPNOTSUPP);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	errno_t retval = socket_listen[socket->domain][socket->type](socket,
	    backlog);
	fibril_mutex_unlock(&socket_lock);

	async_answer_0(iid, retval);
}

/** Connects socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_connect_srv(ipc_callid_t iid, ipc_call_t *icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_connect_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);

	ipc_callid_t callid;
	size_t addrlen;
	errno_t rv = async_data_write_receive(&callid, &addrlen);
	if (!rv) {
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		return;
	}

	void *addr = malloc(addrlen);
	if (addr == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	errno_t rc = async_data_write_finalize(callid, addr, addrlen);
	if (rc != EOK) {
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(addr);
		return;
	}

	/* Find socket and call connect implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free(addr);
		return;
	}

	if (socket_connect[socket->domain][socket->type] == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free(addr);
		return;
	}
	errno_t retval = socket_connect[socket->domain][socket->type](socket, addr,
	    addrlen);
	fibril_mutex_unlock(&socket_lock);

	async_answer_0(iid, retval);
	free(addr);
}

/** Accept socket connection.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_accept_srv(ipc_callid_t iid, ipc_call_t *icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_accept_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	size_t addrlen = IPC_GET_ARG2(*icall);

	ipc_callid_t callid;

	void *addr = malloc(addrlen);
	if (addr == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	/* Find socket and call accept implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free(addr);
		return;
	}

	if (socket_accept[socket->domain][socket->type] == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free(addr);
		return;
	}
	int fd;
	errno_t retval = socket_accept[socket->domain][socket->type](socket,
	    addr, &addrlen, &fd);

	bool rv = async_data_read_receive(&callid, &addrlen);
	if (!rv) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		free(addr);
		return;
	}
	errno_t rc = async_data_read_finalize(callid, addr, addrlen);
	if (rc != EOK) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(addr);
		return;
	}
	fibril_mutex_unlock(&socket_lock);

	async_answer_2(iid, retval, fd, addrlen);
	free(addr);
}

/** Sets socket options.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_setsockopt_srv(ipc_callid_t iid, ipc_call_t *icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_setsockopt_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	int level = IPC_GET_ARG2(*icall);
	int optname = IPC_GET_ARG3(*icall);

	/* Receive option value */
	ipc_callid_t callid;
	size_t optlen;
	errno_t rv = async_data_write_receive(&callid, &optlen);
	if (!rv) {
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		return;
	}

	void *optval = malloc(optlen);
	if (optval == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	errno_t rc = async_data_write_finalize(callid, optval, optlen);
	if (rc != EOK) {
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		return;
	}

	/* Find socket and call setsockopt implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		fibril_mutex_unlock(&socket_lock);
		return;
	}

	if (socket_setsockopt[socket->domain][socket->type] == NULL) {
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	errno_t retval = socket_setsockopt[socket->domain][socket->type](socket,
	    level, optname, optval, optlen);
	fibril_mutex_unlock(&socket_lock);
	async_answer_0(iid, retval);
	free(optval);
}

/** Accept socket connection.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_getsockname_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_getsockname_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	size_t addrlen = IPC_GET_ARG2(*icall);

	ipc_callid_t callid;

	void *addr = malloc(addrlen);
	if (addr == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	/* Find socket and call accept implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free(addr);
		return;
	}

	if (socket_getsockname[socket->domain][socket->type] == NULL) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free(addr);
		return;
	}
	errno_t retval = socket_getsockname[socket->domain][socket->type](socket,
	    addr, &addrlen);

	bool rv = async_data_read_receive(&callid, &addrlen);
	if (!rv) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		free(addr);
		return;
	}
	errno_t rc = async_data_read_finalize(callid, addr, addrlen);
	if (rc != EOK) {
		fibril_mutex_unlock(&socket_lock);
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(addr);
		return;
	}
	fibril_mutex_unlock(&socket_lock);

	async_answer_1(iid, retval, addrlen);
	free(addr);
}

/** Sends message through socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_sendmsg_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_sendmsg_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	size_t msg_iovlen = IPC_GET_ARG2(*icall);
	int flags = IPC_GET_ARG3(*icall);

	struct msghdr *msg = calloc(1, sizeof(struct msghdr));
	if (msg == NULL) {
		async_answer_0(iid, ENOMEM);
		return;
	}

	msg->msg_iovlen = msg_iovlen;
	msg->msg_iov = calloc(msg_iovlen, sizeof(struct iovec));
	if (msg->msg_iov == NULL) {
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	/* Receive destination address */
	ipc_callid_t callid;

	bool rv = async_data_write_receive(&callid, &msg->msg_namelen);
	CHECK_RV();

	msg->msg_name = malloc(msg->msg_namelen);
	if (msg->msg_name == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	errno_t rc = async_data_write_finalize(callid, msg->msg_name,
	    msg->msg_namelen);
	CHECK_RC();

	/* Receive all input/output vectors */
	for (size_t i = 0; i < msg_iovlen; i++) {
		size_t iov_len;
		rv = async_data_write_receive(&callid, &iov_len);
		CHECK_RV();

		msg->msg_iov[i].iov_len = iov_len;
		msg->msg_iov[i].iov_base = malloc(iov_len);
		if (msg->msg_iov[i].iov_base == NULL) {
			async_answer_0(callid, ENOMEM);
			async_answer_0(iid, ENOMEM);
			free_msghdr(msg);
			return;
		}
		rc = async_data_write_finalize(callid, msg->msg_iov[i].iov_base,
		    iov_len);
		CHECK_RC();
	}

	/* Receive control data */
	rv = async_data_write_receive(&callid, &msg->msg_controllen);
	CHECK_RV();

	msg->msg_control = malloc(msg->msg_controllen);
	if (msg->msg_control == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	rc = async_data_write_finalize(callid, msg->msg_control,
	    msg->msg_controllen);
	CHECK_RC();

	/* Find socket and call sendmsg implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free_msghdr(msg);
		fibril_mutex_unlock(&socket_lock);
		return;
	}

	if (socket_sendmsg[socket->domain][socket->type] == NULL) {
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free_msghdr(msg);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	size_t nsent;
	errno_t retval = socket_sendmsg[socket->domain][socket->type](socket, msg,
	    flags, &nsent);

	fibril_mutex_unlock(&socket_lock);
	async_answer_1(iid, retval, nsent);
	free_msghdr(msg);
}

/** Receives message from socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_recvmsg_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_recvmsg_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	int msg_namelen = IPC_GET_ARG2(*icall);
	int msg_iovlen = IPC_GET_ARG3(*icall);
	int msg_controllen = IPC_GET_ARG4(*icall);
	int flags = IPC_GET_ARG5(*icall);

	struct msghdr *msg = calloc(1, sizeof(struct msghdr));
	if (msg == NULL) {
		async_answer_0(iid, ENOMEM);
		return;
	}

	msg->msg_namelen = msg_namelen;
	msg->msg_name = malloc(msg_namelen);
	if (msg->msg_name == NULL) {
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	msg->msg_iovlen = msg_iovlen;
	msg->msg_iov = calloc(msg_iovlen, sizeof(struct iovec));
	if (msg->msg_iov == NULL) {
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	msg->msg_controllen = msg_controllen;
	msg->msg_control = malloc(msg_controllen);
	if (msg->msg_control == NULL) {
		async_answer_0(iid, ENOMEM);
		free_msghdr(msg);
		return;
	}

	size_t size;
	ipc_callid_t callid;
	errno_t rc;
	bool rv;

	/* Receive sizes and allocate input/output vectors where will be stored
	 * received data */
	for (int i = 0; i < msg_iovlen; i++) {
		rv = async_data_write_receive(&callid, &size);
		CHECK_RV();
		if (size != sizeof(size_t)) {
			async_answer_0(callid, EINVAL);
			async_answer_0(iid, EINVAL);
			return;
		}

		size_t iov_len;
		rc = async_data_write_finalize(callid, &iov_len, size);
		CHECK_RC();
		if (iov_len > DATA_XFER_LIMIT) {
			async_answer_0(callid, EINVAL);
			async_answer_0(iid, EINVAL);
			return;
		}

		msg->msg_iov[i].iov_len = iov_len;
		msg->msg_iov[i].iov_base = malloc(iov_len);
		if (msg->msg_iov[i].iov_base == NULL) {
			async_answer_0(callid, ENOMEM);
			async_answer_0(iid, ENOMEM);
			free_msghdr(msg);
			return;
		}
	}

	/* Find socket and call recvmsg implementation based on domain and
	 * type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(callid, EBADF);
		async_answer_0(iid, EBADF);
		free_msghdr(msg);
		fibril_mutex_unlock(&socket_lock);
		return;
	}

	if (socket_recvmsg[socket->domain][socket->type] == NULL) {
		async_answer_0(callid, EOPNOTSUPP);
		async_answer_0(iid, EOPNOTSUPP);
		free_msghdr(msg);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	sysarg_t rsize;
	errno_t retval = socket_recvmsg[socket->domain][socket->type](socket, msg,
	    flags, &rsize);
	fibril_mutex_unlock(&socket_lock);

	/* Send source address */
	rv = async_data_read_receive(&callid, &size);
	CHECK_RV();
	rc = async_data_read_finalize(callid, msg->msg_name, msg->msg_namelen);
	CHECK_RC();

	/* Send contents of input/output vectors */
	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		rv = async_data_read_receive(&callid, &size);
		CHECK_RV();

		rc = async_data_read_finalize(callid, msg->msg_iov[i].iov_base,
		    min(msg->msg_iov[i].iov_len, size));
		CHECK_RC();
	}

	/* Send control data */
	rv = async_data_read_receive(&callid, &size);
	CHECK_RV();
	rc = async_data_read_finalize(callid, msg->msg_control,
	    msg->msg_controllen);
	CHECK_RC();

	async_answer_1(iid, retval, rsize);
	free_msghdr(msg);
}

/** Writes to socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_write_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_write_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	size_t count;

	/* Receive data to write */
	ipc_callid_t callid;
	bool rv = async_data_write_receive(&callid, &count);
	if (!rv) {
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		return;
	}

	void *buf = malloc(count);
	if (buf == NULL) {
		async_answer_0(callid, ENOMEM);
		async_answer_0(iid, ENOMEM);
		return;
	}

	errno_t rc = async_data_write_finalize(callid, buf, count);
	if (rc != EOK) {
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(buf);
		return;
	}


	/* Find socket and call write implementation based on domain and type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(iid, EBADF);
		free(buf);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	if (socket_write[socket->domain][socket->type] == NULL) {
		async_answer_0(iid, EOPNOTSUPP);
		free(buf);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	size_t nsent;
	errno_t retval = socket_write[socket->domain][socket->type](socket, buf,
	    count, &nsent);
	free(buf);

	fibril_mutex_unlock(&socket_lock);
	async_answer_1(iid, retval, nsent);
}

/** Reads from socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_read_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_read_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);
	size_t count = IPC_GET_ARG2(*icall);

	void *buf = malloc(count);
	if (buf == NULL) {
		async_answer_0(iid, ENOMEM);
		return;
	}

	/* Find socket and call read implementation based on domain and type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(iid, EBADF);
		free(buf);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	if (socket_write[socket->domain][socket->type] == NULL) {
		async_answer_0(iid, EOPNOTSUPP);
		free(buf);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	size_t nrecv = 0;
	errno_t retval = socket_read[socket->domain][socket->type](socket, buf,
	    count, &nrecv);

	/* Send read data */
	ipc_callid_t callid;
	bool rv = async_data_read_receive(&callid, &count);
	if (!rv) {
		async_answer_0(callid, EREFUSED);
		async_answer_0(iid, EREFUSED);
		free(buf);
		return;
	}

	errno_t rc = async_data_read_finalize(callid, buf, nrecv);
	if (rc != EOK) {
		async_answer_0(callid, rc);
		async_answer_0(iid, rc);
		free(buf);
		return;
	}

	free(buf);

	fibril_mutex_unlock(&socket_lock);
	async_answer_1(iid, retval, nrecv);
}

/** Closes socket.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_close_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_close_srv()");

	/* Get parameters transfered as sysarg_t */
	int sockfd = IPC_GET_ARG1(*icall);

	/* Find socket and call close implementation based on domain and type */
	fibril_mutex_lock(&socket_lock);
	common_socket_t *socket = get_socket_by_id(sockfd);
	if (socket == NULL) {
		async_answer_0(iid, EBADF);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	if (socket_close[socket->domain][socket->type] == NULL) {
		log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_close_srv() EOPNOTSUPP!!!");
		async_answer_0(iid, EOPNOTSUPP);
		fibril_mutex_unlock(&socket_lock);
		return;
	}
	errno_t retval = socket_close[socket->domain][socket->type](socket);
	fibril_mutex_unlock(&socket_lock);

	async_answer_0(iid, retval);
}

/** Select for sockets.
 *
 * @param iid	Async request ID.
 * @param icall	Async request data.
 */
static void socket_select_srv(ipc_callid_t iid, ipc_call_t * icall)
{
	fibril_mutex_lock(&socket_lock);

	bool is_readfds = IPC_GET_ARG2(*icall);
	bool is_writefds = IPC_GET_ARG3(*icall);
	bool is_exceptfds = IPC_GET_ARG4(*icall);
	bool is_timeout = IPC_GET_ARG5(*icall);
	struct timeval timeout;

	size_t size;
	ipc_callid_t callid;

	bool rv;
	errno_t rc;

	if (is_timeout) {
		/* Receive timeval */
		rv = async_data_write_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		rc = async_data_write_finalize(callid, &timeout, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
	}

	if (is_readfds) {
		fd_set readfds_in;
		fd_set readfds_out;
		memset(&readfds_out.fds_bits, 0, sizeof(readfds_out.fds_bits));

		/* Receive read file descriptors */
		rv = async_data_write_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		rc = async_data_write_finalize(callid, &readfds_in, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		errno_t retval;

		/* Go through all sockets and check them for read availability*/
		list_foreach(socket_list, link, common_socket_t, socket) {
			if (socket_read_avail[socket->domain][socket->type]) {
				bool read_avail;
				retval = socket_read_avail[socket->domain]
				    [socket->type](socket, &read_avail);

				if (retval != EOK) {
					continue;
				}

				readfds_out.fds_bits[socket->id] = read_avail &
				    readfds_in.fds_bits[socket->id];
			}
		}

		/* Send read file descriptors */
		rv = async_data_read_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
		rc = async_data_read_finalize(callid, &readfds_out, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
	}

	async_answer_0(iid, EOK);

	if (is_writefds) {
		fd_set writefds_in;
		fd_set writefds_out;
		memset(&writefds_out.fds_bits, 0, sizeof(writefds_out.fds_bits));

		/* Receive write file descriptors */
		rv = async_data_write_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		rc = async_data_write_finalize(callid, &writefds_in, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		errno_t retval;

		/* Go through all sockets and check them for write
		 * availability*/
		list_foreach(socket_list, link, common_socket_t, socket) {
			if (socket_write_avail[socket->domain][socket->type]) {
				bool write_avail;
				retval = socket_write_avail[socket->domain]
				    [socket->type](socket, &write_avail);

				if (retval != EOK) {
					continue;
				}

				writefds_out.fds_bits[socket->id] = write_avail
				    & writefds_in.fds_bits[socket->id];
			}
		}

		/* Send write file descriptors */
		rv = async_data_read_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
		rc = async_data_read_finalize(callid, &writefds_out, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
	}

	if (is_exceptfds) {
		fd_set exceptfds;

		/* Receive except file descriptors */
		rv = async_data_write_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		rc = async_data_write_finalize(callid, &exceptfds, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}

		/* Send except file descriptors */
		rv = async_data_read_receive(&callid, &size);
		if (!rv) {
			async_answer_0(callid, EREFUSED);
			async_answer_0(iid, EREFUSED);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
		rc = async_data_read_finalize(callid, &exceptfds, size);
		if (rc != EOK) {
			async_answer_0(callid, rc);
			async_answer_0(iid, rc);
			fibril_mutex_unlock(&socket_lock);
			return;
		}
	}

	fibril_mutex_unlock(&socket_lock);
}

/** Handle Socket client connection.
 *
 * @param iid	Connect call ID
 * @param icall	Connect call data
 * @param arg	Connection argument
 */
static void socket_client_conn(ipc_callid_t iid, ipc_call_t *icall, void *arg)
{
	/* Accept the connection */
	async_answer_0(iid, EOK);
	int session_id = generate_sesssion_id();

	log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_client_conn()");

	while (true) {
		ipc_call_t call;
		ipc_callid_t callid = async_get_call(&call);
		sysarg_t method = IPC_GET_IMETHOD(call);

		if (!method) {

			log_msg(LOG_DEFAULT, LVL_DEBUG, "Client hanged up");
			/* The other side has hung up */
			fibril_mutex_lock(&socket_lock);

			common_socket_t *socket;
			while ((socket = get_socket_by_session_id(session_id)) != NULL)
				if (socket_close[socket->domain][socket->type])
					socket_close[socket->domain][socket->type](socket);

			fibril_mutex_unlock(&socket_lock);

			free_session_id(session_id);
			async_answer_0(callid, EOK);
			break;
		}

		switch (method) {
		case SOCKET_CREATE:
			socket_create_srv(callid, &call, session_id);
			break;
		case SOCKET_BIND:
			socket_bind_srv(callid, &call);
			break;
		case SOCKET_LISTEN:
			socket_listen_srv(callid, &call);
			break;
		case SOCKET_CONNECT:
			socket_connect_srv(callid, &call);
			break;
		case SOCKET_ACCEPT:
			socket_accept_srv(callid, &call);
			break;
		case SOCKET_SETSOCKOPT:
			socket_setsockopt_srv(callid, &call);
			break;
		case SOCKET_GETSOCKNAME:
			socket_getsockname_srv(callid, &call);
			break;
		case SOCKET_SENDMSG:
			socket_sendmsg_srv(callid, &call);
			break;
		case SOCKET_RECVMSG:
			socket_recvmsg_srv(callid, &call);
			break;
		case SOCKET_WRITE:
			socket_write_srv(callid, &call);
			break;
		case SOCKET_READ:
			socket_read_srv(callid, &call);
			break;
		case SOCKET_CLOSE:
			socket_close_srv(callid, &call);
			break;
		case SOCKET_SELECT:
			socket_select_srv(callid, &call);
			break;
		}
	}
}

/** Initialize socket service.
 *
 * @return	EOK on success, error code on failure.
 */
errno_t socket_service_init(void)
{
	errno_t rc;
	service_id_t sid;

	async_set_fallback_port_handler(socket_client_conn, NULL);

	rc = loc_server_register(NAME);
	if (rc != EOK) {
		log_msg(LOG_DEFAULT, LVL_ERROR, "Failed registering server.");
		return EIO;
	}

	rc = loc_service_register(SERVICE_NAME_SOCKET, &sid);
	if (rc != EOK) {
		log_msg(LOG_DEFAULT, LVL_ERROR, "Failed registering service.");
		return EIO;
	}

	socket_create[AF_INET][SOCK_RAW] = raw_socket;
	socket_setsockopt[AF_INET][SOCK_RAW] = raw_socket_setsockopt;
	socket_read_avail[AF_INET][SOCK_RAW] = raw_socket_read_avail;
	socket_sendmsg[AF_INET][SOCK_RAW] = raw_socket_sendmsg;
	socket_recvmsg[AF_INET][SOCK_RAW] = raw_socket_recvmsg;
	socket_close[AF_INET][SOCK_RAW] = raw_socket_close;

	socket_create[AF_INET][SOCK_DGRAM] = udp_socket;
	socket_setsockopt[AF_INET][SOCK_DGRAM] = udp_socket_setsockopt;
	socket_bind[AF_INET][SOCK_DGRAM] = udp_socket_bind;
	socket_read_avail[AF_INET][SOCK_DGRAM] = udp_socket_read_avail;
	socket_sendmsg[AF_INET][SOCK_DGRAM] = udp_socket_sendmsg;
	socket_recvmsg[AF_INET][SOCK_DGRAM] = udp_socket_recvmsg;
	socket_close[AF_INET][SOCK_DGRAM] = udp_socket_close;

	socket_create[AF_INET][SOCK_STREAM] = tcp_socket;
	socket_setsockopt[AF_INET][SOCK_STREAM] = tcp_socket_setsockopt;
	socket_bind[AF_INET][SOCK_STREAM] = tcp_socket_bind;
	socket_listen[AF_INET][SOCK_STREAM] = tcp_socket_listen;
	socket_connect[AF_INET][SOCK_STREAM] = tcp_socket_connect;
	socket_accept[AF_INET][SOCK_STREAM] = tcp_socket_accept;
	socket_read_avail[AF_INET][SOCK_STREAM] = tcp_socket_read_avail;
	socket_write_avail[AF_INET][SOCK_STREAM] = tcp_socket_write_avail;
	socket_write[AF_INET][SOCK_STREAM] = tcp_socket_write;
	socket_read[AF_INET][SOCK_STREAM] = tcp_socket_read;
	socket_close[AF_INET][SOCK_STREAM] = tcp_socket_close;
	socket_getsockname[AF_INET][SOCK_STREAM] = tcp_socket_getsockname;

	socket_create[AF_UNIX][SOCK_STREAM] = unix_socket;
	socket_bind[AF_UNIX][SOCK_STREAM] = unix_socket_bind;
	socket_listen[AF_UNIX][SOCK_STREAM] = unix_socket_listen;
	socket_connect[AF_UNIX][SOCK_STREAM] = unix_socket_connect;
	socket_read_avail[AF_UNIX][SOCK_STREAM] = unix_socket_read_avail;
	socket_close[AF_UNIX][SOCK_STREAM] = unix_socket_close;

	return EOK;
}

/** @}
 */
