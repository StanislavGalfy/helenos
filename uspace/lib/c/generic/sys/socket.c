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

/** @addtogroup libc
 * @{
 */
/** @file
 */

#include <errno.h>
#include <loc.h>
#include <async.h>
#include <ipc/services.h>
#include <ipc/socket.h>
#include <sys/socket.h>
#include <inet/inetcfg.h>
#include <stdlib.h>
#include <types/socket/in.h>
#include <stdio.h>
#include <time.h>

/** Macro to handle return code from async_data_write_start call */
#define CHECK_RC() \
        if (rc != EOK) { \
                async_exchange_end(exch); \
                async_forget(req); \
                errno = rc; \
                return SOCK_ERR; \
        }

/** Macro to handle return value from service acquired by async_wait_for */
#define CHECK_RETVAL() \
        if ((int)retval != EOK) { \
                errno = retval; \
                return SOCK_ERR; \
        }

/** Asynchronous session with socket service, initialized when first socket
 is created, shared between all functions */
static async_sess_t* sess;

/** Sockets are initialized once when first socket is created by application
 * using this library. Indicates if initialization already happened */
static bool sockets_initialized = false;

/**
 * Creates asynchronous session with socket service.
 *
 * @return	EOK on success, EIO if the session was not created.
 */
static int socket_init()
{
	if (!sockets_initialized) {
		service_id_t socket_svcid;
		int rc = loc_service_get_id(SERVICE_NAME_SOCKET, &socket_svcid,
		    IPC_FLAG_BLOCKING);
		if (rc != EOK) {
			rc = EIO;
			return rc;
		}

		sess = loc_service_connect(socket_svcid, INTERFACE_SOCKET,
		    IPC_FLAG_BLOCKING);
		if (sess == NULL) {
			return EIO;
		}
		sockets_initialized = true;
		return EOK;
	}
	return EOK;
}

/** Creates new socket.
 *
 * Socket structure  is created on service side. It can be accessed through
 * returned file descriptor. If the function fails, error code is stored in
 * errno.
 *
 * @param domain	Socket domain.
 * @param type		Socket type.
 * @param protocol	Socket protocol.
 * @return		Socket file descriptor on success, SOCK_ERR on failure.
 */
int socket(int domain, int type, int protocol)
{
	int rc = socket_init();
	if (rc != EOK) {
		errno = rc;
		return SOCK_ERR;
	}

	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* All parameters sent as sysarg_t */
	aid_t req = async_send_3(exch, SOCKET_CREATE, domain, type, protocol,
	    &answer);
	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	int fd = IPC_GET_ARG1(answer);
	return fd;
}

/** Sets option on socket.
 *
 * Option is set on socket structure on service side looked up by given socket
 * file descriptor. If the function fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param level		Level at which the option reside.
 * @param optname	Name of the option.
 * @param optval	Value of option to set.
 * @param optlen	Length of optval.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int setsockopt(int sockfd, int level, int optname, const void *optval,
    socklen_t optlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_3(exch, SOCKET_SETSOCKOPT, sockfd, level,
	    optname, &answer);

	/* Send option value */
	int rc = async_data_write_start(exch, optval, optlen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return retval;
}

/** Binds socket to given address.
 *
 * Bound is socket structure looked up by sockfd on service side. If the
 * function fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Address to which the socket will be bound.
 * @param addrlen	Length of addr.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/*  Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_1(exch, SOCKET_BIND, sockfd, &answer);

	/* Send socket address */
	int rc = async_data_write_start(exch, addr, addrlen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return retval;
}

/** Sends message through socket.
 *
 * How the message will be send is decided according to socket structure given
 * by @a sockfd. The structure is looked up on service side. If the function
 * fails, error code is stored in errno.
 *
 * @param sockfd	Sockets file descriptor.
 * @param msg		Pointer to message that will be sent.
 * @param flags		Flags to further configure sending - currently
 *			unsupported.
 * @return		Number of sent bytes on success, SOCK_ERR on failure.
 */
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_3(exch, SOCKET_SENDMSG, sockfd, msg->msg_iovlen,
	    flags, &answer);

	/* Send destination address */
	int rc = async_data_write_start(exch, msg->msg_name, msg->msg_namelen);
	CHECK_RC();

	/* Send input/output vectors */
	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		rc = async_data_write_start(exch, msg->msg_iov[i].iov_base,
		    msg->msg_iov[i].iov_len);
		CHECK_RC();
	}

	/* Send control message */
	rc = async_data_write_start(exch, msg->msg_control,
	    msg->msg_controllen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	ssize_t nsent = IPC_GET_ARG1(answer);
	return nsent;
}

/** Receives message from a socket.
 *
 * Message that will be received is determined by socket structure looked up by
 * @a sockfd. The structure is looked up on service side. If the function
 * fails, error code is stored in errno.
 *
 * @param sockfd	Sockets file descriptor.
 * @param msg		Pointer where will be stored the received message.
 * @param flags		Flags to further configure receiving - currently not
 *			supported.
 * @return		Number recived bytes on sucess, SOCK_ERR on failure.
 */
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t (sockfd,
	 * msg->msg_namelen - size of structure where will be stored source
	 * address of the message, msg->msg_iovlen - number of input/output
	 * vectors the message contains, msg->msg_controllen - size of structure
	 *  where will be store additional info, flags) */
	aid_t req = async_send_5(exch, SOCKET_RECVMSG, sockfd, msg->msg_namelen,
	    msg->msg_iovlen, msg->msg_controllen, flags, &answer);

	int rc;
	/* Send respective size of each input/output vector */
	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		rc = async_data_write_start(exch, &msg->msg_iov[i].iov_len,
		    sizeof(size_t));
		CHECK_RC();
	}

	/* Receive source address of the message */
	rc = async_data_read_start(exch, msg->msg_name, msg->msg_namelen);
	CHECK_RC();

	/* Receive data into intup/output vectors */
	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		rc = async_data_read_start(exch, msg->msg_iov[i].iov_base,
		    msg->msg_iov[i].iov_len);
		CHECK_RC();
	}

	/* Receive control message */
	rc = async_data_read_start(exch, msg->msg_control, msg->msg_controllen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	ssize_t nrecv = IPC_GET_ARG1(answer);
	return nrecv;
}

/** Writes data to socket. Implemented for TCP sockets only. If the function
 * fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param buf		Data to send.
 * @param count		Byte count to send.
 * @return		Actually sent byte count on success, SOCK_ERR on
 *			failure.
 */
ssize_t sockwrite(int sockfd, const void *buf, size_t count)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/*  Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_1(exch, SOCKET_WRITE, sockfd, &answer);

	/* Send data */
	int rc = async_data_write_start(exch, buf, count);
	CHECK_RC();

	async_exchange_end(exch);
	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	ssize_t nsent = IPC_GET_ARG1(answer);
	return nsent;
}

/** Reads data from socket. Implemented for TCP sockets only. If the function
 * fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param buf		Buffer where read data will be stored.
 * @param count		Maximum count of bytes to read.
 * @return		Actually read byte count on success, SOCK_ERR on
 *			failure.
 */
ssize_t sockread(int sockfd, void *buf, size_t count)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/*  Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_2(exch, SOCKET_READ, sockfd, count, &answer);

	/* Read data */
	int rc = async_data_read_start(exch, buf, count);
	CHECK_RC();

	async_exchange_end(exch);
	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	ssize_t nrecv = IPC_GET_ARG1(answer);
	return nrecv;
}

/** Listens for incoming connections on a socket. If the function fails, error
 *  code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param backlog	Maximum number of connections to put in queue.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int listen(int sockfd, int backlog)
{
	async_sleep(1);

	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_2(exch, SOCKET_LISTEN, sockfd, backlog, &answer);

	async_exchange_end(exch);
	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return retval;
}

/** Connects socket.
 *
 * If the function fails, error code is stored in errno.
 *
 * @param sockfd	Sockets file descriptor
 * @param addr		Address to which socket should be connected.
 * @param addrlen	Length of address.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int connect(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_1(exch, SOCKET_CONNECT, sockfd, &answer);

	/* Send socket address */
	int rc = async_data_write_start(exch, addr, addrlen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return retval;
}

/** Return socket local address.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Pointer where will be returned address stored.
 * @param addrlen	Address length.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_2(exch, SOCKET_GETSOCKNAME, sockfd, *addrlen,
	    &answer);

	/* Receive socket address */
	int rc = async_data_read_start(exch, addr, *addrlen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	*addrlen = IPC_GET_ARG1(answer);

	return retval;
}

/** Accepts socket connection.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Pointer where will be store remote address of the
 *			connection.
 * @param addrlen	Address length.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_2(exch, SOCKET_ACCEPT, sockfd, *addrlen,
	    &answer);

	/* Receive socket address */
	int rc = async_data_read_start(exch, addr, *addrlen);
	CHECK_RC();

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	int new_sockfd = IPC_GET_ARG1(answer);
	*addrlen = IPC_GET_ARG2(answer);

	return new_sockfd;
}

/** Closes socket.
 *
 * Socket to close is looked up by sockfd on service side. If the function
 * fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int sockclose(int sockfd)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_1(exch, SOCKET_CLOSE, sockfd, &answer);

	async_exchange_end(exch);
	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return retval;
}

/** Socket select.
 *
 * @param nfds		Highest file descriptor in all three sets.
 * @param readfds	Socket file descriptors to check availability for
 *			reading.
 * @param writefds	Socket file descriptors to check availability for
 *			writing.
 * @param exceptfds	UNUSED.
 * @param timeout	UNUSED.
 * @return		Number of file descriptors contained in all sets after
 *			select.
 */
int sockselect(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
	async_exch_t *exch = async_exchange_begin(sess);

	bool is_readfds = readfds != NULL;
	bool is_writefds = writefds != NULL;
	bool is_exceptfds = exceptfds != NULL;
	bool is_timeout = timeout != NULL;

	ipc_call_t answer;
	/* Send parameters that can be sent as sysarg_t (sockfd) */
	aid_t req = async_send_5(exch, SOCKET_SELECT, nfds, is_readfds,
	    is_writefds, is_exceptfds, is_timeout, &answer);


	int rc;

	if (is_timeout) {
		/* Send timeout */
		rc = async_data_write_start(exch, timeout,
		    sizeof(struct timeval));
		CHECK_RC();
	}

	if (is_readfds) {
		/* Send read file descriptors */
		rc = async_data_write_start(exch, readfds, sizeof(fd_set));
		CHECK_RC();
		/* Receive read file descriptors */
		rc = async_data_read_start(exch, readfds, sizeof(fd_set));
		CHECK_RC();
	}

	if (is_writefds) {
		/* Send write file descriptors */
		rc = async_data_write_start(exch, writefds, sizeof(fd_set));
		CHECK_RC();
		/* Receive write file descriptors */
		rc = async_data_read_start(exch, writefds, sizeof(fd_set));
		CHECK_RC();
	}

	if (is_exceptfds) {
		/* Send except file descriptors */
		rc = async_data_write_start(exch, exceptfds, sizeof(fd_set));
		CHECK_RC();
		/* Receive except file descriptors */
		rc = async_data_read_start(exch, exceptfds, sizeof(fd_set));
		CHECK_RC();
	}

	async_exchange_end(exch);
	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	return nfds;
}

/** @}
 */
