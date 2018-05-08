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
 * Following combinations of domain, type, protocol are implemented:
 *
 * AF_INET, SOCK_RAW, IPPROTO_OSPF	OSPF socket.
 * AF_INET, SOCK_DGRAM, IPPROTO_UDP	UDP socket.
 * AF_INET, SOCK_STREAM, IPPROTO_TCP	TCP socket.
 * AF_UNIX, SOCK_STREAM, 0		UNIX socket.
 *
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
 * Options can be set on TCP, UDP and OSPF sockets. Each of them has the same
 * set of options. Option level is SOL_IP for all of them. They are as follows.
 * If the function fails, error code is stored in errno.
 *
 * SO_BINDTODEVICE	Binds a socket to an interface. Option value is a
 *			pointer to string with a name of the interface. Option
 *			length is length of the string.
 *
 * IP_MULTICAST_IF	Enables multicast on an interface the socket is bound
 *			to. Option value and option length are not used.
 *
 * SO_REUSEADDR		Socket addresses are reusable by default. Does nothing,
 *			returns EOK (BIRD compatibility).
 *
 * IP_TOS		Does nothing, returns EOK (BIRD compatibility).
 *
 *
 * @param sockfd	Socket file descriptor.
 * @param level		Option level.
 * @param optname	Option name.
 * @param optval	Option value.
 * @param optlen	Option length.
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
 * Implemented for UDP, TCP and UNIX sockets. If called on UNIX socket, the
 * function does nothing and returns EOK (BIRD compatibility).
 *
 * For TCP and UDP sockets, address is expected to be sockaddr_in structure and
 * address length size of the structure. The structure specifies a local port
 * and a local address of the socket. In case of UDP socket, the function
 * creates UDP association. In case of TCP socket, the function only prepares
 * address and port which will be used during connect. If the function fails,
 * error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Socket address.
 * @param addrlen	Socket address length.
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

/** Sends a message through a socket.
 *
 * Implemented for OSPF and UDP sockets. The message attributes are expected to
 * be as follows.
 *
 * msg_name		Destination of the message, a pointer to a sockaddr_in
 *			structure. It specifies remote address (OSPF socket) /
 *			remote address and port(UDP socket).
 *
 * msg_namelen		Size of the sockaddr_in structure.
 *
 * msg_iov		Array of input/output vectors. Each vector specifies
 *			pointer to data and their size. Only the first vector is
 *			used.
 *
 * msg_iov_len		Number of input/output vectors.
 *
 * msg_control		Pointer to array of control messages, not used.
 *
 * msg_controllen	Size of the control message array, not used.
 *
 * The function sends data from the first input/output vector to the destination
 * given by msg_name. Flags are not used. If the function fails, error code is
 * stored in errno.
 *
 * @param sockfd	Sockets file descriptor.
 * @param msg		Message.
 * @param flags		Flags.
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

/** Receives a message from a socket.
 *
 * Implemented for OSPF and UDP sockets. The function reads one packet from
 * a socket and stores its data and info about it into the message. All parts
 * of the message must be preallocated. The message is filled as follows.
 *
 * msg_name		Points to a sockaddr_in structure. The function fills it
 *			with packet's remote address (OSPF socket) / remote
 *			address and port(UDP socket) in it.
 *
 * msg_namelen		It should be at least size of a sockaddr_in structure.
 *			The function sets it to the size of returned msg_name,
 *			which is the size of sockaddr_in structure.
 *
 * msg_iov		Array of input/output vectors. Each vector specifies
 *			pointer to a buffer and its size. The function stores
 *			data of the packet in the first vector and sets its size
 *			to the size of the received data. Other vectors are not
 *			used.
 *
 * msg_iovlen		Number of input/output vectors.
 *
 * msg_control		Pointer to array of cmsghdr structures. Data of the
 *			first should point to a in_pktinfo structure. The packet
 *			info is filled with local address and local interface id
 *			(OSPF socket) / local address, local port and local
 *			interface id (UDP socket). Other control messages are
 *			not used
 *
 * msg_controllen	Size of the control message array.
 *
 * First input/output vector is filled with packet's
 * data. Attribute msg_control should point to one  Flags are not used.
 * If the function fails, error code is stored in errno.
 *
 * @param sockfd	Sockets file descriptor.
 * @param msg		Message.
 * @param flags		Flags.
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

/** Writes data to a socket.
 *
 * Implemented for TCP sockets only. Sends data from buffer over TCP. The number
 * of bytes to send is specified by byte count. If the function fails, error
 * code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param buf		Buffer.
 * @param count		Byte count.
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

/** Reads data from socket.
 *
 * Implemented for TCP sockets only. Reads at most byte count bytes from TCP
 * connection and stores them in the buffer. If the function fails, error code
 * is stored in errno.
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

/** Listens for incoming connections on a socket.
 *
 * Implemented for TCP and UNIX sockets. If called on UNIX socket, the function
 * does nothing and returns EOK (BIRD compatibility). If called on a TCP
 * socket, it starts listening for incoming TCP connections. If the function
 * fails, error code is stored in errno.
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

/** Connects a socket.
 *
 * Implemented for TCP and UNIX sockets. If called on UNIX socket, the function
 * does nothing and returns ECONNREFUSED (BIRD compatibility). If called on a TCP
 * socket, it creates a TCP connection to destination given by socket address.
 * The socket address is expected to be sockaddr_in structure specifying remote
 * address and port the TCP connection. The socket address length is expected to
 * be size of the sockaddr_in structure. If the function fails, error code is
 * stored in errno.
 *
 * @param sockfd	Sockets file descriptor
 * @param addr		Socket address.
 * @param addrlen	Socket address length.
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
 * Implemented for TCP sockets only. Socket address is expected to be a
 * sockaddr_in structure and socket address length to be size of sockaddr_in.
 * The function fill the socket address with local address and local port of the
 * socket. If the function fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Socket address.
 * @param addrlen	Socket address length.
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
 * Implemented for TCP sockets only. Accepts first TCP connection from
 * connection queue of the TCP listener socket. Listen must have been called
 * previously on the socket.  Socket address is expected to be a sockaddr_in
 * structure and socket address length to be size of sockaddr_in. The function
 * fills the socket address with remote address and remote port of the
 * connection. If the function fails, error code is stored in errno.
 *
 * @param sockfd	Socket file descriptor.
 * @param addr		Socket address.
 * @param addrlen	Socket address length.
 * @return		EOK on success, SOCK_ERR on failure.
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	async_exch_t *exch = async_exchange_begin(sess);

	ipc_call_t answer;
	bool is_addr = addr != NULL;
	/* Send parameters that can be sent as sysarg_t */
	aid_t req = async_send_3(exch, SOCKET_ACCEPT, sockfd, *addrlen, is_addr,
	    &answer);

	/* Receive socket address */
	if (is_addr) {
		int rc = async_data_read_start(exch, addr, *addrlen);
		CHECK_RC();
	}

	async_exchange_end(exch);

	int retval;
	async_wait_for(req, &retval);
	CHECK_RETVAL();

	int new_sockfd = IPC_GET_ARG1(answer);
	*addrlen = IPC_GET_ARG2(answer);

	return new_sockfd;
}

/** Closes a socket.
 *
 * Implemented for OSPF, UDP, TCP and UNIX socket. Socket to close is looked up
 * by sockfd on service side. OSPF and UDP sockets deallocate pending messages.
 * TCP listener sockets destroy their TCP listener. Connected TCP sockets destroy
 * their connection.
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
 * Initially, the read set contains file socket file descriptors to be checked
 * for read availability . Read availablity is checked for OSPF, UDP and TCP
 * sockets. After the call, the set contains OSPF, UDP and TCP socket file
 * descriptors that were initially in the set, and have data available for
 * reading.
 *
 * Initially, the write set contains socket file descriptors to be checked for
 * write availability. Read availablity is checked for TCP sockets. After
 * the call, the set contains TCP socket file descriptors that were initially in
 * the set, and have established TCP connection.
 *
 * Nfds, except set and timeout are not used.
 *
 * @param nfds		Highest file descriptor in all three sets.
 * @param readfds	Read set.
 * @param writefds	Write set.
 * @param exceptfds	Except set
 * @param timeout	Timeout.
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
