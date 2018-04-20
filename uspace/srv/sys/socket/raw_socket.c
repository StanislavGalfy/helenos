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
/** @file Raw socket
 */

/** DISCLAIMER - main purpose of raw socket implementation is BIRD port.
 * It is not fully POSIX compliant, most features are not implemented.
 */

#include <types/socket/if.h>
#include <types/socket/in.h>
#include <loc.h>
#include <inet/inet.h>
#include <io/log.h>
#include <byteorder.h>
#include <stdlib.h>
#include <stdio.h>
#include <macros.h>
#include <errno.h>
#include <inet/inetcfg.h>
#include <nic_iface.h>
#include <mem.h>

#include "raw_socket.h"
#include "common_socket.h"
#include "tools.h"

#define IP_HEADER_BYTE_LENGTH 20
#define IP_HEADER_DWORD_LENGTH 5
#define IP_HEADER_IPV4_VERSION 4

/** Raw message */
typedef struct {
	/** Link to message queue of a particular socket */
	link_t msg_queue_link;
	/** Datagram received from inet */
	inet_dgram_t dgram;
} raw_msg_t;

/** Creates raw socket.
 *
 * @param domain	Socket domain.
 * @param type		Socket type.
 * @param protocol	Socket protocol.
 * @param session_id	Session id.
 * @return		Created socket id.
 */
errno_t raw_socket(int domain, int type, int protocol, int session_id, int *fd)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "    - Creating raw socket");

	raw_socket_t *raw_socket = (raw_socket_t *) calloc(1, sizeof(
	    raw_socket_t));
	common_socket_init(&raw_socket->socket, AF_INET, SOCK_RAW, protocol,
	    session_id);
	list_initialize(&raw_socket->msg_queue);
	*fd = raw_socket->socket.id;
	return EOK;
}

/** Sets option for raw socket.
 *
 * @param socket	Socket to set option on.
 * @param level		UNUSED.
 * @param optname	Option name.
 * @param optval	Option value.
 * @param optlen	Option value length.
 * @return		EOK on success, error code on failure.
 */
errno_t raw_socket_setsockopt(common_socket_t *socket, int level, int optname,
    const void *optval, socklen_t optlen)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " - raw_socket_setsockopt()");

	raw_socket_t *raw_socket = (raw_socket_t*) socket;

	log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);

	errno_t retval;
	inet_link_info_t linfo;

	switch (optname) {
	case SO_BINDTODEVICE:
		/* Make socket send and receive data only through given link */
		log_msg(LOG_DEFAULT, LVL_DEBUG2,
		    "   * option: SO_BINDTODEVICE");

		if (optlen < sizeof(struct ifreq)) {
			retval = EINVAL;
			break;
		}

		service_id_t sid;

		char *iface_name = ((struct ifreq*) optval)->ifr_name;
		retval = loc_service_get_id(iface_name, &sid, 0);
		if (retval != EOK)
			break;

		raw_socket->iplink = sid;
		retval = EOK;
		break;

	case IP_MULTICAST_IF:
		/* Setup multicast on nic associated with link socket is bound
		 * to */
		log_msg(LOG_DEFAULT, LVL_DEBUG2,
		    "   * option: IP_MULTICAST_IF");

		retval = inetcfg_link_get(raw_socket->iplink, &linfo);
		if (retval != EOK)
			break;

		async_sess_t *sess = loc_service_connect(
		    linfo.nic_svcid, INTERFACE_DDF, 0);
		retval = nic_multicast_set_mode(sess,
		    NIC_MULTICAST_PROMISC, NULL, 0);
		if (retval != EOK)
			break;

		retval = EOK;
		break;

	case SO_REUSEADDR:
		/* Reuse address, just return EOK - BIRD compatibility */
		log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * option: SO_REUSEADDR");
		retval = EOK;
		break;

	case IP_TOS:
		/* Type of service, just return EOK - BIRD compatibility */
		log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * option: IP_TOS");
		retval = EOK;
		break;

	default:
		log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * option: unknown");
		retval = EOPNOTSUPP;
		break;
	}
	return retval;
}

/** Checks if data are available for reading on given socket.
 *
 * @param socket	Socket to check.
 * @param read_avail	Pointer where will be stored the result.
 * @return		EOK.
 */
errno_t raw_socket_read_avail(common_socket_t *socket, bool *read_avail)
{
	raw_socket_t *raw_socket = (raw_socket_t*) socket;
	*read_avail = !list_empty(&raw_socket->msg_queue);
	return EOK;
}

/** Sends message through raw socket
 *
 * @param socket	Socket to send the message through.
 * @param msg		Message to send.
 * @param flags		UNUSED.
 * @return		EOK on success, error code on failure.
 */
errno_t raw_socket_sendmsg(common_socket_t *socket, const struct msghdr *msg,
    int flags, size_t *nsent)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " - raw_socket_sendmsg()");

	if (msg->msg_namelen < sizeof(struct sockaddr_in))
		return EINVAL;
	if (msg->msg_iovlen < 1)
		return EINVAL;

	raw_socket_t *raw_socket = (raw_socket_t*) socket;
	struct sockaddr_in *sa = (struct sockaddr_in*) msg->msg_name;

	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket link: %d",
	    raw_socket->iplink);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message size: %d",
	    msg->msg_iov[0].iov_len);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message dest addr: %x",
	    htonl(sa->sin_addr.s_addr));

	/* Convert message into datagram and send it through inet */
	inet_dgram_t dgram;
	dgram.iplink = raw_socket->iplink;
	dgram.size = msg->msg_iov[0].iov_len;
	dgram.data = msg->msg_iov[0].iov_base;
	dgram.tos = 0;
	dgram.dest.addr = htonl(sa->sin_addr.s_addr);
	dgram.dest.version = ip_v4;
	inet_addr_t src;
	errno_t rc = get_link_addr(raw_socket->iplink, &src);
	if (rc != EOK) {
		return rc;
	}
	dgram.src = src;

	*nsent = dgram.size;
	rc = inet_send(&dgram, INET_TTL_MAX, 0);
	return rc;
}

/** Received datagram callback.
 *
 * Allocates new raw message, copies content of received datagram into it, and
 * adds it to queue of received messages for all raw sockets bound to link,
 * from where the datagram was received.
 *
 * @param dgram	received datagram.
 * @return	EOK.
 */
errno_t raw_socket_inet_ev_recv(inet_dgram_t *dgram)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
	log_msg(LOG_DEFAULT, LVL_DEBUG, "raw_socket_inet_ev_recv()");
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message size: %d", dgram->size);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message source: %d",
	    dgram->src.addr);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message link: %d", dgram->iplink);

	fibril_mutex_lock(&socket_lock);

	list_foreach(socket_list, link, common_socket_t, socket) {
		if (socket->domain != AF_INET || socket->type != SOCK_RAW) {
			continue;
		}

		raw_socket_t *raw_socket = (raw_socket_t*) socket;
		if (raw_socket->iplink != dgram->iplink) {
			continue;
		}

		raw_msg_t* raw_msg = malloc(sizeof(raw_msg_t));
		/* If there is no more memory, just discard the datagram and
		 * return EOK */
		if (raw_msg == NULL) {
			fibril_mutex_unlock(&socket_lock);
			return EOK;
		}

		link_initialize(&raw_msg->msg_queue_link);
		raw_msg->dgram.iplink = dgram->iplink;
		raw_msg->dgram.src = dgram->src;
		raw_msg->dgram.dest = dgram->dest;
		raw_msg->dgram.tos = dgram->tos;
		raw_msg->dgram.data = malloc(dgram->size);
		/* If there is no more memory, just discard the datagram and
		 * return EOK */
		if (raw_msg->dgram.data == NULL) {
			free(raw_msg);
			fibril_mutex_unlock(&socket_lock);
			return EOK;
		}
		memcpy(raw_msg->dgram.data, dgram->data, dgram->size);
		raw_msg->dgram.size = dgram->size;

		list_append(&raw_msg->msg_queue_link, &raw_socket->msg_queue);
	}

	fibril_mutex_unlock(&socket_lock);
	return EOK;
}

/** Receives message from raw socket.
 *
 * @param socket	Socket to receive from.
 * @param msg		Structure, where will be stored data and information
 *			about them.
 * @param flags		UNUSED.
 * @param rsize		Pointer, where will be stored number of received bytes.
 * @return		EOK on success, error code on failure.
 */
errno_t raw_socket_recvmsg(common_socket_t* socket, struct msghdr *msg,
    int flags, size_t *rsize)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " - raw_socket_recvmsg()");
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket link: %d",
	    ((raw_socket_t*) socket)->iplink);

	raw_socket_t *raw_socket = (raw_socket_t*) socket;

	if (msg->msg_namelen < sizeof(struct sockaddr_in))
		return EINVAL;
	if (msg->msg_iovlen < 1)
		return EINVAL;
	if (msg->msg_controllen < CMSG_LEN(sizeof(struct in_pktinfo)))
		return EINVAL;

	/* Get first message from the queue */
	raw_msg_t *raw_msg = (raw_msg_t*) list_first(&raw_socket->msg_queue);
	if (raw_msg == NULL) {
		log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * empty socket message"
		    " queue ");
		return EWOULDBLOCK;
	}

	/* Fill info about source, where the message was received from */
	struct sockaddr_in *sa = (struct sockaddr_in*) msg->msg_name;
	sa->sin_addr.s_addr = htonl(raw_msg->dgram.src.addr);
	sa->sin_port = 0;
	sa->sin_family = AF_INET;

	/* Reconstruct beginning of IP header and put it before the actual data.
	 * Only first byte of IP header is set - this byte describes ip version
	 * (IPv4) and ip header length (20) */
	struct iovec *iov = &msg->msg_iov[0];
	if (iov->iov_len >= 1) {
		((unsigned char*) iov->iov_base)[0] =
		    (IP_HEADER_IPV4_VERSION << 4) | IP_HEADER_DWORD_LENGTH;
	}
	/* Put actual data after 20 bytes long header. */
	if (iov->iov_len > IP_HEADER_BYTE_LENGTH) {
		memcpy(iov->iov_base + IP_HEADER_BYTE_LENGTH,
		    raw_msg->dgram.data, min(raw_msg->dgram.size, iov->iov_len
		    - IP_HEADER_BYTE_LENGTH));
	}
	iov->iov_len = min(iov->iov_len, raw_msg->dgram.size +
	    IP_HEADER_BYTE_LENGTH);

	/* Fill additional info about received data */
	struct cmsghdr *msg_control = (struct cmsghdr*) msg->msg_control;
	msg_control->cmsg_level = SOL_IP;
	msg_control->cmsg_type = IP_PKTINFO;
	struct in_pktinfo *pi = (struct in_pktinfo*) CMSG_DATA(msg_control);
	/* Local address datagram was destined to */
	pi->ipi_addr.s_addr = htonl(raw_msg->dgram.dest.addr);
	/* Service id of link datagram was received through, set as interface
	 *  index */
	pi->ipi_ifindex = raw_msg->dgram.iplink;

	/* Remove the raw message from queue */
	list_remove(&raw_msg->msg_queue_link);
	if (raw_msg->dgram.data != NULL)
		free(raw_msg->dgram.data);
	free(raw_msg);

	*rsize = iov->iov_len;

	return EOK;
}

/** Closes raw socket.
 *
 * @param socket	The socket to close.
 * @return		EOK.
 */
errno_t raw_socket_close(common_socket_t* socket)
{
	log_msg(LOG_DEFAULT, LVL_DEBUG2, " - raw_socket_close()");
	log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);

	raw_socket_t *raw_socket = (raw_socket_t*) socket;
	list_remove(&raw_socket->socket.link);
	free_socket_id(raw_socket->socket.id);

	while (!list_empty(&raw_socket->msg_queue)) {
		raw_msg_t *raw_msg = (raw_msg_t*) list_first(
		    &raw_socket->msg_queue);
		list_remove(&raw_msg->msg_queue_link);
		if (raw_msg->dgram.data != NULL)
			free(raw_msg->dgram.data);
		free(raw_msg);
	}

	free(raw_socket);

	return EOK;
}

/** @}
 */
