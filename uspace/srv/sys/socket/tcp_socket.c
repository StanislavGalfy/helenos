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
/** @file TCP socket
 */

#include <errno.h>
#include <macros.h>
#include <stdlib.h>
#include <byteorder.h>
#include <stdio.h>
#include <io/log.h>
#include <types/socket/if.h>
#include <types/socket/in.h>
#include <inet/inetcfg.h>
#include <loc.h>
#include <mem.h>

#include "tcp_socket.h"
#include "tools.h"

static void tcp_socket_new_conn(tcp_listener_t *, tcp_conn_t *);

static tcp_listen_cb_t listen_cb = {
	.new_conn = tcp_socket_new_conn
};

static tcp_cb_t conn_cb = {
	.connected = NULL
};

/** Creates TCP socket
 *
 * @param domain - socket domain
 * @param type - socket type
 * @param protocol - socket protocol
 * @param session_id - session id
 * @return socket file descriptor
 */
errno_t tcp_socket(int domain, int type, int protocol, int session_id, int *fd)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "    - Creating TCP socket");

        tcp_socket_t *tcp_socket = (tcp_socket_t *) calloc(1, sizeof(
            tcp_socket_t));
        common_socket_init(&tcp_socket->socket, domain, type, protocol,
            session_id);
        tcp_socket->is_listener = false;
        inet_ep_init(&tcp_socket->ep);
        list_initialize(&tcp_socket->tcp_conn_queue);
        *fd = tcp_socket->socket.id;

        return EOK;
}

/** Sets option for UDP socket.
 *
 * @param socket - socket to set option on
 * @param level - UNUSED
 * @param optname - option name
 * @param optval - option value
 * @param optlen - option value length
 * @return EOK on success, error code on failure
 */
errno_t tcp_socket_setsockopt(common_socket_t *socket, int level, int optname,
    const void *optval, socklen_t optlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_setsockopt()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);

        int retval;

        switch (optname) {
        // Make socket send and receive data only through given link
        case SO_BINDTODEVICE:
                log_msg(LOG_DEFAULT, LVL_DEBUG2,
                    "   * option: SO_BINDTODEVICE");
                retval = EOK;
                break;

        // Setup multicast on nic associated with link socket is bound to
        case IP_MULTICAST_IF:
                log_msg(LOG_DEFAULT, LVL_DEBUG2,
                    "   * option: IP_MULTICAST_IF");
                retval = EOK;
                break;

        // Reuse address, just return EOK - bird compatibility
        case SO_REUSEADDR:
                log_msg(LOG_DEFAULT, LVL_DEBUG2,
                    "   * option: SO_REUSEADDR");
                retval = EOK;
                break;

        // Type of service, just return EOK - bird compatibility
        case IP_TOS:
                log_msg(LOG_DEFAULT, LVL_DEBUG2,
                    "   * option: IP_TOS");
                retval = EOK;
                break;

        default:
                log_msg(LOG_DEFAULT, LVL_DEBUG2,
                    "   * option: unknown\n");
                retval = EOPNOTSUPP;
                break;
        }

        return retval;
}

/** Binds TCP socket to given address.
 *
 * @param socket - socket to bind
 * @param addr - address to bind to
 * @param addrlen - address length
 * @return - EOK on success, error code on failure
 */
errno_t tcp_socket_bind(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - Binding TCP socket");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * address: %d",
            ((struct sockaddr_in*)addr)->sin_addr.s_addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * port: %d",
            ((struct sockaddr_in*)addr)->sin_port);

        if (addrlen < sizeof(struct sockaddr_in))
                return EINVAL;

        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * is listener: %d", tcp_socket->is_listener);

        tcp_socket->ep.addr.version = ip_v4;
        tcp_socket->ep.addr.addr =
            ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
        tcp_socket->ep.port = ntohs(((struct sockaddr_in*)addr)->sin_port);

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * is listener: %d", tcp_socket->is_listener);

        return EOK;
}

static void tcp_socket_new_conn(tcp_listener_t *lst, tcp_conn_t *conn)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "tcp_socket_new_conn()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection remote addr: %d",
            conn->ident.remote.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection remote port: %d",
            conn->ident.remote.port);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection local addr: %d",
            conn->ident.local.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection local port: %d",
            conn->ident.local.port);

        fibril_mutex_lock(&socket_lock);

        tcp_socket_t *tcp_listener_socket = (tcp_socket_t*)lst->lcb_arg;

        tcp_sock_conn_t *tcp_sock_conn = calloc(1, sizeof(tcp_sock_conn_t));
        if (tcp_sock_conn == NULL) {
            fibril_mutex_unlock(&socket_lock);
            return;
        }
        tcp_sock_conn->is_incoming = true;

        link_initialize(&tcp_sock_conn->conn_queue_link);
        fibril_condvar_initialize(&tcp_sock_conn->tcp_conn_fcv);
        tcp_sock_conn->tcp_conn = conn;
        list_append(&tcp_sock_conn->conn_queue_link,
            &tcp_listener_socket->tcp_conn_queue);

        fibril_condvar_wait(&tcp_sock_conn->tcp_conn_fcv, &socket_lock);

        fibril_mutex_unlock(&socket_lock);
}

errno_t tcp_socket_listen(common_socket_t *socket, int backlog)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_listen()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);

        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;

        tcp_socket->is_listener = true;
        errno_t rc = tcp_listener_create(socket_tcp, &tcp_socket->ep,
            &listen_cb, socket, &conn_cb, NULL, &tcp_socket->tcp_listener);

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * return: %d", rc);

        return rc;

}

errno_t tcp_socket_connect(common_socket_t *socket, const struct sockaddr *addr,
        socklen_t addrlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_connect()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);

        if (addrlen < sizeof(struct sockaddr_in))
                return EINVAL;

        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        if (tcp_socket->tcp_sock_conn != NULL) {
                if (tcp_socket->tcp_sock_conn->tcp_conn != NULL) {
                        if (tcp_socket->tcp_sock_conn->tcp_conn->connected) {
                                return EISCONN;
                        }
                        return EINPROGRESS;
                }
        }

        inet_ep2_t epp;
        memset(&epp, 0, sizeof(inet_ep2_t));
        memcpy(&epp.local, &tcp_socket->ep, sizeof(inet_ep_t));
        epp.remote.addr.version = ip_v4;
        epp.remote.addr.addr = htonl(
            ((struct sockaddr_in*)addr)->sin_addr.s_addr);
        epp.remote.port = htons(((struct sockaddr_in*)addr)->sin_port);

        tcp_socket->tcp_sock_conn = calloc(1, sizeof(tcp_sock_conn_t));
        if (tcp_socket->tcp_sock_conn == NULL) {
            return ENOMEM;
        }
        tcp_socket->tcp_sock_conn->is_incoming = false;

        errno_t rc = tcp_conn_create(socket_tcp, &epp, NULL, NULL,
            &tcp_socket->tcp_sock_conn->tcp_conn);
        if (rc != EOK) {
                return rc;
        }
        return EINPROGRESS;
}

errno_t tcp_socket_accept(common_socket_t *socket, const struct sockaddr *addr,
        socklen_t *addrlen, int *fd)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_accept()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * listener socket id: %d",
            socket->id);

        if (*addrlen < sizeof(struct sockaddr_in)) {
                return EINVAL;
        }

        tcp_socket_t *tcp_listener_socket = (tcp_socket_t*)socket;

        if (list_empty(&tcp_listener_socket->tcp_conn_queue)) {
                log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * empty connection queue");
                return EWOULDBLOCK;
        }

        tcp_socket_t *tcp_socket = (tcp_socket_t *) calloc(1,
            sizeof(tcp_socket_t));
        if (tcp_socket == NULL) {
                return ENOMEM;
        }

        common_socket_init(&tcp_socket->socket,
            tcp_listener_socket->socket.domain,
            tcp_listener_socket->socket.type,
            tcp_listener_socket->socket.protocol,
            tcp_listener_socket->socket.session_id);

        tcp_socket->is_listener = false;
        memcpy (&tcp_socket->ep, &tcp_listener_socket->ep, sizeof(inet_ep_t));

        tcp_sock_conn_t *tcp_sock_conn = (tcp_sock_conn_t *)list_first(
            &tcp_listener_socket->tcp_conn_queue);

        tcp_socket->tcp_sock_conn = tcp_sock_conn;
        list_remove(&tcp_sock_conn->conn_queue_link);

        *fd = tcp_socket->socket.id;

        struct sockaddr_in *sa = (struct sockaddr_in*)addr;
        sa->sin_addr.s_addr = htonl(
            tcp_socket->tcp_sock_conn->tcp_conn->ident.remote.addr.addr);
        sa->sin_port = htons(
            tcp_socket->tcp_sock_conn->tcp_conn->ident.remote.port);
        sa->sin_family = AF_INET;

        *addrlen = sizeof(struct sockaddr_in);

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * new socket id: %d", *fd);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection remote addr: %d",
            tcp_socket->tcp_sock_conn->tcp_conn->ident.remote.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection remote port: %d",
            tcp_socket->tcp_sock_conn->tcp_conn->ident.remote.port);

        return EOK;
}

errno_t tcp_socket_getsockname(common_socket_t * socket,
        const struct sockaddr *addr, socklen_t *addrlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_getsockname()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);

        if (*addrlen < sizeof(struct sockaddr_in)) {
                return EINVAL;
        }

        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        struct sockaddr_in *sa = (struct sockaddr_in*)addr;
        sa->sin_addr.s_addr = htonl(
            tcp_socket->tcp_sock_conn->tcp_conn->ident.local.addr.addr);
        sa->sin_port = htons(
            tcp_socket->tcp_sock_conn->tcp_conn->ident.local.port);
        sa->sin_family = AF_INET;

        *addrlen = sizeof(struct sockaddr_in);

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection local addr: %d",
            tcp_socket->tcp_sock_conn->tcp_conn->ident.local.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * connection local port: %d",
            tcp_socket->tcp_sock_conn->tcp_conn->ident.local.port);

        return EOK;
}

errno_t tcp_socket_read_avail(common_socket_t *socket, bool *read_avail)
{
        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;
        if (tcp_socket->is_listener) {
                *read_avail = !list_empty(&tcp_socket->tcp_conn_queue);
                return EOK;
        } else {
                if (tcp_socket->tcp_sock_conn == NULL ||
                    tcp_socket->tcp_sock_conn->tcp_conn == NULL) {
                        *read_avail = false;
                        return EOK;
                }
                *read_avail = tcp_socket->tcp_sock_conn->tcp_conn->data_avail;
                return EOK;
        }
}

errno_t tcp_socket_write_avail(common_socket_t *socket, bool *write_avail)
{
        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;
        if (tcp_socket->tcp_sock_conn != NULL &&
            tcp_socket->tcp_sock_conn->tcp_conn != NULL) {
                *write_avail = tcp_socket->tcp_sock_conn->tcp_conn->connected;
                return EOK;
        }
        *write_avail = false;
        return EOK;
}


errno_t tcp_socket_write(common_socket_t *socket, void *buf, size_t count,
        size_t *nsent)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_write()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * data count to send: %d", count);

        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;

        int rc = EOK;
        if (count > 0)
                rc = tcp_conn_send(tcp_socket->tcp_sock_conn->tcp_conn, buf, count);

        *nsent = count;

        return rc;
}

errno_t tcp_socket_read(common_socket_t *socket, void *buf, size_t count,
        size_t *nrecv)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_read()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * data count to receive: %d",
            count);

        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;

        int rc = tcp_conn_recv(tcp_socket->tcp_sock_conn->tcp_conn, buf, count,
            nrecv);

        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * data count actually received: %d",
            *nrecv);

        return rc;
}

errno_t tcp_socket_close(common_socket_t *socket)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_close()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);

        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        list_remove(&tcp_socket->socket.link);
        free_socket_id(tcp_socket->socket.id);

        if (tcp_socket->is_listener) {
                log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * closing listener");
                if (tcp_socket->tcp_listener != NULL) {
                        tcp_listener_destroy(tcp_socket->tcp_listener);
                        list_foreach(tcp_socket->tcp_conn_queue,
                            conn_queue_link, tcp_sock_conn_t, tcp_sock_conn) {
                                fibril_condvar_signal(&tcp_sock_conn->tcp_conn_fcv);
                                free(tcp_sock_conn);
                        }
                        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * tcp listener destroyed");
                }
        } else {
                log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * closing normal");
                if (tcp_socket->tcp_sock_conn != NULL) {
                        if (tcp_socket->tcp_sock_conn->is_incoming) {
                                log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * incoming");
                                fibril_condvar_signal(&tcp_socket->tcp_sock_conn->tcp_conn_fcv);
                        } else {
                                if (tcp_socket->tcp_sock_conn->tcp_conn != NULL) {
                                        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * destroying connection");
                                        tcp_conn_destroy(tcp_socket->tcp_sock_conn->tcp_conn);
                                }
                        }
                        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * freeing connection");
                        free(tcp_socket->tcp_sock_conn);
                }
        }
        free(tcp_socket);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * done");
        return EOK;
}