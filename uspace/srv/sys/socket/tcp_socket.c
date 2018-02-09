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
int tcp_socket(int domain, int type, int protocol, int session_id)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "    - Creating TCP socket");
    
        tcp_socket_t *tcp_socket = (tcp_socket_t *) calloc(1, sizeof(
            tcp_socket_t));
        common_socket_init(&tcp_socket->socket, domain, type, protocol,
            session_id);
        inet_ep_init(&tcp_socket->ep);
        list_initialize(&tcp_socket->tcp_conn_queue);
        return tcp_socket->socket.id;
}

/** Binds TCP socket to given address.
 * 
 * @param socket - socket to bind
 * @param addr - address to bind to
 * @param addrlen - address length
 * @return - EOK on success, error code on failure
 */
int tcp_socket_bind(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen) 
{    
        if (addrlen < sizeof(struct sockaddr_in))
                return EINVAL;

        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - Binding TCP socket");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * address: %d", 
            ((struct sockaddr_in*)addr)->sin_addr.s_addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * port: %d", 
            ((struct sockaddr_in*)addr)->sin_port);

        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;

        tcp_socket->ep.addr.version = ip_v4;
        tcp_socket->ep.addr.addr = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
        tcp_socket->ep.port = ntohs(((struct sockaddr_in*)addr)->sin_port);

        return EOK;
}

static void tcp_socket_new_conn(tcp_listener_t *lst, tcp_conn_t *conn)
{
        
        log_msg(LOG_DEFAULT, LVL_DEBUG, "TCP socket - new connection");       
        
        fibril_mutex_lock(&socket_lock);
        
        tcp_socket_t *tcp_listener_socket = (tcp_socket_t*)lst->lcb_arg;
        
        tcp_sock_conn_t *tcp_sock_conn = calloc(1, sizeof(tcp_sock_conn_t));
        link_initialize(&tcp_sock_conn->conn_queue_link);
        fibril_condvar_initialize(&tcp_sock_conn->tcp_conn_fcv);
        tcp_sock_conn->tcp_conn = conn;
        list_append(&tcp_sock_conn->conn_queue_link, 
            &tcp_listener_socket->tcp_conn_queue);
        
        fibril_condvar_wait(&tcp_sock_conn->tcp_conn_fcv, &socket_lock);
        
        fibril_mutex_unlock(&socket_lock);
}

int tcp_socket_listen(common_socket_t *socket, int backlog) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_listen()");
    
        int rc;
                
        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;

        tcp_socket->is_listener = true;
        tcp_listener_t *lst;
        rc = tcp_listener_create(socket_tcp, &tcp_socket->ep,
                &listen_cb, socket, &conn_cb, NULL, &lst);
        
        return rc;
        
}

int tcp_socket_connect(common_socket_t *socket, const struct sockaddr *addr,
        socklen_t addrlen) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "connect, fd: %d <<<<<<", socket->id);
    
        if (addrlen < sizeof(struct sockaddr_in))
                return EINVAL;
        
        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        if (tcp_socket->tcp_sock_conn != NULL)
                return EISCONN;
        
        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        
        inet_ep2_t epp;
        memcpy(&epp.local, tcp_socket->ep, sizeof(inet_ep_t));
        epp.remote.addr = htonl(((sockaddr_in*)addr)->sin_addr.s_addr;
        epp.remote.addr = htonl(((sockaddr_in*)addr)->sin_port;
        
        tcp_conn_create(socket_tcp, &epp, NULL, NULL, tcp_socket->tcp_sock_conn->tcp_conn);
    
        return ECONNREFUSED;
}

int tcp_socket_accept(common_socket_t *socket, int *fd,
        const struct sockaddr *addr, socklen_t *addrlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_accept()");
    
        if (*addrlen < sizeof(struct sockaddr_in)) {
                return EINVAL;   
        }
        
        tcp_socket_t *tcp_listener_socket = (tcp_socket_t*)socket;
                
        if (list_empty(&tcp_listener_socket->tcp_conn_queue)) {
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
        
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "Accepted, fd: %d", *fd);
        
        return EOK;
}

int tcp_socket_getsockname(common_socket_t * socket, 
        const struct sockaddr *addr, socklen_t *addrlen)
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_getsockname()");
    
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
        
        return EOK;
}

bool tcp_socket_read_avail(common_socket_t *socket) 
{    
        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;
        if (tcp_socket->is_listener) {
                return !list_empty(&tcp_socket->tcp_conn_queue);
        } else {
                if (tcp_socket->tcp_sock_conn == NULL || 
                    tcp_socket->tcp_sock_conn->tcp_conn == NULL) {
                        return false;
                }
                return tcp_socket->tcp_sock_conn->tcp_conn->data_avail;
        }
}


int tcp_socket_write(common_socket_t *socket, void *buf, size_t count,
        size_t *nsent) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_write()");
    
        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;
        
        int rc = tcp_conn_send(tcp_socket->tcp_sock_conn->tcp_conn, buf, count);
        *nsent = count;
        
        return rc;
}

int tcp_socket_read(common_socket_t *socket, void *buf, size_t count,
        size_t *nrecv) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_read()");
    
        tcp_socket_t* tcp_socket = (tcp_socket_t*)socket;
        
        int rc = tcp_conn_recv(tcp_socket->tcp_sock_conn->tcp_conn, buf, count,
                nrecv);
        
        return rc;
}

int tcp_socket_close(common_socket_t *socket) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - tcp_socket_close()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        
        tcp_socket_t *tcp_socket = (tcp_socket_t*)socket;
        list_remove(&tcp_socket->socket.link);
        free_socket_id(tcp_socket->socket.id);
        
        if (!tcp_socket->is_listener && tcp_socket->tcp_sock_conn != NULL) {
            fibril_condvar_signal(&tcp_socket->tcp_sock_conn->tcp_conn_fcv);
            free(tcp_socket->tcp_sock_conn);
        }
        free(tcp_socket);
        
        return EOK;
}