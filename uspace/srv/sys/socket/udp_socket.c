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
/** @file UDP socket
 */

/** DISCLAIMER - main purpose of udp socket implementation is BIRD port. 
 * It is not fully POSIX compliant, most features are not implemented. 
 */

#include <errno.h>
#include <macros.h>
#include <stdlib.h>
#include <byteorder.h>
#include <stdio.h>
#include <io/log.h>
#include <types/socket/if.h>
#include <inet/inetcfg.h>
#include <loc.h>
#include <nic_iface.h>
#include <mem.h>

#include "udp_socket.h"
#include "tools.h"

/** UDP message stored by socket */
typedef struct {
        /** Link to list of messages */
        link_t msg_queue_link;
        /** Endpoint, from where the message was received */
        inet_ep_t remote_ep;
        /** Received data size */
        size_t data_size;
        /** Received data */
        void *data;
} udp_msg_t;

static void udp_socket_ev_recv(udp_assoc_t *, udp_rmsg_t *);
static void udp_socket_ev_recv_err(udp_assoc_t *, udp_rerr_t *);
static void udp_socket_ev_link_state(udp_assoc_t *, udp_link_state_t);

/** Callback for UDP association */
static udp_cb_t udp_socket_cb = {
        .recv_msg = udp_socket_ev_recv,
        .recv_err = udp_socket_ev_recv_err,
        .link_state = udp_socket_ev_link_state
};

/** Creates UDP socket
 * 
 * @param domain - socket domain
 * @param type - socket type
 * @param protocol - socket protocol
 * @param session_id - session id
 * @return socket file descriptor
 */
errno_t udp_socket(int domain, int type, int protocol, int session_id, int *fd)
{
        udp_socket_t *udp_socket = (udp_socket_t *) calloc(1, sizeof(udp_socket_t));
        common_socket_init(&udp_socket->socket, domain, type, protocol,
            session_id);
        list_initialize(&udp_socket->msg_queue);
        *fd = udp_socket->socket.id;
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
errno_t udp_socket_setsockopt(common_socket_t *socket, int level, int optname,
    const void *optval, socklen_t optlen) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - udp_socket_setsockopt()");
    
        udp_socket_t *udp_socket = (udp_socket_t*)socket;
        
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "   * socket id: %d", socket->id);
        
        int retval;
        inet_link_info_t linfo;

        switch (optname) {
        // Make socket send and receive data only through given link
        case SO_BINDTODEVICE:
                log_msg(LOG_DEFAULT, LVL_DEBUG2, 
                    "   * option: SO_BINDTODEVICE");
                
                if (optlen < sizeof(struct ifreq)) {
                        retval = EINVAL;
                        break;
                }

                service_id_t sid;

                char *iface_name = ((struct ifreq*)optval)->ifr_name;
                retval = loc_service_get_id(iface_name, &sid, 0);
                if (retval != EOK)
                        break;

                udp_socket->iplink = sid;
                retval = EOK;
                break;

        // Setup multicast on nic associated with link socket is bound to
        case IP_MULTICAST_IF:
                log_msg(LOG_DEFAULT, LVL_DEBUG2, 
                    "   * option: IP_MULTICAST_IF");
            
                retval = inetcfg_link_get(udp_socket->iplink, &linfo);
                if (retval != EOK)
                        break;

                async_sess_t *sess = loc_service_connect(linfo.nic_svcid,
                    INTERFACE_DDF, 0);
                retval = nic_multicast_set_mode(sess, 
                    NIC_MULTICAST_PROMISC, NULL, 0);
                if (retval != EOK)
                        break;           

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

/** Binds UDP socket to given address.
 * 
 * @param socket - socket to bind
 * @param addr - address to bind to
 * @param addrlen - address length
 * @return - EOK on success, error code on failure
 */
errno_t udp_socket_bind(common_socket_t *socket, const struct sockaddr *addr,
    socklen_t addrlen) 
{    
        if (addrlen < sizeof(struct sockaddr_in))
                return EINVAL;

        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - Binding UDP socket");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * port: %d", 
            ((struct sockaddr_in*)addr)->sin_port);

        udp_socket_t* udp_socket = (udp_socket_t*)socket;

        inet_ep2_t epp;
        inet_ep2_init(&epp);

        epp.local_link = udp_socket->iplink;
        epp.local.addr.version = ip_v4;
        epp.local.port = ntohs(((struct sockaddr_in*)addr)->sin_port);

        int rc = udp_assoc_create(socket_udp, &epp, &udp_socket_cb, socket,
            &udp_socket->udp_assoc);
        
        return rc;
}

errno_t udp_socket_read_avail(common_socket_t *socket, bool *read_avail) 
{
        udp_socket_t *udp_socket = (udp_socket_t*)socket;
        *read_avail = !list_empty(&udp_socket->msg_queue);
        return EOK;
}

/** Send message through UDP socket
 * 
 * @param socket - socket to send message through
 * @param msg - message to send
 * @param flags - UNUSED
 * @return - EOK on success, error code on failure
 */
errno_t udp_socket_sendmsg(common_socket_t *socket, const struct msghdr *msg,
    int flags, size_t *nsent) 
{
        if (msg->msg_namelen < sizeof(struct sockaddr_in))
                return EINVAL;
        if (msg->msg_iovlen < 1)
                return EINVAL;

        udp_socket_t *udp_socket = (udp_socket_t*)socket;
        struct sockaddr_in *sa = (struct sockaddr_in*)msg->msg_name;

        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - Sending message through UDP "
            "socket");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        
        if (udp_socket->udp_assoc == NULL)
                return EINVAL;    

        inet_ep_t ep;
        inet_ep_init(&ep);

        ep.addr.addr = htonl(sa->sin_addr.s_addr);
        ep.port = htons(sa->sin_port);
        ep.addr.version = ip_v4;
        
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * dest addr: %x", ep.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * dest port: %d", ep.port);

        void *data = msg->msg_iov[0].iov_base;
        *nsent = msg->msg_iov[0].iov_len;

        inet_addr_t local;
        get_link_addr(udp_socket->iplink, &local);
        return udp_assoc_send_msg(udp_socket->udp_assoc, &local, &ep, data,
            *nsent);
}

/** Receive UDP message callback.
 * 
 * @param assoc - association, the message was received from
 * @param rmsg - UDP received message
 */
static void udp_socket_ev_recv(udp_assoc_t *assoc, udp_rmsg_t *rmsg) 
{   
        udp_socket_t *udp_socket = (udp_socket_t*)assoc->cb_arg;
    
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "udp_socket_ev_recv()");      
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", 
                udp_socket->socket.id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket link: %d", 
                udp_socket->iplink);

        udp_msg_t* udp_msg = malloc(sizeof(udp_msg_t));
        if (udp_msg == NULL)
                return;

        link_initialize(&udp_msg->msg_queue_link);
        udp_msg->data_size = udp_rmsg_size(rmsg);
        udp_msg->data = malloc(udp_msg->data_size);
        if (udp_msg->data == NULL) {
                free(udp_msg);
                return;
        }
        udp_rmsg_read(rmsg, 0, udp_msg->data, udp_msg->data_size);
        udp_rmsg_remote_ep(rmsg, &udp_msg->remote_ep);
        
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message size: %d",
            udp_msg->data_size);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message source address: %x",
            udp_msg->remote_ep.addr.addr);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * message source port: %d",
            udp_msg->remote_ep.port);
        
        list_append(&udp_msg->msg_queue_link, &udp_socket->msg_queue); 
}

/** Receive UDP error callback.
 * 
 * @param assoc - association, the error was received from
 * @param rerr - UDP received error
 */
static void udp_socket_ev_recv_err(udp_assoc_t *assoc, udp_rerr_t *rerr) 
{
}

/** UDP link state callback.
 * 
 * @param assoc - association, the link state was changed for
 * @param rerr - new link state
 */
static void udp_socket_ev_link_state(udp_assoc_t *assoc,
    udp_link_state_t lstate) 
{
}

/** Receives message from UDP socket.
 * 
 * @param socket - socket to receive message from
 * @param msg - structure where will be stored message data and additional info
 * @param flags - UNUSED
 * @param rsize - number of received bytes
 * @return - EOK on success, error code on failure
 */
errno_t udp_socket_recvmsg(common_socket_t *socket, struct msghdr *msg,
    int flags, size_t *rsize) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - udp_socket_recvmsg()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket link: %d", 
                ((udp_socket_t*)socket)->iplink);

        udp_socket_t *udp_socket = (udp_socket_t*)socket;
        
        if (msg->msg_namelen < sizeof(struct sockaddr_in))
                return EINVAL;   
        if (msg->msg_iovlen < 1)
                return EINVAL;

        udp_msg_t *udp_msg = (udp_msg_t*)list_first(&udp_socket->msg_queue);
        if (udp_msg == NULL) {
                log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * empty socket message"
                    " queue");
                return EWOULDBLOCK;
        }

        size_t data_size = min(msg->msg_iov[0].iov_len, udp_msg->data_size);
        memcpy(msg->msg_iov[0].iov_base, udp_msg->data, data_size);

        struct sockaddr_in *sa = (struct sockaddr_in*)msg->msg_name;
        sa->sin_addr.s_addr = htonl(udp_msg->remote_ep.addr.addr);
        sa->sin_port = htons(udp_msg->remote_ep.port);
        sa->sin_family = AF_INET;

        list_remove(&udp_msg->msg_queue_link);
        if (udp_msg->data != NULL)
                free(udp_msg->data);
        free(udp_msg);

        *rsize = data_size;
        
        return EOK;
}

/** Closes UDP socket.
 * 
 * @param socket - socket to close
 * @return - EOK on success, error code on failure
 */
errno_t udp_socket_close(common_socket_t* socket) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " - udp_socket_close()");
        log_msg(LOG_DEFAULT, LVL_DEBUG2, "  * socket id: %d", socket->id);
    
        udp_socket_t *udp_socket = (udp_socket_t*)socket;
        list_remove(&udp_socket->socket.link);
        free_socket_id(udp_socket->socket.id);

        while (!list_empty(&udp_socket->msg_queue)) {
                udp_msg_t *udp_msg =  (udp_msg_t*)list_first(
                        &udp_socket->msg_queue);
                list_remove(&udp_msg->msg_queue_link);
                if (udp_msg->data != NULL)
                        free(udp_msg->data);
                free(udp_msg);
        }

        free(udp_socket);
        
        return EOK;
}

/** @}
 */