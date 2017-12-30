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
#include <macros.h>

#include "service.h"
#include "tools.h"
#include "common_socket.h"
#include "raw_socket.h"
#include "udp_socket.h"
#include "unix_socket.h"

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
int (*socket_create[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (int, int, int, int);

/** Array of socket bind functions */
int (*socket_bind[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *, 
    const struct sockaddr *, socklen_t);

/** Array of socket connect functions */
int (*socket_connect[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *, 
    const struct sockaddr *, socklen_t);

/** Array of socket setsockopt functions */
int (*socket_setsockopt[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    int, int, const void*, socklen_t);

/** Array of socket sendmsg functions */
ssize_t (*socket_sendmsg[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *, 
    const struct msghdr*, int);

/** Array of socket recvmsg functions */
int (*socket_recvmsg[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX]) (common_socket_t *,
    struct msghdr*, int, size_t *);

/** Array of socket close functions */
int (*socket_close[SOCK_DOMAIN_MAX][SOCK_TYPE_MAX])(common_socket_t *);

/** Deallocates all parts of msghdr structure.
 * 
 * @param msg - message to deallocate.
 */
static void free_msghdr(const struct msghdr *msg) {
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
 * @param iid - async request ID
 * @param icall - async request data
 * @param session_id - session ID
 */
static void socket_create_srv(ipc_callid_t iid, ipc_call_t *icall,
    int session_id) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");    
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_create_srv()");

        // Get parameters transfered as sysarg_t
        int domain = IPC_GET_ARG1(*icall);
        int type = IPC_GET_ARG2(*icall);
        int protocol = IPC_GET_ARG3(*icall);  

        if (socket_create[domain][type] == NULL) {
                async_answer_0(iid, ESOCKTNOSUPPORT);
                return;
        }

        fibril_mutex_lock(&socket_lock);
        int retval = socket_create[domain][type](domain, type, protocol,
            session_id);
        fibril_mutex_unlock(&socket_lock);

        async_answer_0(iid, retval);
}

/** Binds socket to socket address.
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_bind_srv(ipc_callid_t iid, ipc_call_t *icall) 
{   
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_bind_srv()");

        // Get parameters transfered as sysarg_t
        int sockfd = IPC_GET_ARG1(*icall);

        // Receive socket address
        ipc_callid_t callid;
        size_t addrlen;    
        int rv = async_data_write_receive(&callid, &addrlen);
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

        int rc = async_data_write_finalize(callid, addr, addrlen);
        if (rc != EOK) {
                async_answer_0(callid, rc);
                async_answer_0(iid, rc);
                free(addr);
                return;
        }

        // Find socket and call bind implementation based on domain and type
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
        int retval = socket_bind[socket->domain][socket->type](socket, addr,
            addrlen);
        fibril_mutex_unlock(&socket_lock);

        async_answer_0(iid, retval);
        free(addr);    
}

/** 
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_connect_srv(ipc_callid_t iid, ipc_call_t *icall) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_connect_srv()");

        // Get parameters transfered as sysarg_t
        int sockfd = IPC_GET_ARG1(*icall);

        ipc_callid_t callid;
        size_t addrlen;    
        int rv = async_data_write_receive(&callid, &addrlen);
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

        int rc = async_data_write_finalize(callid, addr, addrlen);
        if (rc != EOK) {
                async_answer_0(callid, rc);
                async_answer_0(iid, rc);
                free(addr);
                return;
        }

        // Find socket and call connect implementation based on domain and type
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
        int retval = socket_connect[socket->domain][socket->type](socket, addr,
            addrlen);
        fibril_mutex_unlock(&socket_lock);

        async_answer_0(iid, retval);
        free(addr);    
}

/**
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_setsockopt_srv(ipc_callid_t iid, ipc_call_t *icall) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_setsockopt_srv()");

        // Get parameters transfered as sysarg_t
        int sockfd = IPC_GET_ARG1(*icall);
        int level = IPC_GET_ARG2(*icall);
        int optname = IPC_GET_ARG3(*icall);

        // Receive option value
        ipc_callid_t callid;
        size_t optlen;
        int rv = async_data_write_receive(&callid, &optlen);
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

        int rc = async_data_write_finalize(callid, optval, optlen);
        if (rc != EOK) {
                async_answer_0(callid, rc);
                async_answer_0(iid, rc);
                return;
        }

        // Find socket and call setsockopt implementation based on domain and type
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
        int retval = socket_setsockopt[socket->domain][socket->type](socket, 
            level, optname, optval, optlen);
        fibril_mutex_unlock(&socket_lock);
        async_answer_0(iid, retval);
        free(optval);
}

/** Sends message through socket.
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_sendmsg_srv(ipc_callid_t iid, ipc_call_t *icall) 
{   
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_sendmsg_srv()");

        // Get parameters transfered as sysarg_t
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

        // Receive destination address
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

        int rc = async_data_write_finalize(callid, msg->msg_name,
            msg->msg_namelen);
        CHECK_RC();

        // Receive all input/output vectors
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

        // Receive control data
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

        // Find socket and call sendmsg implementation based on domain and type
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
        int retval = socket_sendmsg[socket->domain][socket->type](socket, msg,
            flags);

        fibril_mutex_unlock(&socket_lock);   
        async_answer_0(iid, retval);
        free_msghdr(msg);
}

/** Receives message from socket.
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_recvmsg_srv(ipc_callid_t iid, ipc_call_t *icall) 
{
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");    
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_recvmsg_srv()");

        // Get parameters transfered as sysarg_t
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
        int rc;
        bool rv;

        // Receive sizes and allocate input/output vectors where will be stored 
        // received data
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

        // Find socket and call recvmsg implementation based on domain and type  
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
        int retval = socket_recvmsg[socket->domain][socket->type](socket, msg,
            flags, &rsize);        
        fibril_mutex_unlock(&socket_lock);

        // Send source address
        rv = async_data_read_receive(&callid, &size);
        CHECK_RV();
        rc = async_data_read_finalize(callid, msg->msg_name, msg->msg_namelen);
        CHECK_RC();

        // Send contents of input/output vectors
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
                rv = async_data_read_receive(&callid, &size);
                CHECK_RV();

                rc = async_data_read_finalize(callid, msg->msg_iov[i].iov_base,
                    min(msg->msg_iov[i].iov_len, size));
                CHECK_RC();
        }

        // Send control data
        rv = async_data_read_receive(&callid, &size);
        CHECK_RV();
        rc = async_data_read_finalize(callid, msg->msg_control,
            msg->msg_controllen);
        CHECK_RC();

        async_answer_1(iid, retval, rsize);
        free_msghdr(msg);
}

/** Checks if message can be received on a socket.
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_sockfdisset_srv(ipc_callid_t iid, ipc_call_t *icall) 
{    
        // Get parameters transfered as sysarg_t
        int sockfd = IPC_GET_ARG1(*icall);

        int retval = 0;
        fibril_mutex_lock(&socket_lock);    
        common_socket_t *socket = get_socket_by_id(sockfd);
        if (socket == NULL) {
                async_answer_0(iid, retval);
                fibril_mutex_unlock(&socket_lock);
                return;
        }
        retval = !list_empty(&socket->msg_queue);
        fibril_mutex_unlock(&socket_lock);
        async_answer_0(iid, retval);
}

/** Closes socket
 * 
 * @param iid - async request ID
 * @param icall - async request data
 */
static void socket_close_srv(ipc_callid_t iid, ipc_call_t *icall) 
{    
        log_msg(LOG_DEFAULT, LVL_DEBUG2, " ");
        log_msg(LOG_DEFAULT, LVL_DEBUG, "socket_close_srv()");

        // Get parameters transfered as sysarg_t
        int sockfd = IPC_GET_ARG1(*icall);

        // Find socket and call close implementation based on domain and type  
        fibril_mutex_lock(&socket_lock);    
        common_socket_t *socket = get_socket_by_id(sockfd);
                if (socket == NULL) {
                async_answer_0(iid, EBADF);
                fibril_mutex_unlock(&socket_lock);
                return;
        }
        if (socket_close[socket->domain][socket->type] == NULL) {
                async_answer_0(iid, EOPNOTSUPP);
                fibril_mutex_unlock(&socket_lock);
                return;
        }
        int retval = socket_close[socket->domain][socket->type](socket);
        fibril_mutex_unlock(&socket_lock);

        async_answer_0(iid, retval);
}

/** Handle Socket client connection.
 *
 * @param iid - connect call ID
 * @param icall - connect call data
 * @param arg - connection argument
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
                case SOCKET_CONNECT:
                        socket_connect_srv(callid, &call);
                        break;
                case SOCKET_SETSOCKOPT:
                        socket_setsockopt_srv(callid, &call);
                        break;
                case SOCKET_SENDMSG:
                        socket_sendmsg_srv(callid, &call);
                        break;
                case SOCKET_RECVMSG:
                        socket_recvmsg_srv(callid, &call);
                        break;
                case SOCKET_FDISSET:
                        socket_sockfdisset_srv(callid, &call);
                        break;
                case SOCKET_CLOSE:
                        socket_close_srv(callid, &call);
                        break;
                }
        }
}

/** Initialize socket service
 * 
 * @return EOK on success, error code on failure
 */
int socket_service_init(void)
{
        int rc;
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
        socket_recvmsg[AF_INET][SOCK_RAW] = raw_socket_recvmsg;
        socket_sendmsg[AF_INET][SOCK_RAW] = raw_socket_sendmsg;
        socket_close[AF_INET][SOCK_RAW] = raw_socket_close;

        socket_create[AF_INET][SOCK_DGRAM] = udp_socket;
        socket_setsockopt[AF_INET][SOCK_DGRAM] = udp_socket_setsockopt;
        socket_bind[AF_INET][SOCK_DGRAM] = udp_socket_bind;
        socket_recvmsg[AF_INET][SOCK_DGRAM] = udp_socket_recvmsg;
        socket_sendmsg[AF_INET][SOCK_DGRAM] = udp_socket_sendmsg;
        socket_close[AF_INET][SOCK_DGRAM] = udp_socket_close;

        socket_create[AF_UNIX][SOCK_STREAM] = unix_socket;
        socket_bind[AF_UNIX][SOCK_STREAM] = unix_socket_bind;
        socket_connect[AF_UNIX][SOCK_STREAM] = unix_socket_connect;
        socket_close[AF_UNIX][SOCK_STREAM] = unix_socket_close;

        return EOK;
}

/** @}
 */