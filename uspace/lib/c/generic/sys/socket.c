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
        if ((int)retval < 0) { \
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
 * @return EOK on success, EIO if the session was not created.
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
 * @param domain - socket domain
 * @param type - socket type
 * @param protocol -socket protocol
 * @return - socket file descriptor on success, SOCK_ERR on failure.
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
        // All parameters (domain, type, protocol) sent as sysarg_t
        aid_t req = async_send_3(exch, SOCKET_CREATE, domain, type, protocol,
            &answer);
        async_exchange_end(exch);

        int retval;
        async_wait_for(req, &retval);
        CHECK_RETVAL();

        return retval;
}

/** Sets option on socket.
 * 
 * Option is set on socket structure on service side looked up by given socket
 * file descriptor. If the function fails, error code is stored in errno.
 * 
 * @param sockfd - sockets file descriptor
 * @param level - level at which the option reside
 * @param optname - name of the option
 * @param optval - value of option to set
 * @param optlen - length of optval
 * @return - EOK on success, SOCK_ERR on failure
 */
int setsockopt(int sockfd, int level, int optname, const void *optval,
        socklen_t optlen) 
{   
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd, level, optname)
        aid_t req = async_send_3(exch, SOCKET_SETSOCKOPT, sockfd, level,
            optname, &answer);

        // Send option value
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
 * @param sockfd - sockets file descriptor
 * @param addr - address to which the socket will be bound
 * @param addrlen - length of addr
 * @return - EOK on success, SOCK_ERR on failure
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd)
        aid_t req = async_send_1(exch, SOCKET_BIND, sockfd, &answer);

        // Send socket address
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
 * How the message will be send is decided according to socket structe given by 
 * @a sockfd. The structure is looked up on service side. If the function 
 * fails, error code is stored in errno.
 * 
 * @param sockfd - sockets file descriptor
 * @param msg - pointer to message that will be sent
 * @param flags - flags to further configure sending - currently not unsupported
 * @return - numbet of sent bytes on success, SOCK_ERR on failure
 */
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{  
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd, msg->msg_iovlen 
        // - number of input/output vectors the message contains, flags)
        aid_t req = async_send_3(exch, SOCKET_SENDMSG, sockfd, msg->msg_iovlen,
            flags, &answer);

        // Send destination address
        int rc = async_data_write_start(exch, msg->msg_name, msg->msg_namelen);
        CHECK_RC();

        // Send input/output vectors contents
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
                rc = async_data_write_start(exch, msg->msg_iov[i].iov_base, 
                    msg->msg_iov[i].iov_len);
                CHECK_RC();
        }

        rc = async_data_write_start(exch, msg->msg_control,
            msg->msg_controllen);
        CHECK_RC();

        async_exchange_end(exch);

        int retval;
        async_wait_for(req, &retval);
        CHECK_RETVAL();

        return retval;
}

/** Receives message from a socket.
 * 
 * Message that will be received is determined by socket structure looked up by
 * @a sockfd. The structure is looked up on service side. If the function 
 * fails, error code is stored in errno.
 * 
 * @param sockfd - sockets file descriptor
 * @param msg - pointer, where the received message will be stored
 * @param flags - flags to further configure receiving - currently not supported
 * @return - number recived bytes on sucess, SOCK_ERR on failure
 */
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) 
{    
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd,
        // msg->msg_namelen - size of structure where will be stored source 
        // address of the message, msg->msg_iovlen - number of input/output 
        // vectors the message contains, msg->msg_controllen - size of 
        // structure where will be store additional info, flags)
        aid_t req = async_send_5(exch, SOCKET_RECVMSG, sockfd, msg->msg_namelen,
            msg->msg_iovlen, msg->msg_controllen, flags, &answer);

        int rc;
        // Send respective size of each input/output vector where the received
        // data should be stored
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
                rc = async_data_write_start(exch, &msg->msg_iov[i].iov_len,
                    sizeof(size_t));
                CHECK_RC();
        }

        // Receive source address of the message
        rc = async_data_read_start(exch, msg->msg_name, msg->msg_namelen);
        CHECK_RC();

        // Receive data into intup/output vectors
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
                rc = async_data_read_start(exch, msg->msg_iov[i].iov_base,
                    msg->msg_iov[i].iov_len);
                CHECK_RC();
        }

        // Receive control message
        rc = async_data_read_start(exch, msg->msg_control, msg->msg_controllen);
        CHECK_RC();

        async_exchange_end(exch);

        int retval;
        async_wait_for(req, &retval);
        CHECK_RETVAL();

        size_t rsize = IPC_GET_ARG1(answer);
        return rsize;
}

/** NOT IMPLEMENTED
 * 
 * @param sockfd
 * @param backlog
 * @return
 */
int listen(int sockfd, int backlog) {
	return 0;
}

/** NOT IMPLEMENTED
 * 
 * @param sockfd
 * @param buf
 * @param len
 * @param flags
 * @param dest_addr
 * @param addrlen
 * @return
 */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen) 
{ 
        return 0;
}

/** Connects socket.
 * 
 * Current service implementation only returns -1 for AF_UNIX sockets (Behavior
 * required for BIRD port). If the function fails, error code is stored in 
 * errno.
 * 
 * @param sockfd - sockets file descriptor
 * @param addr - address to which socket should be connected
 * @param addrlen - length of addr
 * @return - - EOK on success, SOCK_ERR on failure
 */
int connect(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen) 
{
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd)
        aid_t req = async_send_1(exch, SOCKET_CONNECT, sockfd, &answer);

        // Send socket address
        int rc = async_data_write_start(exch, addr, addrlen);
        CHECK_RC();

        async_exchange_end(exch);

        int retval;
        async_wait_for(req, &retval);
        CHECK_RETVAL();   

        return retval;
}

/** NOT IMPLEMENTED.
 * 
 * @param sockfd
 * @param addr
 * @param addrlen
 * @return
 */
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	return 0;
}

/** NOT IMPLEMENTED.
 * 
 * @param sockfd
 * @param addr
 * @param addrlen
 * @return
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	return 0;
}

/** Closes socket.
 * 
 * Socket to close is looked up by sockfd on service side. If the function 
 * fails, error code is stored in errno.
 * 
 * @param sockfd - socket file descriptor
 * @return - EOK on success, SOCK_ERR on failure
 */
int sockclose(int sockfd) 
{   
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd)
        aid_t req = async_send_1(exch, SOCKET_CLOSE, sockfd, &answer);

        async_exchange_end(exch);
        int retval;
        async_wait_for(req, &retval);

        return retval;   
}

/** Checks, if data can be received on socket
 * 
 * @param sockfd - socket file descriptor
 * @return 1 if there are data to recevie, 0 otherwise
 */
int sockfdisset(int sockfd) 
{    
        async_exch_t *exch = async_exchange_begin(sess);

        ipc_call_t answer;
        // Send parameters that can be sent as sysarg_t (sockfd)
        aid_t req = async_send_1(exch, SOCKET_FDISSET, sockfd, &answer);

        async_exchange_end(exch);
        int retval;
        async_wait_for(req, &retval);

        return retval;   
}

/** @}
 */