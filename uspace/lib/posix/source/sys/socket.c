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

/** @addtogroup libposix
 * @{
 */
/** @file
 */

#define __POSIX_DEF__(x) posix_##x

#include "libc/inet/inetcfg.h"
#include "libc/inet/addr.h"
#include "libc/sys/socket.h"
#include "libc/errno.h"
#include "posix/unistd.h"
#include "posix/sys/socket.h"

/** Calls socket from libc. 
 * 
 * @param domain - socket domain
 * @param type - socket type
 * @param protocol -socket protocol
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
int posix_socket(int domain, int type, int protocol)
{
        return socket(domain, type, protocol);
}

/** Calls setsockopt from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @param level - level at which the option reside
 * @param optname - name of the option
 * @param optval - value of option to set
 * @param optlen - length of optval
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
int posix_setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen) 
{
        return setsockopt(sockfd, level, optname, optval, optlen);
}

/** Calls bind from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @param addr - address to which the socket will be bound
 * @param addrlen - length of addr
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
int posix_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
        return bind (sockfd, addr, addrlen);
}

/** Calls sendmsg from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @param msg - pointer to message that will be sent
 * @param flags - flags to further configure sending - currently not unsupported
 * @return - NOT negated return value from libc call, in case of failure it is
 *   already -1 and error code is stored in errno
 */
ssize_t posix_sendmsg(int sockfd, const struct msghdr *msg, int flags) 
{
        return sendmsg(sockfd, msg, flags);
}

/** Calls recvmsg from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @param msg - pointer, where the received message will be stored
 * @param flags - flags to further configure receiving - currently not supported
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
ssize_t posix_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
        return recvmsg(sockfd, msg, flags);
}

/** NOT SUPPORTED.
 * 
 * @param sockfd
 * @param backlog
 * @return
 */
int posix_listen(int sockfd, int backlog) 
{
        return listen(sockfd, backlog);
}

/** NOT SUPPORTED.
 * 
 * @param sockfd
 * @param buf
 * @param len
 * @param flags
 * @param dest_addr
 * @param addrlen
 * @return
 */
ssize_t posix_sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen) 
{
        return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/** Calls connect from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @param addr - address to which socket should be connected
 * @param addrlen - length of addr
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
int posix_connect(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen) 
{
        return connect(sockfd, addr, addrlen);
}

/** NOT SUPPORTED
 * 
 * @param sockfd
 * @param addr
 * @param addrlen
 * @return
 */
int posix_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
        return getsockname(sockfd, addr, addrlen);
}

/** NOT SUPPORTED
 * 
 * @param sockfd
 * @param addr
 * @param addrlen
 * @return
 */
int posix_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
        return accept(sockfd, addr, addrlen);
}

/** Calls sockclose from libc.
 * 
 * @param sockfd - sockets file descriptor
 * @return - return value from libc call (it is not negated because in case of
 *  failure it is already -1 and error code is stored in errno)
 */
int posix_sockclose(int sockfd) 
{
        return sockclose(sockfd);
}

/** @}
 */