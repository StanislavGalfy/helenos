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
/** @file Synchronous I/O multiplexing.
 */

/*
 * Not implemented, except for FD_ISSET. Defined in order to make compilation of
 * BIRD from coastline possible. 
 */

#ifndef SELECT_POSIX_H_
#define SELECT_POSIX_H_

#include <libc/sys/socket.h>
#include <libc/types/socket/select.h>

#define FD_CLR(fd, fd_set) _fd_clr(fd, fd_set) 

#define FD_ISSET(fd, fd_set) _fd_isset(fd, fd_set)

#define FD_SET(fd, fd_set) _fd_set(fd, fd_set)

#define FD_ZERO(fd_set) _fd_zero(fd_set)

extern void _fd_clr(int fd, fd_set *fd_set);

extern bool _fd_isset(int fd, fd_set *fd_set);

extern void _fd_set(int fd, fd_set *fd_set);

extern void _fd_zero(fd_set *fd_set);

extern int select(int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout);

#endif

/** @}
 */