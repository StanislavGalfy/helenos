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
/** @file  Internet Protocol family.
 */

#ifndef POSIX_SOCKET_H_
#define POSIX_SOCKET_H_

#include "libc/types/socket/socket.h"

#ifndef __POSIX_DEF__
#define __POSIX_DEF__(x) x
#endif

extern int __POSIX_DEF__(bind)(int, const struct sockaddr *, socklen_t);
extern int __POSIX_DEF__(socket)(int, int, int);
extern ssize_t __POSIX_DEF__(recvmsg)(int, struct msghdr *, int);
extern ssize_t __POSIX_DEF__(sendto)(int, const void *, size_t, int,
        const struct sockaddr *, socklen_t);
extern int __POSIX_DEF__(connect)(int, const struct sockaddr *, socklen_t);
extern ssize_t __POSIX_DEF__(sendmsg)(int, const struct msghdr *, int);
extern int __POSIX_DEF__(listen)(int, int);
extern int __POSIX_DEF__(setsockopt)(int, int, int, const void *, socklen_t);
extern int __POSIX_DEF__(getsockname)(int, struct sockaddr *, socklen_t *);
extern int __POSIX_DEF__(accept)(int, struct sockaddr *, socklen_t *);
extern int __POSIX_DEF__(sockclose)(int);

#endif

/** @}
 */