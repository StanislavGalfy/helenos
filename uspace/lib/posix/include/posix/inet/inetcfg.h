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


#ifndef POSIX_INETCFG_H_
#define POSIX_INETCFG_H

#include "libc/types/inetcfg.h"

extern int inetcfg_init(void);
extern int inetcfg_addr_create_static(const char *,
        inet_naddr_t *, sysarg_t, sysarg_t *);
extern int inetcfg_addr_get(sysarg_t, inet_addr_info_t *,
        inet_addr_status_t);
extern int inetcfg_get_addr_list(sysarg_t **, size_t *,
        inet_addr_status_t);
extern int inetcfg_get_link_list(sysarg_t **, size_t *);
extern int inetcfg_get_sroute_list(sysarg_t **, size_t *,
        inet_sroute_status_t);
extern int inetcfg_link_get(sysarg_t, inet_link_info_t *);
extern int inetcfg_sroute_create(inet_naddr_t *, inet_addr_t *, sysarg_t);
extern int inetcfg_sroute_delete(inet_naddr_t *, inet_addr_t *);
extern int inetcfg_sroute_to_array(inet_sroute_info_t *, size_t *);

#endif

/** @}
 */

