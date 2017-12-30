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

#define LIBPOSIX_INTERNAL
#define __POSIX_DEF__(x) posix_##x

#include "../internal/common.h"
#include "posix/errno.h"
#include "posix/inet/inetcfg.h"

#include "libc/inet/inetcfg.h"

/** Calls inetcfg_init from libc.
 * 
 * @return - negated error code from libc call
 */
int posix_inetcfg_init(void)
{
    return negerrno(inetcfg_init);
}

/** Calls inetcfg_addr_get from libc.
 * 
 * @param addr_id - id of address to get
 * @param ainfo - pointer where the address information will be stored
 * @param inet_addr_status - status that the address must have - active or 
 *      deleted
 * @return - negated error code from libc call
 */
int posix_inetcfg_addr_get(sysarg_t addr_id, inet_addr_info_t *ainfo,
    inet_addr_status_t inet_addr_status)
{
    return negerrno(inetcfg_addr_get, addr_id, ainfo, inet_addr_status);
}

/** Calls inetcfg_get_addr_list from libc
 * 
 * @param addrs - pointer, where will be stored the list of addresses
 * @param count - pointer, where will be stored the count of addresses
 * @param inet_addr_status - status that the addresses must have - active or 
 *      deleted
 * @return - negated error code from libc call
 */
int posix_inetcfg_get_addr_list(sysarg_t **addrs, size_t *count,
    inet_addr_status_t inet_addr_status)
{
    return negerrno(inetcfg_get_addr_list, addrs, count, inet_addr_status);
}

/** Calls inetcfg_get_link_list from libc
 * 
 * @param links - pointer, where will be stored the list of links
 * @param count - pointer, where will be stored the count of links
 * @return - negated error code from libc call
 */
int posix_inetcfg_get_link_list(sysarg_t **links, size_t *count)
{
    return negerrno(inetcfg_get_link_list, links, count);
}

/** Calls inetcfg_get_sroute_list from libc.
 * 
 * @param sroutes - pointer, where will be stored the list of static routes
 * @param count - pointer, where will be stored the count of static routes
 * @param inet_sroute_status - status that the static routes must have - active
 *      or deleted
 * @return - negated error code from libc call
 */
int posix_inetcfg_get_sroute_list(sysarg_t **sroutes, size_t *count,
        inet_sroute_status_t inet_sroute_status)
{
    return negerrno(inetcfg_get_sroute_list, sroutes, count,
            inet_sroute_status);
}

/** Calls inetcfg_link_get from libc.
 * 
 * @param link_id - id of link get
 * @param linfo - pointer where will be stored the info about link
 * @return - negated error code from libc call
 */
int posix_inetcfg_link_get(sysarg_t link_id, inet_link_info_t *linfo)
{
    return negerrno(inetcfg_link_get, link_id, linfo);
}

/** Calls inetcfg_sroute_create from libc.
 * 
 * @param name - name of new static route
 * @param dest - destination network of the route
 * @param router - address of the router
 * @param rtm_protocol - origin of the route
 * @param sroute_id - pointer, where will be stored generated route id
 * @return - negated error code from libc call
 */
int posix_inetcfg_sroute_create(const char *name, inet_naddr_t *dest,
    inet_addr_t *router, sysarg_t rtm_protocol, sysarg_t *sroute_id)
{
    return negerrno(inetcfg_sroute_create, name, dest, router, rtm_protocol,
            sroute_id);
}

/** Calls inetcfg_sroute_delete from libc.
 * 
 * @param sroute_id - id of static route to delete
 * @return - negated error code from libc call
 */
int posix_inetcfg_sroute_delete(sysarg_t sroute_id)
{
    return negerrno(inetcfg_sroute_delete, sroute_id);
}

/** Calls inetcfg_sroute_get from libc.
 * 
 * @param sroute_id - id of static route to get
 * @param srinfo - pointer, where will be stored info about static route
 * @param inet_sroute_status - status, that the static route must have- active
 *      or deleted
 * @return - negated error code from libc call
 */
int posix_inetcfg_sroute_get(sysarg_t sroute_id, inet_sroute_info_t *srinfo,
    inet_sroute_status_t inet_sroute_status)
{
    return negerrno(inetcfg_sroute_get, sroute_id, srinfo, inet_sroute_status);
}

/** @}
 */
