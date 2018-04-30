/*
 * Copyright (c) 2013 Jiri Svoboda
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

#ifndef LIBC_TYPES_INETCFG_H_
#define LIBC_TYPES_INETCFG_H_

#include <inet/addr.h>
#include <stddef.h>

#define RTPROT_UNSPEC	0  /* Route installed by unsepcified source */
#define RTPROT_KERNEL	2  /* Route installed by OS, not used */
#define RTPROT_STATIC	4  /* Route installed by administrator */
#define RTPROT_BIRD	12 /* Route installed by BIRD */

#define SROUTE_BLOCK_SIZE 1024

typedef enum {
        INET_ADDR_STATUS_ACTIVE = 0, /* Active network address assigned to ineterface */
        INET_ADDR_STATUS_DELETED /* Network address deleted from interface */
} inet_addr_status_t;

typedef enum {
        INET_SROUTE_STATUS_ACTIVE = 0, /* Active static route */
        INET_SROUTE_STATUS_DELETED /* Deleted static route */
} inet_sroute_status_t;

typedef enum {
        INET_SROUTE_CMD_CREATE = 0,
        INET_SROUTE_CMD_DELETE
} inet_sroute_cmd_type_t;

/** Address object info */
typedef struct {
	/** Network address */
	inet_naddr_t naddr;
	/** Link service ID */
	sysarg_t ilink;
	/** Address object name */
	char *name;
} inet_addr_info_t;

/** IP link info */
typedef struct {
	/** Link service name */
	char *name;
	/** Default MTU */
	size_t def_mtu;
	/** Link layer address */
	addr48_t mac_addr;

        sysarg_t nic_svcid;
} inet_link_info_t;

/** Static route info */
typedef struct {
        unsigned char padding[2 * sizeof(void *)];
	/** Destination network */
	inet_naddr_t dest;
	/** Router via which to route packets */
	inet_addr_t router;
        /** Origin */
        unsigned char rtm_protocol;
        /** Status - active/deleted*/
        inet_sroute_status_t status;
} inet_sroute_info_t;

typedef struct {
        inet_naddr_t dest;
        inet_addr_t router;
        sysarg_t rtm_protocol;
        inet_sroute_cmd_type_t sroute_cmd_type;
} inet_sroute_cmd_t;

#endif

/** @}
 */
