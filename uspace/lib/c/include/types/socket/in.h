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

#ifndef LIBC_TYPES_IN_H_
#define LIBC_TYPES_IN_H_

#include <stdint.h>
#include <types/socket/socket.h>
#include <types/socket/in6.h>

/** Socket option names */
#define IP_TOS 1           // Type of service
#define IP_TTL 2           // Time to live
#define IP_PKTINFO 8       // Include packet info
#define IP_MULTICAST_IF 32 // Multicast

/** Enumeration of socket protocols, passed as last parameter when creating
 * socket 
 */
enum {
    IPPROTO_TCP = 6,  /* Transmission Control Protocol  */
#define IPPROTO_TCP IPPROTO_TCP
    IPPROTO_UDP = 17, /* User Datagram Protocol socket type */  
#define IPPROTO_UDP IPPROTO_UDP
    IPPROTO_MAX
};

/** Integer value of IPv4 network address */
typedef uint32_t in_addr_t;

/** Structure containing integer value of IPv4 network address */
struct in_addr {
	in_addr_t s_addr;
};

/** Structure describing packet info. */
struct in_pktinfo {
        /** Service id of iplink where the packet was received, or should be
         sent */
	int ipi_ifindex;
        /** Local address of the packet */
	struct in_addr ipi_spec_dst;
        /** Destination address of the packet, from the packet header */
	struct in_addr ipi_addr;
};

/** Socket address. By convention, functions taking this structure as parameter 
 * instead of sockaddr may modify the values.
 */
struct sockaddr_in {
        /** Address family, e.g. AF_INET */
	sa_family_t sin_family;
        /** Port */
	in_port_t sin_port;
        /** IPV4 address */
	struct in_addr sin_addr;
        /** Unused space to make the size same as size of sockaddr */
	unsigned char sin_zero[sizeof (struct sockaddr) -
	(sizeof (unsigned short int)) -
	sizeof (in_port_t) -
	sizeof (struct in_addr)];
};

#endif

/** @}
 */