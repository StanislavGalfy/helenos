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

#ifndef LIBC_TYPES_SOCKET_H_
#define LIBC_TYPES_SOCKET_H_

#include <types/socket/uio.h>
#include <stdint.h>

/** Socket error, returned by library functions working with sockets in case of
 failure. The specific error code is stored in errno */
#define SOCK_ERR (-1)

/** Socket option layers */
#define SOL_IP 0     /* IP layer */
#define SOL_SOCKET 1 /* Socket layer */
#define SOL_IPV6 41  /* IPv6 layer */

/** Socket option names for setsockopt */
#define SO_REUSEADDR 2     /* Reuse address */
#define SO_BROADCAST 6     /* Set up broadcast */
#define SO_PRIORITY 12     /* Priority */
#define SO_BINDTODEVICE 25 /* Bind socket to receive and send data only through
                              particular interface */

/** Socket domains, used when creating socket */
#define AF_UNSPEC 0 /* Unspecified */
#define AF_UNIX 1   /* Internal OS socket */
#define AF_INET 2   /* IPv4 network socket */
#define AF_INET6 10 /* IPv6 netwoek socket, unused */

/** Socket types, used when creating socket */
#define SOCK_STREAM 1 /* Stream socket */
#define SOCK_DGRAM 2  /* Datagram socket */
#define SOCK_RAW 3    /* Raw socket */

enum {
        MSG_TRUNC = 0x20, /* Truncated message, unused */
#define MSG_TRUNC MSG_TRUNC
};

/** Socket address family type */
typedef unsigned short int sa_family_t;
/** Port number type */
typedef uint16_t in_port_t;
/** Type for length of structures passed to socket functions */
typedef unsigned int socklen_t;

/** Socket address */
struct sockaddr {
        /** Address family, e.g. AF_INET */
        sa_family_t sa_family;
        /** Space for attributes particular to address family */
        char sa_data[14];
};

/** Socket address storage, unused */
struct sockaddr_storage {
        sa_family_t ss_family;
        unsigned long int __ss_align;
        char __ss_padding[(128 - (2 * sizeof (unsigned long int)))];
};

/** Control message header*/
struct cmsghdr {
        unsigned long cmsg_len; /* __cmsg_data byte count*/
        int cmsg_level; /* socket layer of control message */
        int cmsg_type; /* control message type */
        unsigned char __cmsg_data[]; /* control message data particular to
                                      control message type */
};

/** Message header containing all the structures necessary to send or receive
 message through socket */
struct msghdr {
        /** Address, where the message will be sent or from where was received */
        void *msg_name;
        /** Address(msg_name) length in bytes */
        socklen_t msg_namelen;

        /** Scatter/gather array of memory vectors, with data to send or where
         data will e received. Currently only first vector of array is used. */
        struct iovec *msg_iov;
        /** Number of memory vector is scatter/gather array */
        size_t msg_iovlen;

        /** Array of control messages to pass/receive additional information
         * when sending/receiving */
        void *msg_control;
        /** Number of control messages in array */
        size_t msg_controllen;

        /** Message flags, not used */
        int msg_flags;
};

/** Returns first control message from message header */
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0)

/** Gets next control message from message header, not implemented */
#define CMSG_NXTHDR(msgh, cmsghdr) NULL

/** Aligns given length to higher multiple of size of size_t */
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
                         & (size_t) ~(sizeof (size_t) - 1))

/** Number of bytes control message with given length of data occupies */
#define CMSG_SPACE(len) (CMSG_ALIGN (len) \
                         + CMSG_ALIGN (sizeof (struct cmsghdr)))

/** Returns the length to store in control message cmsg_len for data with
 * given length */
#define CMSG_LEN(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))

/** Returns control message data */
#define CMSG_DATA(cmsg) ((cmsg)->__cmsg_data)

#endif

/** @}
 */
