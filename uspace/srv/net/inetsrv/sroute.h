/*
 * Copyright (c) 2012 Jiri Svoboda
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

/** @addtogroup inet
 * @{
 */
/**
 * @file
 * @brief
 */

#ifndef INET_SROUTE_H_
#define INET_SROUTE_H_

#include <adt/trie.h>
#include <types/inetcfg.h>
#include <stddef.h>
#include <stdint.h>
#include "inetsrv.h"

typedef struct {
	size_t count;
	inet_sroute_cmd_t *cmds;
} inet_sroute_cmds_t;

extern trie_t *sroute_table;

extern errno_t inet_sroute_batch(void *arg);
extern errno_t inet_sroute_add(inet_sroute_t *);
extern inet_sroute_t *inet_sroute_find_longest_match(inet_addr_t *);
extern inet_sroute_t *inet_sroute_find_exact(inet_naddr_t *);
extern errno_t inet_sroute_to_array(inet_sroute_t **, size_t *);

#endif

/** @}
 */
