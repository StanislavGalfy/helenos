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

#include <bitops.h>
#include <errno.h>
#include <fibril_synch.h>
#include <io/log.h>
#include <ipc/loc.h>
#include <stdlib.h>
#include <str.h>
#include <byteorder.h>
#include <adt/list.h>
#include "sroute.h"
#include "inetsrv.h"
#include "inet_link.h"
#include "types/inetcfg.h"

static FIBRIL_MUTEX_INITIALIZE(sroute_list_lock);
static LIST_INITIALIZE(sroute_list);
static LIST_INITIALIZE(del_sroute_list);

trie_t *ipv4_sroute_table;
trie_t *ipv6_sroute_table;

inet_sroute_t *sroute_array;
size_t sroute_array_size;
size_t sroute_array_count = 0;

static int inet_sroute_compare(inet_sroute_t *a, inet_sroute_t *b)
{
	if (inet_naddrs_compare(&a->dest, &b->dest) == 0) {
		return 0;
	}
	return inet_addr_compare(&a->router, &b->router);
}

static void inet_sroute_copy(inet_sroute_t *dest, inet_sroute_t *source)
{
	dest->rtm_protocol = source->rtm_protocol;
	dest->router = source->router;
	dest->dest = source->dest;
	dest->status = source->status;
}

static errno_t inet_check_sroute_array() {
	if (sroute_array_count < sroute_array_size) {
		return EOK;
	}

	inet_sroute_t * tmp_sroute_array = malloc(
	    sizeof(inet_sroute_t) * sroute_array_size * 2);
	if (tmp_sroute_array == NULL) {
		return ENOMEM;
	}
	memcpy(tmp_sroute_array, sroute_array,
	    sroute_array_size * sizeof(inet_sroute_t));
	sroute_array_size *= 2;
	free(sroute_array);
	sroute_array = tmp_sroute_array;
	return EOK;
}

errno_t inet_sroute_batch(void *arg)
{
	/*
	fibril_mutex_lock(&sroute_list_lock);
	inet_sroute_cmds_t *inet_sroute_cmds = (inet_sroute_cmds_t*) arg;
	log_msg(LOG_DEFAULT, LVL_FATAL, "Processing %d routes ...",
	    inet_sroute_cmds->count);
	inet_sroute_t *sroute = NULL;
	for (size_t i = 0; i < inet_sroute_cmds->count; i++) {
		inet_sroute_cmd_t cmd = inet_sroute_cmds->cmds[i];
		switch (cmd.sroute_cmd_type) {
		case INET_SROUTE_CMD_CREATE:
			sroute = calloc(1, sizeof(inet_sroute_t));
			if (sroute == NULL) {
				return ENOMEM;
			}
			link_initialize(&sroute->sroute_list);
			sroute->id = ++sroute_id;
			list_append(&sroute->sroute_list, &sroute_list);
			break;
		case INET_SROUTE_CMD_DELETE:
			sroute = inet_sroute_find_exact(&cmd.dest, &cmd.router,
			    cmd.rtm_protocol, INET_ADDR_STATUS_ACTIVE);

			if (sroute != NULL) {
				list_remove(&sroute->sroute_list);
				if (sroute->name != NULL)
					free(sroute->name);
				free(sroute);
			}
			break;
		}
	}
	log_msg(LOG_DEFAULT, LVL_FATAL, "... done");
	fibril_mutex_unlock(&sroute_list_lock);
	*/
	return EOK;
}

errno_t inet_sroute_add(inet_sroute_t *sroute)
{
	errno_t rc;

	fibril_mutex_lock(&sroute_list_lock);

	rc = inet_check_sroute_array();
	if (rc != EOK) {
		fibril_mutex_unlock(&sroute_list_lock);
		return rc;
	}

	uint8_t dest[16];
	trie_t *sroute_table = NULL;
	uint8_t prefix = sroute->dest.prefix;
	if (sroute->dest.version == ip_v4) {
		sroute_table = ipv4_sroute_table;
		addr32_t dest_addr = htonl(sroute->dest.addr);
		memcpy(dest, &dest_addr, sizeof(addr32_t));
	} if (sroute->dest.version == ip_v6) {
		sroute_table = ipv6_sroute_table;
		memcpy(dest, &sroute->dest.addr6, sizeof(addr128_t));
	}

	inet_sroute_t *new_sroute = &sroute_array[sroute_array_count];
	inet_sroute_copy(new_sroute, sroute);
	link_initialize(&new_sroute->list_link);

	list_t *list = (list_t *) trie_find_exact(sroute_table, dest, prefix);
	if (list != NULL) {
		list_foreach(*list, list_link, inet_sroute_t, old_sroute) {
			if (inet_sroute_compare(old_sroute, sroute) != 0) {
				if (old_sroute->status == INET_SROUTE_STATUS_DELETED) {
					inet_sroute_copy(old_sroute, sroute);
					fibril_mutex_unlock(&sroute_list_lock);
					return EOK;
				}
				fibril_mutex_unlock(&sroute_list_lock);
				return EEXIST;
			}
		}
		list_prepend(&new_sroute->list_link, list);
		sroute_array_count++;
		fibril_mutex_unlock(&sroute_list_lock);
		return EOK;
	}
	list = malloc(sizeof(list_t));
	if (list == NULL) {
		fibril_mutex_unlock(&sroute_list_lock);
		return ENOMEM;
	}

	list_initialize(list);

	list_prepend(&new_sroute->list_link, list);
	rc = trie_insert(sroute_table, dest, new_sroute->dest.prefix,
	    list);
	if (rc != EOK) {
		fibril_mutex_unlock(&sroute_list_lock);
		return rc;
	}
	sroute_array_count++;
	fibril_mutex_unlock(&sroute_list_lock);

	return rc;
}

/** Find static route object matching address @a addr.
 *
 * @param addr	Address
 */
inet_sroute_t *inet_sroute_find_longest_match(inet_addr_t *addr)
{
	fibril_mutex_lock(&sroute_list_lock);

	uint8_t dest[16];
	trie_t *sroute_table = NULL;
	uint8_t prefix;
	if (addr->version == ip_v4) {
		sroute_table = ipv4_sroute_table;
		addr32_t dest_addr = htonl(addr->addr);
		memcpy(dest, &dest_addr, sizeof(addr32_t));
		prefix = 32;
	} if (addr->version == ip_v6) {
		sroute_table = ipv6_sroute_table;
		memcpy(dest, &addr->addr6, sizeof(addr128_t));
		prefix = 64;
	}

	list_t *list= (list_t *) trie_find_longest_match(sroute_table, dest,
	    prefix);
	if (list == NULL) {
		fibril_mutex_unlock(&sroute_list_lock);
		return NULL;
	}
	fibril_mutex_unlock(&sroute_list_lock);
	inet_sroute_t *sroute = (inet_sroute_t *) list_first(list);
	if (sroute == NULL || sroute->status == INET_SROUTE_STATUS_DELETED) {
		return NULL;
	}
	return sroute;
}


/** Find static route object matching address @a addr.
 *
 * @param addr	Address
 */
errno_t inet_sroute_delete(inet_naddr_t *addr, inet_addr_t *router)
{
	fibril_mutex_lock(&sroute_list_lock);

	uint8_t dest[16];
	trie_t *sroute_table = NULL;
	uint8_t prefix;
	if (addr->version == ip_v4) {
		sroute_table = ipv4_sroute_table;
		addr32_t dest_addr = htonl(addr->addr);
		memcpy(dest, &dest_addr, sizeof(addr32_t));
		prefix = 32;
	} if (addr->version == ip_v6) {
		sroute_table = ipv6_sroute_table;
		memcpy(dest, &addr->addr6, sizeof(addr128_t));
		prefix = 128;
	}

	list_t *list = (list_t *) trie_find_exact(sroute_table, dest, prefix);
	if (list == NULL) {
		fibril_mutex_unlock(&sroute_list_lock);
		return ENOENT;
	}

	inet_sroute_t *dsroute = NULL;
	list_foreach(*list, list_link, inet_sroute_t, sroute) {
		if (inet_naddrs_compare(&sroute->dest, addr) != 0
		    &&inet_addr_compare(&sroute->router, router) != 0) {
			dsroute = sroute;
			break;
		}
	}
	if (dsroute != NULL) {
		dsroute->status = INET_SROUTE_STATUS_DELETED;
		list_remove(&dsroute->list_link);
		list_append(&dsroute->list_link, list);
		fibril_mutex_unlock(&sroute_list_lock);
		return EOK;
	}
	fibril_mutex_unlock(&sroute_list_lock);
	return ENOENT;
}

/** @}
 */
