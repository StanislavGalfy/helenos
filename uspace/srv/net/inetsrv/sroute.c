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
#include "sroute.h"
#include "inetsrv.h"
#include "inet_link.h"
#include "types/inetcfg.h"

static FIBRIL_MUTEX_INITIALIZE(sroute_list_lock);
static LIST_INITIALIZE(sroute_list);
static LIST_INITIALIZE(del_sroute_list);

trie_t *sroute_table;

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
	fibril_mutex_lock(&sroute_list_lock);

	addr32_t dest = htonl(sroute->dest.addr);

	inet_sroute_t *old_sroute = (inet_sroute_t *) trie_find_exact(
	    sroute_table, &dest, sroute->dest.prefix);
	if (old_sroute != NULL) {
		if (old_sroute->status == INET_SROUTE_STATUS_DELETED) {
			old_sroute->rtm_protocol = sroute->rtm_protocol;
			old_sroute->router = sroute->router;
			old_sroute->dest = sroute->dest;
			old_sroute->status = INET_SROUTE_STATUS_ACTIVE;
			fibril_mutex_unlock(&sroute_list_lock);
			return EOK;
		}
		fibril_mutex_unlock(&sroute_list_lock);
		return EEXIST;
	}
	errno_t rc = trie_insert(sroute_table, &dest, sroute->dest.prefix,
	    sroute);

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

	addr->addr = htonl(addr->addr);
	inet_sroute_t *sroute = (inet_sroute_t *) trie_find_longest_match(
	    sroute_table, &addr->addr, 32);

	fibril_mutex_unlock(&sroute_list_lock);

	return sroute;
}


/** Find static route object matching address @a addr.
 *
 * @param addr	Address
 */
inet_sroute_t *inet_sroute_find_exact(inet_naddr_t *naddr)
{
	fibril_mutex_lock(&sroute_list_lock);

	naddr->addr = htonl(naddr->addr);
	inet_sroute_t *sroute = (inet_sroute_t *) trie_find_exact(
	    sroute_table, &naddr->addr, naddr->prefix);

	fibril_mutex_unlock(&sroute_list_lock);

	return sroute;
}

errno_t inet_sroute_to_array(inet_sroute_t **rsroutes, size_t *rcount)
{
	fibril_mutex_lock(&sroute_list_lock);

	errno_t rc = trie_to_array(sroute_table, sizeof(inet_sroute_t),
	    (void **) rsroutes);
	*rcount = sroute_table->count;

	fibril_mutex_unlock(&sroute_list_lock);

	return rc;
}

/** @}
 */
