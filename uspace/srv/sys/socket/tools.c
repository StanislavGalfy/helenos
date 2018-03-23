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

/** @addtogroup socket
 * @{
 */
/** @file Tools
 */

#include <adt/list.h>
#include <malloc.h>
#include <inet/inetcfg.h>
#include <stdio.h>
#include <byteorder.h>
#include <io/log.h>
#include <errno.h>

#include "tools.h"

/** Maximum file id generated by VFS module */
#define VFS_MAX_FILE_ID 127

/** ID */
typedef struct {
	/** Link to list of free ids */
	link_t link;
	/** Value of id */
	int value;
} id_t;

/** Next free socket id. Socket ID's start after file ID's from VFS module */
int next_socket_id = VFS_MAX_FILE_ID + 1;
/** Next free session id.*/
int next_session_id = 0;

/** List of freed socket ids */
static list_t free_socket_ids;
/** List of freed session ids */
static list_t free_session_ids;

/** Initialize tools.
 */
void tools_init()
{
	inetcfg_init();
	list_initialize(&free_socket_ids);
	list_initialize(&free_session_ids);
}

/** Generates id.
 *
 * @param free_ids	List of free id's to look for one.
 * @param next_id	Next ID, in case there is no free ID.
 * @return		generated ID.
 */
static int generate_id(list_t *free_ids, int *next_id)
{
	if (list_empty(free_ids)) {
		*next_id += 1;
		return *next_id;
	}

	id_t *id = (id_t*)list_first(free_ids);
	list_remove(&id->link);
	int tmp_id = id->value;
	free(id);
	return tmp_id;
}

/** Puts ID into list of free ID's.
 *
 * @param free_ids	List of free ID's.
 * @param value		Value of ID.
 */
static void free_id(list_t* free_ids, int value)
{
	id_t *id = calloc(1, sizeof(id_t));
	link_initialize(&id->link);
	id->value = value;
	list_append(&id->link, free_ids);
}

/** Generated socket ID.
 *
 * @return	Socket ID.
 */
int generate_socket_id(void)
{
	return generate_id(&free_socket_ids, &next_socket_id);
}

/** Frees socket ID.
 *
 * @param value	Socket ID to free.
 */
void free_socket_id(int value)
{
	free_id(&free_socket_ids, value);
}

/** Generates session ID.
 *
 * @return	Session ID.
 */
int generate_sesssion_id(void)
{
	return generate_id(&free_session_ids, &next_session_id);
}

/** Frees session ID.
 *
 * @param value	Session ID to free.
 */
void free_session_id(int value)
{
	free_id(&free_session_ids, value);
}

/** Looks up socket by ID in socket list.
 *
 * @param id	Socket id.
 * @return	Pointer to socket with given ID, NULL if it does not exist.
 */
common_socket_t* get_socket_by_id(int id)
{

	list_foreach(socket_list, link, common_socket_t, socket) {
		if (socket->id == id) {
			return socket;
		}
	}
	return NULL;
}

/** Looks up socket by ip link service ID in socket list.
 *
 * @param id	Ip link service ID.
 * @return	Pointer to socket with given socket link, NULL if it does not
 *		exist.
 */
common_socket_t* get_socket_by_iplink(service_id_t iplink)
{

	list_foreach(socket_list, link, common_socket_t, socket) {
		if (socket->domain == AF_INET && socket->type == SOCK_RAW) {
			if (((raw_socket_t*)socket)->iplink == iplink)
				return socket;
		}
	}
	return NULL;
}

/** Returns first socket with given session ID in socket list.
 *
 * @param session_id	Session ID.
 * @return		Pointer to socket with given session ID, NULL if it does
 *			not exist.
 */
common_socket_t* get_socket_by_session_id(int session_id)
{

	list_foreach(socket_list, link, common_socket_t, socket) {
		if (socket->session_id == session_id) {
			return socket;
		}
	}
	return NULL;
}

/** Finds first address configured for link with given service ID.
 *
 * @param link_svcid	Link service ID.
 * @param raddr		Pointer, where the address will be stored.
 * @return		EOK on success, error code on failure.
 */
int get_link_addr(sysarg_t link_svcid, inet_addr_t *raddr)
{
	sysarg_t *addr_list;
	inet_addr_info_t ainfo;

	size_t count;
	size_t i;

	int rc = inetcfg_get_addr_list(&addr_list, &count,
	    INET_ADDR_STATUS_ACTIVE);
	if (rc != EOK) {
		return rc;
	}

	for (i = 0; i < count; i++) {
		rc = inetcfg_addr_get(addr_list[i], &ainfo,
		    INET_ADDR_STATUS_ACTIVE);
		if (rc != EOK) {
			continue;
		}

		if (ainfo.naddr.version == ip_v4 && ainfo.ilink == link_svcid) {
			inet_naddr_addr(&ainfo.naddr, raddr);
			return EOK;
		}
	}
	inet_addr_any(raddr);
	raddr->version = ip_v4;
	return EOK;
}

/** @}
 */
