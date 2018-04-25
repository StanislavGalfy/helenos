/*
 * Copyright (c) 2018 Stanislav Galfy
 *
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

#include <adt/trie.h>
#include <stdlib.h>
#include <mem.h>
#include <io/log.h>
#include <types/inetcfg.h>

static uint8_t get_bit(void *key, uint32_t pos)
{
	uint32_t byte_pos = pos / 8;
	uint32_t bit_pos = pos % 8;
	unsigned char byte = ((unsigned char *) key)[byte_pos];
	unsigned char mask = 1 << (7 - bit_pos);
	uint8_t bit = (byte & mask) != 0 ? 1 : 0;
	return bit;
}

static errno_t trie_create_node(trie_node_t **trie_node)
{
	*trie_node = malloc(sizeof(trie_node_t));
	if (*trie_node == NULL) {
		return ENOMEM;
	}

	(*trie_node)->parent = NULL;
	(*trie_node)->left = NULL;
	(*trie_node)->right = NULL;
	(*trie_node)->data_node = false;
	(*trie_node)->data = NULL;

	return EOK;
}

errno_t trie_create(trie_t **rtrie)
{
	trie_t *trie = calloc(1, sizeof(trie_t));
	if (trie == NULL) {
		return ENOMEM;
	}
	trie->root = calloc(1, sizeof(trie_node_t));
	if (trie->root == NULL) {
		return ENOMEM;
	}
	*rtrie = trie;
	return EOK;
}

void trie_destroy(trie_t * trie) { }

errno_t trie_insert(trie_t *trie, void *key, size_t key_bit_len, void *data)
{
	trie_node_t *node = trie->root;
	for (size_t i = 0; i < key_bit_len; i++) {
		uint8_t bit = get_bit(key, i);
		if (bit == 0) {
			if (node->left == NULL) {
				errno_t rc = trie_create_node(&node->left);
				if (rc != EOK) {
					return rc;
				}
				node->left->parent = node;
			}
			node = node->left;
		} else {
			if (node->right == NULL) {
				errno_t rc = trie_create_node(&node->right);
				if (rc != EOK) {
					return rc;
				}
				node->right->parent = node;
			}
			node = node->right;
		}
	}
	if (node->data_node) {
		return EEXIST;
	}
	node->data_node = true;
	node->data = data;
	trie->count++;
	if (key_bit_len > trie->max_key_len) {
		trie->max_key_len = key_bit_len;
	}

	return EOK;
}

void *trie_find_longest_match(trie_t *trie, void *key, size_t key_bit_len)
{
	trie_node_t *node = trie->root;
	trie_node_t *last_match = NULL;
	for (size_t i = 0; i < key_bit_len; i++) {
		uint8_t bit = get_bit(key, i);
		if (bit == 0) {
			node = node->left;
		} else {
			node = node->right;
		}
		if (node == NULL) {
			break;
		}

		if (node->data_node) {
			last_match = node;
		}
	}
	if (last_match != NULL) {
		return last_match->data;
	}
	return NULL;
}

void *trie_find_exact(trie_t *trie, void *key, size_t key_bit_len)
{
	trie_node_t *node = trie->root;
	for (size_t i = 0; i < key_bit_len; i++) {
		uint8_t bit = get_bit(key, i);
		if (bit == 0) {
			node = node->left;
		} else {
			node = node->right;
		}
		if (node == NULL) {
			break;
		}
	}
	if (node != NULL && node->data_node) {
		return node->data;
	}
	return NULL;
}

/** @}
 */
