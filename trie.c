/*
 * Simple trie implementation for key-value mapping storage
 *
 * Copyright (c) 2020 Ákos Uzonyi <uzonyi.akos@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "trie.h"

static const uint8_t ptr_sz_lg = (sizeof(uint64_t *) == 8 ? 6 : 5);

bool
trie_check(uint8_t item_size_lg, uint8_t node_key_bits,
	    uint8_t data_block_key_bits, uint8_t key_size)
{
	if (item_size_lg > 6)
		return false;
	if (key_size > 64)
		return false;
	if (node_key_bits < 1)
		return false;
	if (data_block_key_bits < 1 || data_block_key_bits > key_size)
		return false;

	return true;
}

void
trie_init(struct trie *t, uint8_t item_size_lg, uint8_t node_key_bits,
	   uint8_t data_block_key_bits, uint8_t key_size, uint64_t set_value)
{
	assert(trie_check(item_size_lg, node_key_bits, data_block_key_bits,
			   key_size));

	t->set_value = set_value;
	t->data = TRIE_UNSET;
	t->item_size_lg = item_size_lg;
	t->node_key_bits = node_key_bits;
	t->data_block_key_bits = data_block_key_bits;
	t->key_size = key_size;
}

static uint8_t
trie_get_depth(struct trie *t)
{
	return (t->key_size - t->data_block_key_bits + t->node_key_bits - 1)
		/ t->node_key_bits;
}

/**
 * Returns lg2 of node size for the specific level of the trie. If max_depth
 * provided is less than zero, it is calculated via trie_get_depth call.
 */
static uint8_t
trie_get_node_size(struct trie *t, uint8_t depth, int max_depth)
{
	if (max_depth < 0)
		max_depth = trie_get_depth(t);

	/* Last level contains data and we allow it having a different size */
	if (depth == max_depth)
		return t->data_block_key_bits + t->item_size_lg;
	/* Last level of the tree can be smaller */
	if (depth == max_depth - 1)
		return (t->key_size - t->data_block_key_bits - 1) %
		t->node_key_bits + 1 + ptr_sz_lg;

	return t->node_key_bits + ptr_sz_lg;
}

/**
 * Provides starting offset of bits in key corresponding to the node index
 * at the specific level.
 */
static uint8_t
trie_get_node_bit_offs(struct trie *t, uint8_t depth, int max_depth)
{
	uint8_t offs;

	if (max_depth < 0)
		max_depth = trie_get_depth(t);

	if (depth == max_depth)
		return 0;

	offs = t->data_block_key_bits;

	if (depth == max_depth - 1)
		return offs;

	/* data_block_size + remainder */
	offs += trie_get_node_size(t, max_depth - 1, max_depth) - ptr_sz_lg;
	offs += (max_depth - depth - 2) * t->node_key_bits;

	return offs;
}

struct trie *
trie_create(uint8_t item_size_lg, uint8_t node_key_bits,
	     uint8_t data_block_key_bits, uint8_t key_size, uint64_t set_value)
{
	struct trie *t;

	if (!trie_check(item_size_lg, node_key_bits, data_block_key_bits,
	    key_size))
		return NULL;

	t = malloc(sizeof(*t));
	if (!t)
		return NULL;

	trie_init(t, item_size_lg, node_key_bits, data_block_key_bits,
		   key_size, set_value);

	return t;
}

static uint64_t
trie_filler(uint64_t val, uint8_t item_size)
{
	val &= (1 << (1 << item_size)) - 1;

	for (; item_size < 6; item_size++)
		val |= val << (1 << item_size);

	return val;
}

static uint64_t *
trie_get_node(struct trie *t, uint64_t key, bool auto_create)
{
	void **cur_node = &(t->data);
	unsigned i;
	uint8_t cur_depth;
	uint8_t max_depth;
	uint8_t sz;

	if (t->key_size < 64 && key > (uint64_t) 1 << t->key_size)
		return NULL;

	max_depth = trie_get_depth(t);

	for (cur_depth = 0; cur_depth <= max_depth; cur_depth++) {
		sz = trie_get_node_size(t, cur_depth, max_depth);

		if (*cur_node == TRIE_SET || *cur_node == TRIE_UNSET) {
			void *old_val = *cur_node;

			if (!auto_create)
				return (uint64_t *) (*cur_node);

			*cur_node = xcalloc(1 << sz, 1);

			if (old_val == TRIE_SET) {
				uint64_t fill_value = cur_depth == max_depth ?
					t->set_value :
					(uintptr_t) TRIE_SET;

				uint8_t fill_size = cur_depth == max_depth ?
					t->item_size_lg :
					ptr_sz_lg;

				unsigned int n = ((unsigned int) 1 << (sz - 6));
				for (i = 0; i < n; i++)
					((uint64_t *) *cur_node)[i] =
						trie_filler(fill_value,
							fill_size);
			}
		}

		if (cur_depth < max_depth) {
			size_t pos = (key >> trie_get_node_bit_offs(t,
				cur_depth, max_depth)) &
				((1 << (sz - ptr_sz_lg)) - 1);

			cur_node = (((void **) (*cur_node)) + pos);
		}
	}

	return (uint64_t *) (*cur_node);
}

bool
trie_set(struct trie *t, uint64_t key, uint64_t val)
{
	uint64_t *data = trie_get_node(t, key, true);
	size_t mask = (1 << t->data_block_key_bits) - 1;
	size_t pos = (key & mask) >> (6 - t->item_size_lg);

	if (!data)
		return false;

	if (t->item_size_lg == 6) {
		data[pos] = val;
	} else {
		size_t offs = (key & ((1 << (6 - t->item_size_lg)) - 1)) *
			(1 << t->item_size_lg);
		uint64_t mask = (((uint64_t) 1 << (1 << t->item_size_lg)) - 1)
			<< offs;

		data[pos] &= ~mask;
		data[pos] |= (val << offs) & mask;
	}

	return true;
}

#if 0
int
trie_mask_set(struct trie *t, uint64_t key, uint8_t mask_bits)
{
}

/**
 * Sets to 0 all keys with 0-ed bits of mask equivalent to corresponding bits in
 * key.
 */
int
trie_mask_unset(struct trie *t, uint64_t key, uint8_t mask_bits)
{
}

int
trie_interval_set(struct trie *t, uint64_t begin, uint64_t end, uint64_t val)
{
}

uint64_t
trie_get_next_set_key(struct trie *t, uint64_t key)
{
}
#endif

static uint64_t
trie_data_block_get(struct trie *t, uint64_t *data, uint64_t key)
{
	size_t mask;
	size_t pos;
	size_t offs;

	if (!data)
		return 0;
	if ((void *) data == (void *) TRIE_SET)
		return t->set_value;

	mask = (1 << t->data_block_key_bits) - 1;
	pos = (key & mask) >> (6 - t->item_size_lg);

	if (t->item_size_lg == 6)
		return data[pos];

	offs = (key & ((1 << (6 - t->item_size_lg)) - 1)) *
		(1 << t->item_size_lg);

	return (data[pos] >> offs) &
		(((uint64_t)1 << (1 << t->item_size_lg)) - 1);
}

uint64_t
trie_get(struct trie *b, uint64_t key)
{
	return trie_data_block_get(b, trie_get_node(b, key, false), key);
}

static uint64_t
trie_iterate_keys_node(struct trie *t, enum trie_iterate_flags flags,
				trie_iterate_fn fn, void *fn_data,
				void *node, uint64_t start, uint64_t end,
				uint8_t depth, uint8_t max_depth)
{
	if (start > end)
		return 0;

	if ((node == TRIE_SET && !(flags & TRIE_ITERATE_KEYS_SET)) ||
		(node == TRIE_UNSET && !(flags & TRIE_ITERATE_KEYS_UNSET)))
		return 0;

	if (node == TRIE_SET || node == TRIE_UNSET || depth == max_depth) {
		for (uint64_t i = start; i <= end; i++)
			fn(fn_data, i, trie_data_block_get(t,
				(uint64_t *) node, i));

		return end - start + 1; //TODO: overflow
	}

	uint8_t parent_node_bit_off = depth == 0 ?
		t->key_size :
		trie_get_node_bit_offs(t, depth - 1, max_depth);

	uint64_t first_key_in_node = start &
		(uint64_t) -1 << parent_node_bit_off;

	uint8_t node_bit_off = trie_get_node_bit_offs(t, depth, max_depth);
	uint8_t node_key_bits = parent_node_bit_off - node_bit_off;
	uint64_t mask = ((uint64_t) 1 << (node_key_bits)) - 1;
	uint64_t start_index = (start >> node_bit_off) & mask;
	uint64_t end_index = (end >> node_bit_off) & mask;
	uint64_t child_key_count = (uint64_t) 1 << node_bit_off;

	uint64_t count = 0;

	for (uint64_t i = start_index; i <= end_index; i++) {
		uint64_t child_start = first_key_in_node + i * child_key_count;
		uint64_t child_end = first_key_in_node +
			(i + 1) * child_key_count - 1;

		if (child_start < start)
			child_start = start;
		if (child_end > end)
			child_end = end;

		count += trie_iterate_keys_node(t, flags, fn, fn_data,
			((void **) node)[i], child_start, child_end,
			depth + 1, max_depth);
	}

	return count;
}

uint64_t trie_iterate_keys(struct trie *t, uint64_t start, uint64_t end,
			    enum trie_iterate_flags flags, trie_iterate_fn fn,
			    void *fn_data)
{
	return trie_iterate_keys_node(t, flags, fn, fn_data, t->data,
		start, end, 0, trie_get_depth(t));
}

void
trie_free_node(struct trie *t, uint64_t **node, uint8_t depth,
		 int max_depth)
{
	size_t sz;
	size_t i;

	if (node == TRIE_SET || node == TRIE_UNSET)
		return;
	if (max_depth < 0)
		max_depth = trie_get_depth(t);
	if (depth >= max_depth)
		goto free_node;

	sz = 1 << (trie_get_node_size(t, depth, max_depth) - ptr_sz_lg);

	for (i = 0; i < sz; i++)
		trie_free_node(t, (uint64_t **) (node[i]),
			depth + 1, max_depth);

free_node:
	free(node);
}

void
trie_free(struct trie *t)
{
	trie_free_node(t, t->data, 0, -1);
	free(t);
}
