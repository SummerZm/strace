/*
 * Simple trie interface
 *
 * Copyright (c) 2020 Ákos Uzonyi <uzonyi.akos@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef STRACE_TRIE_H
#define STRACE_TRIE_H

#define TRIE_SET   ((void *) ~(intptr_t) 0)
#define TRIE_UNSET ((void *) NULL)

enum trie_iterate_flags {
	/** Iterate over TRIE_SET values also */
	TRIE_ITERATE_KEYS_SET   = 1 << 0,
	/** Iterate over TRIE_UNSET values also */
	TRIE_ITERATE_KEYS_UNSET = 1 << 1,
};

/**
 * Trie control structure.
 * Trie implemented here has the following properties:
 *  * It allows storing values of the same size, the size can vary from 1 bit to
 *    64 bit values (only power of 2 sizes are allowed).
 *  * The key can be up to 64 bits in size.
 *  * It has separate configuration for node size and data block size.
 *  * It can be used for mask storage - supports storing the flag that all keys
 *    are set/unset in the middle tree layers. See also trie_mask_set() and
 *    trie_mask_unset().
 *
 * How bits of key are used for different node levels:
 *
 *   highest bits                                                  lowest bits
 *  | node_key_bits | node_key_bits | ... | <remainder> | data_block_key_bits |
 *  \_________________________________________________________________________/
 *                                 key_size
 *
 * So, the remainder is used on the lowest non-data node level.
 *
 * As of now, it doesn't implement any mechanisms for resizing/changing key
 * size.  De-fragmentation is also unsupported currently.
 */
struct trie {
	/** Default set value */
	uint64_t set_value;

	/** Pointer to root node */
	void *data;

	/** Key size in bits (0..64). */
	uint8_t key_size;

	/**
	 * Size of the stored values in log2 bits (0..6).
	 * (6: 64 bit values, 5: 32 bit values, ...)
	 */
	uint8_t item_size_lg;

	/**
	 * Number of bits in key that makes a symbol for a node.
	 * (equals to log2 of the child count of the node)
	 */
	uint8_t node_key_bits;

	/**
	 * Number of bits in key that make a symbol for the data block (leaf).
	 * (equals to log2 of the value count stored in a data block)
	 */
	uint8_t data_block_key_bits;
};

typedef void (*trie_iterate_fn)(void *data, uint64_t key, uint64_t val);

bool trie_check(uint8_t item_size_lg, uint8_t node_key_bits,
		 uint8_t data_block_key_bits, uint8_t key_size);
void trie_init(struct trie *t, uint8_t item_size_lg,
		uint8_t node_key_bits, uint8_t data_block_key_bits,
		uint8_t key_size, uint64_t set_value);
struct trie * trie_create(uint8_t item_size_lg, uint8_t node_key_bits,
			    uint8_t data_block_key_bits, uint8_t key_size,
			    uint64_t set_value);

bool trie_set(struct trie *t, uint64_t key, uint64_t val);
#if 0
/**
 * Sets to the value b->set_value all keys with 0-ed bits of mask equivalent to
 * corresponding bits in key.
 */
int trie_mask_set(struct trie *t, uint64_t key, uint8_t mask_bits);
/**
 * Sets to 0 all keys with 0-ed bits of mask equivalent to corresponding bits in
 * key.
 */
int trie_mask_unset(struct trie *t, uint64_t key, uint8_t mask_bits);
int trie_interval_set(struct trie *t, uint64_t begin, uint64_t end,
		       uint64_t val);

uint64_t trie_get_next_set_key(struct trie *t, uint64_t key);
#endif

/**
 * Calls trie_iterate_fn for each key-value pair where
 * key is inside the [start, end] interval (inclusive).
 *
 * @param t        The trie.
 * @param start    The start of the key interval (inclusive).
 * @param end      The end of the key interval (inclusive).
 * @param flags    A bitwise combination of enum trie_iterate_flags values.
 * @param fn       The function to be called.
 * @param fn_data  The value to be passed to fn.
 */
uint64_t trie_iterate_keys(struct trie *t, uint64_t start, uint64_t end,
			    enum trie_iterate_flags flags, trie_iterate_fn fn,
			    void *fn_data);

uint64_t trie_get(struct trie *t, uint64_t key);

void trie_free_node(struct trie *t, uint64_t **node, uint8_t depth,
		      int max_depth);
void trie_free(struct trie *t);

#endif /* !STRACE_TRIE_H */
