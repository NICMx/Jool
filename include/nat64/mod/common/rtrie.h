#ifndef _JOOL_MOD_RTRIE_H
#define _JOOL_MOD_RTRIE_H

/**
 * @file
 * A Radix Trie.
 *
 * Why don't we use the kernel's radix trie instead?
 * Because it's only good for keys long-sized; we need 128-bit keys.
 */

#include <linux/types.h>
#include <linux/mutex.h>

struct rtrie_key {
	__u8 *bytes;
	/* In bits; not bytes. */
	__u8 len;
};

enum rtrie_color {
	COLOR_BLACK,
	COLOR_WHITE,
};

/**
 * Some fields here are RCU-friendly and others aren't.
 *
 * RCU-friendly fields can be dereferenced in RCU-protected areas happily,
 * and of course MUST NOT BE EDITED while the node is in the trie.
 *
 * RCU-unfriendly fields must not be touched outside the domain of the trie's
 * lock.
 */
struct rtrie_node {
	/** RCU-friendly. */
	struct rtrie_node __rcu *left;
	/** RCU-friendly. */
	struct rtrie_node __rcu *right;
	/** NOT RCU-friendly. */
	struct rtrie_node *parent;

	/**
	 * RCU-friendly.
	 *
	 * If you want to assign a different value here, consider:
	 *
	 * - Black nodes cannot be upgraded into white nodes since white nodes
	 *   are supposed to contain a value (black nodes only need a key).
	 * - White nodes can be downgraded into black nodes as long as they're
	 *   not attached to tries.
	 */
	enum rtrie_color color;
	/** RCU-friendly. */
	struct rtrie_key key;

	/**
	 * This is used to foreach all the nodes (whether black or white).
	 *
	 * NOT RCU-friendly.
	 */
	struct list_head list_hook;

	/* The value hangs off end. RCU-friendly. */
};

struct rtrie {
	/** The tree. */
	struct rtrie_node __rcu *root;
	/** @root's nodes chained to ease foreaching. */
	struct list_head list;
	/** Size of the values being stored (in bytes). */
	size_t value_size;

	/**
	 * Notice that this is a pointer.
	 * Locking is actually the caller's responsibility; the only reason why
	 * the trie keeps track of it is for the sake of RCU validation.
	 */
	struct mutex *lock;
};

void rtrie_init(struct rtrie *trie, size_t size, struct mutex *lock);
void rtrie_destroy(struct rtrie *trie);

/* Safe-to-use-during-packet-translation functions */

int rtrie_get(struct rtrie *trie, struct rtrie_key *key, void *result);
bool rtrie_contains(struct rtrie *trie, struct rtrie_key *key);
bool rtrie_is_empty(struct rtrie *trie);
void rtrie_print(char *prefix, struct rtrie *trie);

/* Lock-before-using functions. */

int rtrie_add(struct rtrie *trie, void *value, size_t key_offset, __u8 key_len);
int rtrie_rm(struct rtrie *trie, struct rtrie_key *key);
void rtrie_flush(struct rtrie *trie);
int rtrie_foreach(struct rtrie *trie,
		int (*cb)(void *, void *), void *arg,
		struct rtrie_key *offset);

#endif /* _JOOL_MOD_RTRIE_H */
