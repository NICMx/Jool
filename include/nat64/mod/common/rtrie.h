#ifndef _JOOL_MOD_RTRIE_H
#define _JOOL_MOD_RTRIE_H

#include <linux/types.h>

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
 * RCU-unfriendly fields must not be touched outside the config lock's domain.
 */
struct rtrie_node {
	/** RCU-friendly. */
	struct rtrie_node *left;
	/** RCU-friendly. */
	struct rtrie_node *right;
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

void *rtrie_get(struct rtrie_node *root, struct rtrie_key *key);

int rtrie_add(struct rtrie_node **root, void *content, size_t content_len,
		size_t key_offset, __u8 key_len);
int rtrie_rm(struct rtrie_node **root, struct rtrie_key *key);
void rtrie_flush(struct rtrie_node **root);

int rtrie_foreach(struct rtrie_node *root,
		int (*cb)(void *, void *), void *arg,
		struct rtrie_key *offset);
void rtrie_print(char *prefix, struct rtrie_node *root);

#endif /* _JOOL_MOD_RTRIE_H */
