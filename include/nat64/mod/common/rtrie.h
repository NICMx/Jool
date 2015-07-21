#ifndef _JOOL_MOD_RTRIE_H
#define _JOOL_MOD_RTRIE_H

#include <linux/types.h>

struct rtrie_string {
	__u8 *bytes;
	/* In bits; not bytes. */
	__u8 len;
};

struct rtrie_node {
	struct rtrie_node *parent;
	struct rtrie_node *left;
	struct rtrie_node *right;

	struct rtrie_string string;

	/* The value hangs off end. */
};

void *rtrie_get(struct rtrie_node *root, struct rtrie_string *key);

int rtrie_add(struct rtrie_node **root, void *content, size_t content_len,
		size_t key_offset, __u8 key_len);
int rtrie_rm(struct rtrie_node **root, struct rtrie_string *key);
void rtrie_flush(struct rtrie_node **root);

void rtrie_print(struct rtrie_node *root);

#endif /* _JOOL_MOD_RTRIE_H */
