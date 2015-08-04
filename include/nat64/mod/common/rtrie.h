#ifndef _JOOL_MOD_RTRIE_H
#define _JOOL_MOD_RTRIE_H

#include <linux/types.h>

struct rtrie_string {
	__u8 *bytes;
	/* In bits; not bytes. */
	__u8 len;
};

enum rtrie_color {
	COLOR_BLACK,
	COLOR_WHITE,
};

struct rtrie_node {
	struct rtrie_node *left;
	struct rtrie_node *right;
	enum rtrie_color color;

	struct rtrie_string key;

	/* The value hangs off end. */
};

void *rtrie_get(struct rtrie_node *root, struct rtrie_string *key);

int rtrie_add(struct rtrie_node **root, void *content, size_t content_len,
		size_t key_offset, __u8 key_len);
int rtrie_rm(struct rtrie_node **root, struct rtrie_string *key);
void rtrie_flush(struct rtrie_node **root);

int rtrie_foreach(struct rtrie_node *root,
		int (*cb)(void *, void *), void *arg,
		struct rtrie_string *offset, struct rtrie_node **stack);
void rtrie_print(struct rtrie_node *root);

#endif /* _JOOL_MOD_RTRIE_H */
