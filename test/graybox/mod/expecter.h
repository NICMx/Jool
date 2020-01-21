#ifndef _GRAYBOX_MOD_EXPECTER_H
#define _GRAYBOX_MOD_EXPECTER_H

#include <linux/skbuff.h>
#include "common/graybox-types.h"

#define EXCEPTIONS_MAX 64u

struct expected_packet {
	char *filename;
	unsigned char *bytes;
	size_t bytes_len;
	__u16 exceptions[EXCEPTIONS_MAX];
	/* Number of entries in @exceptions. */
	size_t exceptions_len;
};

void expecter_setup(void);
void expecter_teardown(void);

int expecter_add(struct expected_packet *pkt);
void expecter_flush(void);

int expecter_handle_pkt(struct sk_buff *skb);

void expecter_stat(struct graybox_stats *result);
void expecter_stat_flush(void);

#endif
