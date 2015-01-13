#ifndef FRAGS_MOD_SKB_OPS_H
#define FRAGS_MOD_SKB_OPS_H

/**
 * @file
 * Commons operations to compare a incoming skb to an usr_skb;
 *
 * @author Daniel Hdz Felix
 */


#include <types.h>
#include <linux/skbuff.h>

static inline int get_l3_proto(void *l3_hdr)
{
	return (*((char *) l3_hdr)) >> 4;
}

int skb_from_pkt(void *pkt, u32 pkt_len, struct sk_buff **skb);

int skb_route(struct sk_buff *skb, void *pkt);

bool skb_has_same_address(struct sk_buff *expected, struct sk_buff *actual);

bool skb_compare(struct sk_buff *expected, struct sk_buff *actual, int *err);

void skb_free(struct sk_buff *skb);


#endif /* FRAGS_MOD_SKB_OPS_H */
