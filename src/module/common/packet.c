#include "packet.h"

#define SIMPLE_MIN(a, b) ((a < b) ? a : b)

void snapshot_record(struct pkt_snapshot *shot, struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int limit;
	unsigned int i;

	shot->len = skb->len;
	shot->data_len = skb->data_len;
	shot->nr_frags = shinfo->nr_frags;

	limit = SIMPLE_MIN(SNAPSHOT_FRAGS_SIZE, shot->nr_frags);
	for (i = 0; i < limit; i++)
		shot->frags[i] = skb_frag_size(&shinfo->frags[i]);

	/*
	 * Ok so I only have room for SNAPSHOT_FRAGS_SIZE page sizes, unless I
	 * allocate. I don't want to allocate because that's an additional fail
	 * opportunity and I want this to be as unintrusive as possible.
	 *
	 * First of all, since PAGE_SIZE is 4k in my VM, and the typical
	 * Internet MTU is 1500 max, I don't think the packet is going
	 * to have more than one page.
	 *
	 * (Unless IP fragments are being treated as pages, but I don't think
	 * that's the case here because the crashing packet was an ICMP error,
	 * and defrag discards fragmented ICMP errors on reception because they
	 * are BS.)
	 *
	 * Second, even if we get multiple pages, I don't see why would they
	 * have different sizes. Except for the last one, that is.
	 *
	 * (Unless the crashing pages were IP fragments. Again, I don't think
	 * this is the case.)
	 *
	 * Therefore, if the packet has more than SNAPSHOT_FRAGS_SIZE pages,
	 * I'm going to risk it and override the last slottable page size with
	 * the most interesting one. (The last one.)
	 *
	 * Consider that when you're reading the output.
	 */
	if (shot->nr_frags > SNAPSHOT_FRAGS_SIZE) {
		shot->frags[SNAPSHOT_FRAGS_SIZE - 1]
			    = skb_frag_size(&shinfo->frags[shot->nr_frags - 1]);
	}
}

void snapshot_report(struct pkt_snapshot *shot, char *prefix)
{
	unsigned int limit;
	unsigned int i;

	pr_err("%s len: %u\n", prefix, shot->len);
	pr_err("%s data_len: %u\n", prefix, shot->data_len);
	pr_err("%s nr_frags: %u\n", prefix, shot->nr_frags);

	limit = SIMPLE_MIN(SNAPSHOT_FRAGS_SIZE, shot->nr_frags);
	for (i = 0; i < limit; i++)
		pr_err("    %s frag %u: %u\n", prefix, i, shot->frags[i]);
}
