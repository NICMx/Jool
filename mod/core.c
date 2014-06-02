#include "nat64/mod/core.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/fragment_db.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/send_packet.h"
#include "nat64/comm/log_time.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <net/ipv6.h>


static struct log_time step1;
static struct log_time step2;
static struct log_time step3;
static struct log_time step4;
static struct log_time step5;

static void log_cycles(unsigned long start, unsigned long step1End, unsigned long step2End,
		unsigned long step3End, unsigned long step4End, unsigned long step5End)
{
	logtime(&step1, step1End - start);
	logtime(&step2, (step2End - step1End)/1000L);
	logtime(&step3, step3End - step2End);
	logtime(&step4, step4End - step3End);
	logtime(&step5, (step5End - step4End)/100L);
	if (step5.counter%2500 == 0) {
		/*log_warning("%u, %lu, %lu, %lu, %lu, %lu", step5.counter, step1.sum/step1.counter,
				(step2.sum/step2.counter)*1000, step3.sum/step3.counter, step4.sum/step4.counter,
				(step5.sum/step5.counter)*100);*/
		logtime_print_counter(&step1);
		logtime_print_avg(&step1);
		logtime_print_avg_multiply(&step2, 1000);
		logtime_print_avg(&step3);
		logtime_print_avg(&step4);
		logtime_print_avg_multiply(&step5, 100);
		printk("\n");
	}
	if (step5.counter%10000 == 0) {
		logtime_restart(&step1);
		logtime_restart(&step2);
		logtime_restart(&step3);
		logtime_restart(&step4);
		logtime_restart(&step5);
	}

}

static unsigned int core_common(struct sk_buff *skb_in)
{
	struct packet *pkt_in = NULL;
	struct packet *pkt_out = NULL;
	struct tuple tuple_in;
	struct tuple tuple_out;
	verdict result;
	unsigned long start, step1End, step2End, step3End, step4End, step5End;

	result = fragment_arrives(skb_in, &pkt_in);
	if (result != VER_CONTINUE)
		return (unsigned int) result;

	start = get_cycles();

	if (determine_in_tuple(pkt_in->first_fragment, &tuple_in) != VER_CONTINUE)
		goto end;

	step1End = get_cycles();

	if (filtering_and_updating(pkt_in->first_fragment, &tuple_in) != VER_CONTINUE)
		goto end;

	step2End = get_cycles();

	if (compute_out_tuple(&tuple_in, &tuple_out) != VER_CONTINUE)
		goto end;

	step3End = get_cycles();

	if (translating_the_packet(&tuple_out, pkt_in, &pkt_out) != VER_CONTINUE)
		goto end;

	step4End = get_cycles();

	if (is_hairpin(pkt_out)) {
		if (handling_hairpinning(pkt_out, &tuple_out) != VER_CONTINUE)
			goto end;
	} else {
		if (send_pkt(pkt_out) != VER_CONTINUE)
			goto end;
	}

	step5End = get_cycles();
	log_debug("Success.");
	/* Fall through. */

	/** log_cycles(start, step1End, step2End, step3End, step4End, step5End); */

end:
	pkt_kfree(pkt_in);
	pkt_kfree(pkt_out);
	return (unsigned int) VER_STOLEN;
}

/**
 * Entry point for IPv4 packet processing.
 */
unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *ip4_header;
	struct in_addr daddr;

	skb_linearize(skb);

	ip4_header = ip_hdr(skb);

	daddr.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	return core_common(skb);
}

/**
 * Entry point for IPv6 packet processing.
 */
unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_header;

	skb_linearize(skb);

	ip6_header = ipv6_hdr(skb);

	if (!pool6_contains(&ip6_header->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	return core_common(skb);
}
