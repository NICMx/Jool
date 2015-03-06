#include "nat64/mod/stateless/rfc6791.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip_fib.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/random.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateless/pool.h"
#include "nat64/mod/common/route.h"

static struct list_head pool;

int rfc6791_init(char *pref_strs[], int pref_count)
{
	return pool_init(pref_strs, pref_count, &pool);
}

void rfc6791_destroy(void)
{
	return pool_destroy(&pool);
}

int rfc6791_add(struct ipv4_prefix *prefix)
{
	return pool_add(&pool, prefix);
}

int rfc6791_remove(struct ipv4_prefix *prefix)
{
	return pool_remove(&pool, prefix);
}

int rfc6791_flush(void)
{
	return pool_flush(&pool);
}

static int pool_count_wrapper(unsigned int *result)
{
	__u64 tmp;
	int error;

	error = pool_count(&pool, &tmp);
	if (error)
		return error;

	*result = (unsigned int) tmp;
	return 0;
}

/**
 *	Function to get an IPv4 address of the local machine from "daddr".
 *	if not result found return error.
 *	RCU locks must be hold.
 */
static int get_host_address(struct in_addr *result, struct packet *in, struct packet *out)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	struct iphdr *hdr_ip;
	int error;

	struct flowi4 flow;

	if (!in || !out) {
		log_err("in or out cannot be NULL");
		return -EINVAL;
	}

	memset(&flow, 0, sizeof(flow));
	hdr_ip = ip_hdr(out->skb);
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = in->skb->mark;
	flow.flowi4_tos = RT_TOS(hdr_ip->tos);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = hdr_ip->protocol;
	/*
	 * TODO (help) Don't know if we should set FLOWI_FLAG_PRECOW_METRICS. Does the kernel ever
	 * create routes on Jool's behalf?
	 * TODO (help) We should probably set FLOWI_FLAG_ANYSRC (for virtual-interfaceless support).
	 * If you change it, the corresponding attribute in route_ipv6() should probably follow.
	 */
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* It appears this one only introduces noise. */
	/* flow.saddr = hdr_ip->saddr; */
	flow.daddr = hdr_ip->daddr;

	{
		union {
			struct tcphdr *tcp;
			struct udphdr *udp;
			struct icmphdr *icmp4;
		} hdr;

		switch (pkt_l4_proto(in)) {
		case L4PROTO_TCP:
			hdr.tcp = pkt_tcp_hdr(in);
			flow.fl4_sport = hdr.tcp->source;
			flow.fl4_dport = hdr.tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr.udp = pkt_udp_hdr(in);
			flow.fl4_sport = hdr.udp->source;
			flow.fl4_dport = hdr.udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr.icmp4 = pkt_icmp4_hdr(in);
			flow.fl4_icmp_type = hdr.icmp4->type;
			flow.fl4_icmp_code = hdr.icmp4->code;
			break;
		case L4PROTO_OTHER:
			break;
		}
	}

	error = __route4(out, &flow);
	if (error)
		return error;

	dev = out->skb->dev;
	in_dev = rcu_dereference(dev->ip_ptr);
	ifaddr = in_dev->ifa_list;
	while (ifaddr) {
		if (IN_LOOPBACK(ntohl(ifaddr->ifa_address))) {
			ifaddr = ifaddr->ifa_next;
			continue;
		}
		result->s_addr = ifaddr->ifa_address;
		return 0;
	}

	log_err("Something went wrong; looks like packet was routed to the loopback net_device.");
	return -EINVAL;
}

int rfc6791_get(struct in_addr *result, struct packet *in, struct packet *out)
{
	struct pool_entry *entry;
	unsigned int count;
	unsigned int rand;
	int error;

	rcu_read_lock();

	/*
	 * I'm counting the list elements instead of using an algorithm like reservoir sampling
	 * (http://stackoverflow.com/questions/54059) because the random function can be really
	 * expensive. Reservoir sampling requires one random per iteration, this way requires one
	 * random period.
	 */
	error = pool_count_wrapper(&count);
	if (error) {
		rcu_read_unlock();
		log_debug("pool_count failed with errcode %d.", error);
		return error;
	}

	if (count == 0) {
		error = get_host_address(result, in, out);
		goto end;
	}

	rand = get_random_u32() % count;

	list_for_each_entry_rcu(entry, &pool, list_hook) {
		count = prefix4_get_addr_count(&entry->prefix);
		if (count >= rand)
			break;
		rand -= count;
	}

	result->s_addr = htonl(ntohl(entry->prefix.address.s_addr) | rand);

end:
	rcu_read_unlock();
	if (error)
		log_warn_once("The IPv4 RFC6791 pool and the Host's IPv4 address are empty.");
	return error;
}

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg)
{
	return pool_for_each(&pool, func, arg);
}

int rfc6791_count(__u64 *result)
{
	return pool_count(&pool, result);
}

bool rfc6791_is_empty(void)
{
	return pool_is_empty(&pool);
}
