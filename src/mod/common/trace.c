#include "mod/common/trace.h"

#include "mod/common/log.h"

static void trace4_ports(struct xlation *state, char const *proto,
		struct iphdr *hdr4, __be16 sport, __be16 dport)
{
	log_info("INSTANCE:%s PROTO:IPv4/%s SRC:%pI4#%u DST:%pI4#%u",
			state->jool.iname, proto,
			&hdr4->saddr, be16_to_cpu(sport),
			&hdr4->daddr, be16_to_cpu(dport));
}

void pkt_trace4(struct xlation *state)
{
	struct iphdr *hdr4;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct icmphdr *icmp;
	} ptr;

	hdr4 = pkt_ip4_hdr(&state->in);

	switch (pkt_l4_proto(&state->in)) {
	case L4PROTO_TCP:
		ptr.tcp = pkt_tcp_hdr(&state->in);
		trace4_ports(state, "TCP", hdr4, ptr.tcp->source, ptr.tcp->dest);
		break;
	case L4PROTO_UDP:
		ptr.udp = pkt_udp_hdr(&state->in);
		trace4_ports(state, "UDP", hdr4, ptr.udp->source, ptr.udp->dest);
		break;
	case L4PROTO_ICMP:
		ptr.icmp = pkt_icmp4_hdr(&state->in);
		log_info("INSTANCE:%s PROTO:IPv4/ICMP SRC:%pI4 DST:%pI4 TYPE:%u CODE:%u",
				state->jool.iname,
				&hdr4->saddr, &hdr4->daddr,
				ptr.icmp->type, ptr.icmp->code);
		break;
	case L4PROTO_OTHER:
		log_info("INSTANCE:%s PROTO:IPv4/? SRC:%pI4 DST:%pI4",
				state->jool.iname, &hdr4->saddr, &hdr4->daddr);
	}
}

static void trace6_ports(struct xlation *state, char const *proto,
		struct ipv6hdr *hdr6, __be16 sport, __be16 dport)
{
	log_info("INSTANCE:%s PROTO:IPv6/%s SRC:%pI6c#%u DST:%pI6c#%u",
			state->jool.iname, proto,
			&hdr6->saddr, be16_to_cpu(sport),
			&hdr6->daddr, be16_to_cpu(dport));
}

void pkt_trace6(struct xlation *state)
{
	struct ipv6hdr *hdr6;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct icmp6hdr *icmp;
	} ptr;

	hdr6 = pkt_ip6_hdr(&state->in);

	switch (pkt_l4_proto(&state->in)) {
	case L4PROTO_TCP:
		ptr.tcp = pkt_tcp_hdr(&state->in);
		trace6_ports(state, "TCP", hdr6, ptr.tcp->source, ptr.tcp->dest);
		break;
	case L4PROTO_UDP:
		ptr.udp = pkt_udp_hdr(&state->in);
		trace6_ports(state, "UDP", hdr6, ptr.udp->source, ptr.udp->dest);
		break;
	case L4PROTO_ICMP:
		ptr.icmp = pkt_icmp6_hdr(&state->in);
		log_info("INSTANCE:%s PROTO:IPv6/ICMP SRC:%pI6c DST:%pI6c TYPE:%u CODE:%u",
				state->jool.iname,
				&hdr6->saddr, &hdr6->daddr,
				ptr.icmp->icmp6_type, ptr.icmp->icmp6_code);
		break;
	default:
		log_info("INSTANCE:%s PROTO:IPv6/? SRC:%pI6c DST:%pI6c",
				state->jool.iname, &hdr6->saddr, &hdr6->daddr);
	}
}
