#include "mod/common/steps/compute_outgoing_tuple.h"

#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/db/eam.h"
#include "mod/common/db/rfc6791v4.h"
#include "mod/common/db/rfc6791v6.h"

verdict translate_addrs64_siit(struct xlation *state)
{
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(&state->in);
	struct result_addrxlat64 src, dst;
	struct addrxlat_result addr_result;

	/* Dst address. (SRC DEPENDS CON DST, SO WE NEED TO XLAT DST FIRST!) */
	addr_result = addrxlat_siit64(&state->jool, &hdr6->daddr, &dst);
	if (addr_result.reason)
		log_debug("%s.", addr_result.reason);

	switch (addr_result.verdict) {
	case ADDRXLAT_CONTINUE:
		state->out.tuple.dst.addr4.l3 = dst.addr;
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		return untranslatable(state, JSTAT64_SRC);
	case ADDRXLAT_ACCEPT:
		return untranslatable(state, JSTAT64_SRC);
	case ADDRXLAT_DROP:
		return drop(state, JSTAT_UNKNOWN);
	}

	/* Src address. */
	addr_result = addrxlat_siit64(&state->jool, &hdr6->saddr, &src);
	if (addr_result.reason)
		log_debug("%s.", addr_result.reason);

	switch (addr_result.verdict) {
	case ADDRXLAT_CONTINUE:
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		if (pkt_is_icmp6_error(&state->in)
				&& !rfc6791v4_find(state, &src.addr)) {
			src.entry.method = AXM_RFC6791;
			break; /* Ok, success. */
		}
		return untranslatable(state, JSTAT64_DST);
	case ADDRXLAT_ACCEPT:
		return untranslatable(state, JSTAT64_DST);
	case ADDRXLAT_DROP:
		return drop(state, JSTAT_UNKNOWN);
	}

	state->out.tuple.src.addr4.l3 = src.addr;

	/*
	 * Mark intrinsic hairpinning if it's going to be needed.
	 * Why here? It's the only place where we know whether RFC 6052 was
	 * involved.
	 */
	if (state->jool.globals.siit.eam_hairpin_mode == EHM_INTRINSIC) {
		struct eam_table *eamt = state->jool.siit.eamt;
		/* Condition set A */
		if (pkt_is_outer(&state->in) && !pkt_is_icmp6_error(&state->in)
				&& (dst.entry.method == AXM_RFC6052)
				&& eamt_contains4(eamt, dst.addr.s_addr)) {
			state->out.is_hairpin = true;

		/* Condition set B */
		} else if (pkt_is_inner(&state->in)
				&& (src.entry.method == AXM_RFC6052)
				&& eamt_contains4(eamt, src.addr.s_addr)) {
			state->out.is_hairpin = true;
		}
	}

	log_debug("Result: %pI4->%pI4", &state->out.tuple.src.addr4.l3,
			&state->out.tuple.dst.addr4.l3);
	return VERDICT_CONTINUE;
}

static bool disable_src_eam(struct packet *in, bool hairpin)
{
	struct iphdr *inner_hdr;

	if (!hairpin || pkt_is_inner(in))
		return false;
	if (!pkt_is_icmp4_error(in))
		return true;

	inner_hdr = pkt_payload(in);
	return pkt_ip4_hdr(in)->saddr == inner_hdr->daddr;
}

static bool disable_dst_eam(struct packet *in, bool hairpin)
{
	return hairpin && pkt_is_inner(in);
}

verdict translate_addrs46_siit(struct xlation *state)
{
	struct packet *in = &state->in;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	bool is_hairpin;
	bool enable_blacklist;
	struct result_addrxlat46 addr6;
	struct addrxlat_result addr_result;

	is_hairpin = (state->jool.globals.siit.eam_hairpin_mode == EHM_SIMPLE)
			|| pkt_is_intrinsic_hairpin(in);
	enable_blacklist = !pkt_is_icmp4_error(in);

	/* Dst address. (SRC DEPENDS CON DST, SO WE NEED TO XLAT DST FIRST!) */
	addr_result = addrxlat_siit46(&state->jool, hdr4->daddr, &addr6,
			!disable_dst_eam(in, is_hairpin), enable_blacklist);
	if (addr_result.reason)
		log_debug("%s.", addr_result.reason);

	switch (addr_result.verdict) {
	case ADDRXLAT_CONTINUE:
		state->out.tuple.dst.addr6.l3 = addr6.addr;
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		return untranslatable(state, JSTAT46_DST);
	case ADDRXLAT_ACCEPT:
		return untranslatable(state, JSTAT46_DST);
	case ADDRXLAT_DROP:
		return drop(state, JSTAT_UNKNOWN);
	}

	/* Src address. */
	addr_result = addrxlat_siit46(&state->jool, hdr4->saddr, &addr6,
			!disable_src_eam(in, is_hairpin), enable_blacklist);
	if (addr_result.reason)
		log_debug("%s.", addr_result.reason);

	switch (addr_result.verdict) {
	case ADDRXLAT_CONTINUE:
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		if (pkt_is_icmp4_error(in)
				&& !rfc6791v6_find(state, &addr6.addr)) {
			addr6.entry.method = AXM_RFC6791;
			break; /* Ok, success. */
		}
		return untranslatable(state, JSTAT46_SRC);
	case ADDRXLAT_ACCEPT:
		return untranslatable(state, JSTAT46_SRC);
	case ADDRXLAT_DROP:
		return drop(state, JSTAT_UNKNOWN);
	}

	state->out.tuple.src.addr6.l3 = addr6.addr;

	log_debug("Result: %pI6c->%pI6c", &state->out.tuple.src.addr6.l3,
			&state->out.tuple.dst.addr6.l3);
	return VERDICT_CONTINUE;
}

verdict compute_out_tuple_siit(struct xlation *state)
{
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
	} hdr;
	__be16 sport;
	__be16 dport;

	log_debug("Translating addresses...");

	state->out.tuple.l4_proto = pkt_l4_proto(&state->in);

	switch (state->out.tuple.l4_proto) {
	case L4PROTO_TCP:
		hdr.tcp = pkt_tcp_hdr(&state->in);
		sport = hdr.tcp->source;
		dport = hdr.tcp->dest;
		break;
	case L4PROTO_UDP:
		hdr.udp = pkt_udp_hdr(&state->in);
		sport = hdr.udp->source;
		dport = hdr.udp->dest;
		break;
	default:
		sport = 0;
		dport = 0;
		break;
	}

	switch (pkt_l3_proto(&state->in)) {
	case L3PROTO_IPV6: /* 6 -> 4 */
		state->out.tuple.l3_proto = L3PROTO_IPV4;
		state->out.tuple.src.addr4.l4 = sport;
		state->out.tuple.dst.addr4.l4 = dport;
		return translate_addrs64_siit(state);
	case L3PROTO_IPV4: /* 4 -> 6 */
		state->out.tuple.l3_proto = L3PROTO_IPV6;
		state->out.tuple.src.addr6.l4 = sport;
		state->out.tuple.dst.addr6.l4 = dport;
		return translate_addrs46_siit(state);
	}

	WARN(1, "Unknown l3 protocol: %d", pkt_l3_proto(&state->in));
	return drop(state, JSTAT_UNKNOWN);
}
