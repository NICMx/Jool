#include "mod/common/mapt.h"

#include "common/types.h"
#include "mod/common/address.h"
#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/rfc6052.h"
#include "mod/common/db/fmr.h"

static unsigned int get_o(struct mapping_rule *rule)
{
	return rule->ea_bits_length;
}

static unsigned int get_p(struct mapping_rule *rule)
{
	unsigned int o;
	unsigned int p;

	o = get_o(rule);
	p = 32u - rule->prefix4.len;

	return (o > p) ? p : o;
}

static unsigned int get_q(struct mapping_rule *rule)
{
	return get_o(rule) - get_p(rule);
}

static verdict prpf_get_psid(struct xlation *state,
		struct mapping_rule *rule,
		unsigned int port,
		unsigned int *psid)
{
	unsigned int a;
	unsigned int k;
	unsigned int m;

	a = rule->a;
	k = get_q(rule);

	if ((a + k) > 16u) {
		log_debug(state, "Bad Port-Restricted Port Field: `a + k = %u + %u > 16` (`k = o - p = %u - %u`).",
				a, k, get_o(rule), get_p(rule));
		return drop(state, JSTAT_MAPT_BAD_PRPF);
	}

	m = 16u - a - k;

	/*
	 * This is an optimized version of the
	 * 	PSID = trunc((P modulo (R * M)) / M)
	 * equation. (See rfc7597#appendix-B.)
	 * It assumes R and M are powers of 2. I don't really plan on allowing
	 * otherwise for the purposes of this implementation.
	 */
	*psid = (port & (((1u << k) << m) - 1u)) >> m;
	return VERDICT_CONTINUE;
}

static unsigned int get_sport(struct packet const *pkt)
{
	switch (pkt->l4_proto) {
	case L4PROTO_TCP:
		return be16_to_cpu(pkt_tcp_hdr(pkt)->source);
	case L4PROTO_UDP:
		return be16_to_cpu(pkt_udp_hdr(pkt)->source);
	case L4PROTO_ICMP:
	case L4PROTO_OTHER:
		/* TODO (mapt) */
		;
	}

	return 0;
}

static unsigned int get_dport(struct packet const *pkt)
{
	switch (pkt->l4_proto) {
	case L4PROTO_TCP:
		return be16_to_cpu(pkt_tcp_hdr(pkt)->dest);
	case L4PROTO_UDP:
		return be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	case L4PROTO_ICMP:
	case L4PROTO_OTHER:
		/* TODO (mapt) */
		;
	}

	return 0;
}

static verdict use_pool6_46(struct xlation *state, __be32 in,
		struct in6_addr *out)
{
	struct in_addr __in;
	int error;

	if (!state->jool.globals.pool6.set) {
		log_debug(state, "Cannot translate address: The DMR (pool6) is unset.");
		return untranslatable(state, JSTAT_POOL6_UNSET);
	}

	__in.s_addr = in;
	error = __rfc6052_4to6(&state->jool.globals.pool6.prefix, &__in, out);
	if (error) {
		log_debug(state, "__rfc6052_4to6() error: %d", error);
		return drop(state, JSTAT_UNKNOWN);
	}

	log_debug(state, "Address: %pI6c", out);
	return VERDICT_CONTINUE;
}

static void set_interface_id(__be32 in, struct in6_addr *out, unsigned int psid)
{
	__u32 addr4 = be32_to_cpu(in);
	out->s6_addr16[5] = cpu_to_be16(addr4 >> 16u);
	out->s6_addr16[6] = cpu_to_be16(addr4 & 0xFFFFu);
	out->s6_addr16[7] = cpu_to_be16(psid);
}

static verdict ce46_src(struct xlation *state, __be32 in, struct in6_addr *out)
{
	struct mapt_globals *cfg;
	unsigned int q;
	unsigned int packet_psid;
	unsigned int ce_psid;
	verdict result;

	cfg = &state->jool.globals.mapt;
	q = get_q(&cfg->bmr);
	packet_psid = 0;

	/* Check the NAPT made sure the port belongs to us */
	if (q > 0) {
		result = prpf_get_psid(state, &cfg->bmr, get_sport(&state->in),
				&packet_psid);
		if (result != VERDICT_CONTINUE)
			return result;

		ce_psid = addr6_get_bits(&cfg->eui6p.addr,
				cfg->bmr.prefix6.len + get_p(&cfg->bmr), q);

		if (packet_psid != ce_psid) {
			log_debug(state, "IPv4 packet's source port does not match the PSID assigned to this CE.");
			return untranslatable(state, JSTAT_MAPT_PSID);
		}
	}

	memcpy(out, &cfg->eui6p.addr, sizeof(cfg->eui6p.addr));
	set_interface_id(in, out, packet_psid);

	return VERDICT_CONTINUE;
}

EXPORT_UNIT_STATIC verdict rule_xlat46(struct xlation *state,
		struct mapping_rule *rule, __be32 in, unsigned int port,
		struct in6_addr *out)
{
	unsigned int p;
	unsigned int q;
	unsigned int psid;
	struct in_addr addr4;
	verdict result;

	/* IPv6 prefix */
	memcpy(out, &rule->prefix6.addr, sizeof(rule->prefix6.addr));

	/* Embedded IPv4 suffix */
	p = get_p(rule);
	addr4.s_addr = in;
	addr6_set_bits(out, rule->prefix6.len, p,
		addr4_get_bits(&addr4, rule->prefix4.len, p)
	);

	/* PSID */
	q = get_q(rule);
	psid = 0;
	if (q > 0) {
		result = prpf_get_psid(state, rule, port, &psid);
		if (result != VERDICT_CONTINUE)
			return result;
		addr6_set_bits(out, rule->prefix6.len + p, q, psid);
	}

	/* Interface ID */
	set_interface_id(in, out, psid);

	return VERDICT_CONTINUE;
}
EXPORT_UNIT_SYMBOL(rule_xlat46);

static verdict ce46_dst(struct xlation *state, __be32 in, struct in6_addr *out)
{
	struct mapping_rule fmr;
	int error;

	error = fmrt_find4(state->jool.mapt.fmrt, in, &fmr);
	switch (error) {
	case 0:
		return rule_xlat46(state, &fmr, in, get_dport(&state->in), out);
	case -ESRCH:
		return use_pool6_46(state, in, out);
	}

	WARN(1, "Unknown fmrt_find4() result: %d", error);
	return drop(state, JSTAT_UNKNOWN);
}

static verdict br46_src(struct xlation *state, __be32 in, struct in6_addr *out)
{
	return use_pool6_46(state, in, out);
}

static verdict br46_dst(struct xlation *state, __be32 in, struct in6_addr *out)
{
	struct mapping_rule fmr;
	int error;

	error = fmrt_find4(state->jool.mapt.fmrt, in, &fmr);
	switch (error) {
	case 0:
		return rule_xlat46(state, &fmr, in, get_dport(&state->in), out);
	case -ESRCH:
		log_debug(state, "Cannot translate address: No FMR matches '%pI4'.", &in);
		return untranslatable(state, JSTAT_MAPT_FMR4);
	}

	WARN(1, "Unknown fmrt_find4() result: %d", error);
	return drop(state, JSTAT_UNKNOWN);
}

verdict translate_addrs46_mapt(struct xlation *state,
		struct in6_addr *out_src,
		struct in6_addr *out_dst)
{
	struct iphdr *in = pkt_ip4_hdr(&state->in);

	switch (state->jool.globals.mapt.type) {
	case MAPTYPE_CE:
		return ce46_src(state, in->saddr, out_src)
		    || ce46_dst(state, in->daddr, out_dst);
	case MAPTYPE_BR:
		return br46_src(state, in->saddr, out_src)
		    || br46_dst(state, in->daddr, out_dst);
	}

	log_debug(state, "Unknown MAP type: %d", state->jool.globals.mapt.type);
	return drop(state, JSTAT_UNKNOWN);
}
EXPORT_UNIT_SYMBOL(translate_addrs46_mapt);

static verdict use_pool6_64(struct xlation *state, struct in6_addr const *in,
		__be32 *out)
{
	struct in_addr __out;
	int error;

	if (!state->jool.globals.pool6.set) {
		log_debug(state, "Cannot translate address: The DMR (pool6) is unset.");
		return untranslatable(state, JSTAT_MAPT_POOL6);
	}

	error = __rfc6052_6to4(&state->jool.globals.pool6.prefix, in, &__out);
	if (error) {
		log_debug(state, "__rfc6052_6to4() error: %d", error);
		return untranslatable(state, JSTAT_MAPT_POOL6);
	}

	*out = __out.s_addr;
	return VERDICT_CONTINUE;
}

static void extract_addr_64(struct mapping_rule *rule,
		struct in6_addr const *in,
		__be32 *out)
{
	*out = rule->prefix4.addr.s_addr | cpu_to_be32(
		addr6_get_bits(in, rule->prefix6.len, get_p(rule))
	);
}

static verdict ce64_src(struct xlation *state, struct in6_addr const *in,
		__be32 *out)
{
	struct mapping_rule fmr;
	int error;

	error = fmrt_find6(state->jool.mapt.fmrt, in, &fmr);
	switch (error) {
	case 0:
		extract_addr_64(&fmr, in, out);
		return VERDICT_CONTINUE;
	case -ESRCH:
		return use_pool6_64(state, in, out);
	}

	WARN(1, "Unknown fmrt_find6() result: %d", error);
	return drop(state, JSTAT_UNKNOWN);
}

static verdict ce64_dst(struct xlation *state, struct in6_addr const *in,
		__be32 *out)
{
	struct mapt_globals *cfg = &state->jool.globals.mapt;

	if (!prefix6_contains(&cfg->eui6p, in)) {
		log_debug(state, "Packet's destination address does not match the End-User IPv6 Prefix.");
		return untranslatable(state, JSTAT_MAPT_EUI6P);
	}

	extract_addr_64(&cfg->bmr, in, out);
	return VERDICT_CONTINUE;
}

static verdict br64_src(struct xlation *state, struct in6_addr const *in,
		__be32 *out)
{
	struct mapping_rule fmr;
	int error;

	error = fmrt_find6(state->jool.mapt.fmrt, in, &fmr);
	switch (error) {
	case 0:
		extract_addr_64(&fmr, in, out);
		return VERDICT_CONTINUE;
	case -ESRCH:
		log_debug(state, "Cannot translate address: No FMR matches '%pI6c'.", in);
		return untranslatable(state, JSTAT_MAPT_FMR6);
	}

	WARN(1, "Unknown fmrt_find6() result: %d", error);
	return drop(state, JSTAT_UNKNOWN);
}

static verdict br64_dst(struct xlation *state, struct in6_addr const *in,
		__be32 *out)
{
	return use_pool6_64(state, in, out);
}

verdict translate_addrs64_mapt(struct xlation *state, __be32 *out_src,
		__be32 *out_dst)
{
	struct ipv6hdr *in = pkt_ip6_hdr(&state->in);

	switch (state->jool.globals.mapt.type) {
	case MAPTYPE_CE:
		return ce64_src(state, &in->saddr, out_src)
		    || ce64_dst(state, &in->daddr, out_dst);
	case MAPTYPE_BR:
		return br64_src(state, &in->saddr, out_src)
		    || br64_dst(state, &in->daddr, out_dst);
	}

	log_debug(state, "Unknown MAP type: %d", state->jool.globals.mapt.type);
	return drop(state, JSTAT_UNKNOWN);
}
EXPORT_UNIT_SYMBOL(translate_addrs64_mapt);
