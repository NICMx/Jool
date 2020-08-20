#include "mod/common/mapt.h"

#include "common/types.h"
#include "mod/common/address.h"
#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/rfc6052.h"
#include "mod/common/db/fmr.h"

static unsigned int addr6_get_bits(struct in6_addr const *addr,
		unsigned int offset, unsigned int len)
{
	unsigned int i;
	unsigned int result;

	result = 0;
	for (i = 0; i < len; i++)
		if (addr6_get_bit(addr, i + offset))
			result |= 1 << (len - i - 1);

	return result;
}

static void addr6_set_bits(struct in6_addr *addr, unsigned int offset,
		unsigned int len, unsigned int value)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		addr6_set_bit(addr, offset + i, (value >> (len - i - 1u)) & 1u);
}

static unsigned int addr4_get_suffix(struct in_addr const *addr,
		unsigned int suffix_len)
{
	return be32_to_cpu(addr->s_addr) & ((1u << suffix_len) - 1u);
}

/* TODO (mapt post test) missing PSID override */
int mapt_init(struct mapt_globals *cfg,
		struct ipv6_prefix *eui6p, struct mapping_rule *bmr,
		unsigned int a, unsigned int k)
{
	memset(cfg, 0, sizeof(*cfg));

	cfg->prpf.a = a;
	cfg->prpf.k = k;
	if (eui6p) {
		cfg->ce = true;
		cfg->eui6p = *eui6p;
	}
	if (bmr) {
		cfg->ce = true;
		cfg->bmr = *bmr;
	}

	return 0;
}
EXPORT_UNIT_SYMBOL(mapt_init);

static verdict get_m(struct xlation *state, struct mapping_rule *rule,
		unsigned int *m)
{
	struct port_restricted_port_field *prpf;
	unsigned int o;
	unsigned int r;
	unsigned int P;

	prpf = &state->jool.globals.mapt.prpf;
	o = rule->ea_bits_length;
	r = rule->prefix4.len;
	P = ((o + r < 32u) ? (32u - o - r) : 0) + 16u;

	if ((prpf->a + prpf->k) > P) {
		log_debug(state, "The values of a (%u) and k (%u) exceed the Port-Restricted Port Field length (%u) defined by mapping rule { *, %pI4c/%u, %u }.",
				prpf->a, prpf->k, P,
				&rule->prefix4.addr, rule->prefix4.len,
				rule->ea_bits_length);
		return drop(state, JSTAT_MAPT_BAD_P);
	}

	*m = P - prpf->a - prpf->k;
	return VERDICT_CONTINUE;
}

static verdict prpf_get_psid(struct xlation *state,
		struct mapping_rule *rule,
		unsigned int port,
		unsigned int *psid)
{
	unsigned int k;
	unsigned int m;
	verdict result;

	result = get_m(state, rule, &m);
	if (result != VERDICT_CONTINUE)
		return result;

	/*
	 * This is an optimized version of the
	 * 	PSID = trunc((P modulo (R * M)) / M)
	 * equation. (See rfc7597#appendix-B.)
	 * It assumes R and M are powers of 2. I don't really plan on allowing
	 * otherwise for the purposes of this implementation.
	 *
	 * TODO (mapt later) ensure m < 32
	 */
	k = state->jool.globals.mapt.prpf.k;
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

static verdict use_pool6_46(struct xlation *state, __be32 in, struct in6_addr *out)
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

static unsigned int get_p(struct mapping_rule *rule)
{
	return 32u - rule->prefix4.len;
}

static unsigned int get_q(struct mapping_rule *rule)
{
	return rule->ea_bits_length - get_p(rule);
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
	result = prpf_get_psid(state, &cfg->bmr, get_sport(&state->in),
			&packet_psid);
	if (result != VERDICT_CONTINUE)
		return result;

	/* Check the NAT made sure the port belongs to us */
	if (q > 0) {
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
	p = 32 - rule->prefix4.len;
	addr4.s_addr = in;
	addr6_set_bits(out, rule->prefix6.len, p, addr4_get_suffix(&addr4, p));

	/* PSID */
	result = prpf_get_psid(state, rule, port, &psid);
	if (result != VERDICT_CONTINUE)
		return result;
	q = rule->ea_bits_length - p;
	addr6_set_bits(out, rule->prefix6.len + p, q, psid);

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

	if (state->jool.globals.mapt.ce) {
		return ce46_src(state, in->saddr, out_src)
		    || ce46_dst(state, in->daddr, out_dst);
	} else {
		return br46_src(state, in->saddr, out_src)
		    || br46_dst(state, in->daddr, out_dst);
	}
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
		addr6_get_bits(in, 80 + rule->prefix4.len, get_p(rule))
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

	if (state->jool.globals.mapt.ce) {
		return ce64_src(state, &in->saddr, out_src)
		    || ce64_dst(state, &in->daddr, out_dst);
	} else {
		return br64_src(state, &in->saddr, out_src)
		    || br64_dst(state, &in->daddr, out_dst);
	}
}
EXPORT_UNIT_SYMBOL(translate_addrs64_mapt);
