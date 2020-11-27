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

/*
 * Note: The definition of p is inconsistent through the RFC. The two
 * definitions are
 *
 * 1. p = length of the IPv4 suffix contained in the EA bit field.
 * 2. p = length of the IPv4 suffix.
 *
 * I went with the second one; it's the most useful for the implementation ATM.
 */
static unsigned int get_p(struct mapping_rule *rule)
{
	return 32u - rule->prefix4.len;
}

static unsigned int get_q(struct mapping_rule *rule)
{
	if (rule->prefix4.len + rule->ea_bits_length <= 32)
		return 0;
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
	unsigned int offset;
	unsigned int len;
	verdict result;

	cfg = &state->jool.globals.mapt;
	q = get_q(&cfg->bmr);
	packet_psid = 0;

	/* Check the NAPT made sure the port belongs to us */
	if (q > 0) {
		result = prpf_get_psid(state, &cfg->bmr,
				state->in.tuple.src.addr4.l4, &packet_psid);
		if (result != VERDICT_CONTINUE)
			return result;

		ce_psid = addr6_get_bits(&cfg->eui6p.addr,
				cfg->bmr.prefix6.len + get_p(&cfg->bmr), q);

		if (packet_psid != ce_psid) {
			log_debug(state, "IPv4 packet's source port does not match the PSID assigned to this CE.");
			return untranslatable(state, JSTAT_MAPT_PSID);
		}
	}

	/*
	 * Interface ID
	 * (The IID can be overridden by everything else, so write it first.)
	 */
	set_interface_id(in, out, packet_psid);

	/*
	 * BMR's IPv6 prefix
	 * (Do not copy the End-user IPv6 Prefix; it's wrong when o + r < 32
	 * because it contains trailing zeroes.)
	 */
	offset = 0;
	len = cfg->bmr.prefix6.len;
	addr6_copy_bits(&cfg->bmr.prefix6.addr, out, offset, len);

	/* IPv4 address suffix */
	offset += len;
	len = get_p(&cfg->bmr);
	addr6_set_bits(out, offset, len,
		addr4_get_bits(in, cfg->bmr.prefix4.len, len)
	);

	/* PSID */
	offset += len;
	len = q;
	addr6_set_bits(out, offset, len, packet_psid);

	return VERDICT_CONTINUE;
}

EXPORT_UNIT_STATIC verdict rule_xlat46(struct xlation *state,
		struct mapping_rule *rule, __be32 in, unsigned int port,
		struct in6_addr *out)
{
	unsigned int p;
	unsigned int q;
	unsigned int psid;
	verdict result;

	/* IPv6 prefix */
	memcpy(out, &rule->prefix6.addr, sizeof(rule->prefix6.addr));

	/* Embedded IPv4 suffix */
	p = get_p(rule);
	addr6_set_bits(out, rule->prefix6.len, p,
		addr4_get_bits(in, rule->prefix4.len, p)
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
	/* TODO this needs to be done first */
	set_interface_id(in, out, psid);

	return VERDICT_CONTINUE;
}
EXPORT_UNIT_SYMBOL(rule_xlat46);

static verdict ce46_dst(struct xlation *state, __be32 in, struct in6_addr *out)
{
	struct mapping_rule fmr;
	int error;
	verdict result;

	error = fmrt_find4(state->jool.mapt.fmrt, in, &fmr);
	switch (error) {
	case 0:
		result = rule_xlat46(state, &fmr, in,
				state->in.tuple.dst.addr4.l4, out);
		if (result == VERDICT_CONTINUE)
			if (prefix6_contains(&state->jool.globals.mapt.eui6p, out))
				state->is_hairpin_1 = true;
		return result;
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
		return rule_xlat46(state, &fmr, in,
				state->in.tuple.dst.addr4.l4, out);
	case -ESRCH:
		log_debug(state, "Cannot translate address: No FMR matches '%pI4'.", &in);
		return untranslatable(state, JSTAT_MAPT_FMR4);
	}

	WARN(1, "Unknown fmrt_find4() result: %d", error);
	return drop(state, JSTAT_UNKNOWN);
}

typedef verdict (*xlat46_cb)(struct xlation *, __be32, struct in6_addr *);

verdict translate_addrs46_mapt(struct xlation *state, struct in6_addr *out_src,
		struct in6_addr *out_dst, bool invert)
{
	struct iphdr *in = pkt_ip4_hdr(&state->in);
	xlat46_cb src_cb;
	xlat46_cb dst_cb;
	verdict result;

	switch (state->jool.globals.mapt.type) {
	case MAPTYPE_CE:
		src_cb = invert ? ce46_dst : ce46_src;
		dst_cb = invert ? ce46_src : ce46_dst;
		break;
	case MAPTYPE_BR:
		src_cb = invert ? br46_dst : br46_src;
		dst_cb = invert ? br46_src : br46_dst;
		break;
	default:
		log_debug(state, "Unknown MAP type: %d",
				state->jool.globals.mapt.type);
		return drop(state, JSTAT_UNKNOWN);
	}

	result = src_cb(state, in->saddr, out_src);
	if (result != VERDICT_CONTINUE)
		return result;
	return dst_cb(state, in->daddr, out_dst);
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

	/* TODO (mapt) this probably only works for external packets */
	if (state->jool.globals.mapt.type == MAPTYPE_BR &&
	    fmrt_find4(state->jool.mapt.fmrt, __out.s_addr, NULL) == 0)
		state->is_hairpin_1 = true;

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

typedef verdict (*xlat64_cb)(struct xlation *, struct in6_addr const *, __be32 *);

verdict translate_addrs64_mapt(struct xlation *state, __be32 *out_src,
		__be32 *out_dst, bool invert)
{
	struct ipv6hdr *in = pkt_ip6_hdr(&state->in);
	xlat64_cb src_cb;
	xlat64_cb dst_cb;
	verdict result;

	switch (state->jool.globals.mapt.type) {
	case MAPTYPE_CE:
		src_cb = invert ? ce64_dst : ce64_src;
		dst_cb = invert ? ce64_src : ce64_dst;
		break;
	case MAPTYPE_BR:
		src_cb = invert ? br64_dst : br64_src;
		dst_cb = invert ? br64_src : br64_dst;
		break;
	default:
		log_debug(state, "Unknown MAP type: %d",
				state->jool.globals.mapt.type);
		return drop(state, JSTAT_UNKNOWN);
	}

	result = src_cb(state, &in->saddr, out_src);
	if (result != VERDICT_CONTINUE)
		return result;
	return dst_cb(state, &in->daddr, out_dst);
}
EXPORT_UNIT_SYMBOL(translate_addrs64_mapt);
