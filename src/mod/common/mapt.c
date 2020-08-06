#include "mod/common/mapt.h"

#include "common/types.h"
#include "mod/common/address.h"
#include "mod/common/log.h"
#include "mod/common/rfc6052.h"

static unsigned int addr6_get_bits(struct in6_addr *addr, unsigned int offset,
		unsigned int len)
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
		addr6_set_bit(addr, offset + i, (value >> (len - i - 1)) & 1u);
}

static unsigned int addr4_get_bits(struct in_addr *addr, unsigned int offset,
		unsigned int len)
{
	unsigned int i;
	unsigned int result;

	result = 0;
	for (i = 0; i < len; i++)
		if (addr4_get_bit(addr, i + offset))
			result |= 1 << (len - i - 1);

	return result;
}

static int init_prpf(struct port_restricted_port_field *prpf,
		unsigned int a, unsigned int k)
{
	if (a + k > 16) {
		log_err("a + k = %u + %u > 16, which is illegal.", a, k);
		return -EINVAL;
	}

	prpf->a = a;
	prpf->k = k;
	prpf->m = 16 - a - k;
	return 0;
}

static void init_map_ce_addr6(struct ipv6_prefix *eui6p,
		struct mapping_rule *bmr,
		unsigned int psid_arg,
		struct in6_addr *map_ce_addr6)
{
	unsigned int ea_bits_offset;
	unsigned int p; /* IPv4 suffix bits (from BMR) */
	struct in_addr ipv4_address;
	unsigned int psid;
	__u32 addr4;

	ea_bits_offset = bmr->prefix6.len;
	p = 32 - bmr->prefix4.len;
	ipv4_address.s_addr = bmr->prefix4.addr.s_addr | cpu_to_be32(
		addr6_get_bits(&eui6p->addr, ea_bits_offset, p)
	);

	if (eui6p->len - bmr->prefix6.len != 0) {
		psid = addr6_get_bits(&eui6p->addr,
				ea_bits_offset + p,
				/*
				 * Warning: If we're going to end up computing
				 * it anyway, what the fuck is the point of
				 * including the EA-bit length in the BMR?
				 * This should just be
				 * `psid_len = bmr.ea_bit_length - p`.
				 * Or better yet: `psid_len = prpfm.k`.
				 */
				(eui6p->len - bmr->prefix6.len) - p);
	} else {
		psid = psid_arg;
	}

	memcpy(map_ce_addr6, &eui6p->addr, sizeof(eui6p->addr));
	addr4 = be32_to_cpu(ipv4_address.s_addr);
	map_ce_addr6->s6_addr16[5] = cpu_to_be16(addr4 >> 16u);
	map_ce_addr6->s6_addr16[6] = cpu_to_be16(addr4 & 0xFFFFu);
	map_ce_addr6->s6_addr16[7] = cpu_to_be16(psid);
}

int mapt_init(struct jool_globals *config,
		struct ipv6_prefix *euip, struct mapping_rule *bmr,
		unsigned int a, unsigned int k)
{
	int error;

	memset(&config->mapt, 0, sizeof(config->mapt));

	error = init_prpf(&config->mapt.prpf, a, k);
	if (error)
		return error;

	if (euip && bmr)
		/* TODO (mapt post test) psid override */
		init_map_ce_addr6(euip, bmr, 0, &config->mapt.map_ce_addr6);

	/* TODO (mapt fmr) */
	config->mapt.fmr.prefix6.addr.s6_addr32[0] = cpu_to_be32(0x20010db8);
	config->mapt.fmr.prefix6.addr.s6_addr32[1] = 0;
	config->mapt.fmr.prefix6.addr.s6_addr32[2] = 0;
	config->mapt.fmr.prefix6.addr.s6_addr32[3] = 0;
	config->mapt.fmr.prefix6.len = 40;
	config->mapt.fmr.prefix4.addr.s_addr = cpu_to_be32(0xc0000200);
	config->mapt.fmr.prefix4.len = 24;
	config->mapt.fmr.ea_bit_length = 16;

	return 0;
}

static unsigned int prpf_get_psid(struct xlation const *state,
		unsigned int port)
{
	struct port_restricted_port_field const *prpf;
	prpf = &state->jool.globals.mapt.prpf;
	/*
	 * This is an optimized version of the
	 * 	PSID = trunc((P modulo (R * M)) / M)
	 * equation. (See rfc7597#appendix-B.)
	 */
	return (port & (((1u << prpf->k) << prpf->m) - 1u)) >> prpf->m;
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

static int use_pool6_46(struct xlation const *state, __be32 in,
		struct in6_addr *out)
{
	struct in_addr __in;
	struct result_addrxlat46 __out;
	int error;

	if (!state->jool.globals.pool6.set) {
		log_debug(state, "Cannot translate address: The DMR (pool6) is unset.");
		return untranslatable(state, JSTAT_POOL6_UNSET);
	}

	__in.s_addr = in;

	error = rfc6052_4to6(&state->jool.globals.pool6.prefix, &__in, &__out);
	if (error)
		log_debug(state, "rfc6052_4to6() error: %d", error);

	*out = __out.addr;
	log_debug(state, "Address: %pI6c", out);
	return error;
}

static int ce46_src(struct xlation const *state, __be32 in,
		struct in6_addr *out)
{
	unsigned int psid;

	/* PSID */
	psid = prpf_get_psid(state, get_sport(&state->in));
	if (psid != be16_to_cpu(state->jool.globals.mapt.map_ce_addr6.s6_addr16[7])) {
		/* TODO (mapt) ICMP error and stuff */
		log_debug(state, "Bad source port.");
		return -EINVAL;
	}

	*out = state->jool.globals.mapt.map_ce_addr6;
	log_debug(state, "IPv6 source address: %pI6c", out);
	return 0;
}

static int ce46_dst(struct xlation const *state, __be32 in, struct in6_addr *out)
{
	return use_pool6_46(state, in, out);
}

static int br46_src(struct xlation const *state, __be32 in,
		struct in6_addr *out)
{
	return use_pool6_46(state, in, out);
}

static int br46_dst(struct xlation const *state, __be32 in,
		struct in6_addr *out)
{
	unsigned int p;
	unsigned int q;
	unsigned int psid;
	union {
		__u32 u32;
		struct in_addr addr;
	} __in;
	struct mapping_rule fmr;

	/* TODO (mapt fmr) */
	fmr = state->jool.globals.mapt.fmr;

	/* IPv6 prefix */
	memcpy(out, &fmr.prefix6.addr, sizeof(fmr.prefix6.addr));

	/* IPv4 suffix */
	p = 32 - fmr.prefix4.len;
	__in.addr.s_addr = in;
	addr6_set_bits(out, fmr.prefix6.len, p, addr4_get_bits(&__in.addr,
			fmr.prefix4.len, p));

	/* PSID */
	psid = prpf_get_psid(state, get_dport(&state->in));
	q = fmr.ea_bit_length - p;
	addr6_set_bits(out, fmr.prefix6.len + p, q, psid);

	/* IPv4 address */
	__in.u32 = be32_to_cpu(in);
	out->s6_addr16[5] = cpu_to_be16(__in.u32 >> 16u);
	out->s6_addr16[6] = cpu_to_be16(__in.u32 & 0xFFFFu);

	/* PSID again */
	out->s6_addr16[7] = cpu_to_be16(psid);

	log_debug(state, "IPv6 destination address: %pI6c", out);
	return 0;
}

int translate_addrs46_mapt(struct xlation const *state,
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

static int use_pool6_64(struct xlation const *state, struct in6_addr const *in,
		__be32 *out)
{
	struct result_addrxlat64 __out;
	int error;

	if (!state->jool.globals.pool6.set) {
		/* TODO (mapt) ICMP error and stuff */
		log_debug(state, "Cannot translate address: The DMR (pool6) is unset.");
		return -EINVAL;
	}

	error = rfc6052_6to4(&state->jool.globals.pool6.prefix, in, &__out);
	if (error)
		log_debug(state, "rfc6052_4to6() error: %d", error);

	*out = __out.addr.s_addr;
	log_debug(state, "Address: %pI6c", out);
	return error;
}

static void extract_addr_64(struct in6_addr const *in, __be32 *out)
{
	*out = cpu_to_be32((be16_to_cpu(in->s6_addr16[5]) << 16u)
			| be16_to_cpu(in->s6_addr16[6]));
}

static int ce64_src(struct xlation const *state, struct in6_addr const *in,
		__be32 *out)
{
	return use_pool6_64(state, in, out);
}

static int ce64_dst(struct xlation const *state, struct in6_addr const *in,
		__be32 *out)
{
	if (!addr6_equals(in, &state->jool.globals.mapt.map_ce_addr6)) {
		/* TODO (mapt) ICMP error and stuff */
		log_debug(state, "Packet's destination address does not match MAP CE address.");
		return -EINVAL;
	}

	extract_addr_64(in, out);
	log_debug(state, "Address: %pI4", out);
	return 0;
}

static int br64_src(struct xlation const *state, struct in6_addr const *in,
		__be32 *out)
{
	struct mapping_rule fmr;

	/* TODO (mapt fmr) */
	fmr = state->jool.globals.mapt.fmr;
	if (!prefix6_contains(&fmr.prefix6, in)) {
		/* TODO (mapt) ICMP error and stuff */
		log_debug(state, "Cannot translate address: No FMR matches '%pI6c'.", in);
		return -EINVAL;
	}

	extract_addr_64(in, out);
	log_debug(state, "Address: %pI4", out);
	return 0;
}

static int br64_dst(struct xlation const *state, struct in6_addr const *in,
		__be32 *out)
{
	return use_pool6_64(state, in, out);
}

int translate_addrs64_mapt(struct xlation const *state, __be32 *out_src,
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
