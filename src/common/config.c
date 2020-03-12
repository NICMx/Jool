#include "common/config.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

struct nla_policy struct_list_policy[LA_COUNT] = {
	[LA_ENTRY] = { .type = NLA_NESTED }
};

struct nla_policy instance_entry_policy[IFEA_COUNT] = {
	[IFEA_NS] = { .type = NLA_U32 },
	[IFEA_XF] = { .type = NLA_U8 },
	[IFEA_INAME] = {
		.type = NLA_STRING,
#ifndef __KERNEL__
		.maxlen = INAME_MAX_SIZE
#endif
	},
};

struct nla_policy prefix6_policy[PA_COUNT] = {
	[PA_ADDR] = ADDR6_POLICY,
	[PA_LEN] = { .type = NLA_U8 },
};

struct nla_policy prefix4_policy[PA_COUNT] = {
	[PA_ADDR] = ADDR4_POLICY,
	[PA_LEN] = { .type = NLA_U8 },
};

struct nla_policy taddr6_policy[TAA_COUNT] = {
	[TAA_ADDR] = ADDR6_POLICY,
	[TAA_PORT] = { .type = NLA_U16 },
};

struct nla_policy taddr4_policy[TAA_COUNT] = {
	[TAA_ADDR] = ADDR4_POLICY,
	[TAA_PORT] = { .type = NLA_U16 },
};

struct nla_policy eam_policy[EA_COUNT] = {
	[EA_PREFIX6] = { .type = NLA_NESTED },
	[EA_PREFIX4] = { .type = NLA_NESTED },
};

struct nla_policy pool4_entry_policy[P4A_COUNT] = {
	[P4A_MARK] = { .type = NLA_U32 },
	[P4A_ITERATIONS] = { .type = NLA_U32 },
	[P4A_FLAGS] = { .type = NLA_U8 },
	[P4A_PROTO] = { .type = NLA_U8 },
	[P4A_PREFIX] = { .type = NLA_NESTED },
	[P4A_PORT_MIN] = { .type = NLA_U16 },
	[P4A_PORT_MAX] = { .type = NLA_U16 },
};

struct nla_policy bib_entry_policy[BA_COUNT] = {
	[BA_SRC6] = { .type = NLA_NESTED },
	[BA_SRC4] = { .type = NLA_NESTED },
	[BA_PROTO] = { .type = NLA_U8 },
	[BA_STATIC] = { .type = NLA_U8 },
};

struct nla_policy session_entry_policy[SEA_COUNT] = {
	[SEA_SRC6] = { .type = NLA_NESTED },
	[SEA_DST6] = { .type = NLA_NESTED },
	[SEA_SRC4] = { .type = NLA_NESTED },
	[SEA_DST4] = { .type = NLA_NESTED },
	[SEA_PROTO] = { .type = NLA_U8 },
	[SEA_STATE] = { .type = NLA_U8 },
	[SEA_TIMER] = { .type = NLA_U8 },
	[SEA_EXPIRATION] = { .type = NLA_U32 },
};

struct nla_policy siit_globals_policy[GA_COUNT] = {
	[GA_STATUS] = { .type = NLA_U8 },
	[GA_ENABLED] = { .type = NLA_U8 },
	[GA_TRACE] = { .type = NLA_U8 },
	[GA_POOL6] = { .type = NLA_UNSPEC },
	[GA_RESET_TC] = { .type = NLA_U8 },
	[GA_RESET_TOS] = { .type = NLA_U8 },
	[GA_TOS] = { .type = NLA_U8 },
	[GA_PLATEAUS] = { .type = NLA_NESTED },
	[GA_COMPUTE_CSUM_ZERO] = { .type = NLA_U8 },
	[GA_HAIRPIN_MODE] = { .type = NLA_U8 },
	[GA_RANDOMIZE_ERROR_ADDR] = { .type = NLA_U8 },
	[GA_POOL6791V6] = { .type = NLA_UNSPEC },
	[GA_POOL6791V4] = { .type = NLA_UNSPEC },
};

struct nla_policy nat64_globals_policy[GA_COUNT] = {
	[GA_STATUS] = { .type = NLA_U8 },
	[GA_ENABLED] = { .type = NLA_U8 },
	[GA_TRACE] = { .type = NLA_U8 },
	[GA_POOL6] = { .type = NLA_UNSPEC },
	[GA_RESET_TC] = { .type = NLA_U8 },
	[GA_RESET_TOS] = { .type = NLA_U8 },
	[GA_TOS] = { .type = NLA_U8 },
	[GA_PLATEAUS] = { .type = NLA_NESTED },
	[GA_DROP_ICMP6_INFO] = { .type = NLA_U8 },
	[GA_SRC_ICMP6_BETTER] = { .type = NLA_U8 },
	[GA_F_ARGS] = { .type = NLA_U8 },
	[GA_HANDLE_RST] = { .type = NLA_U8 },
	[GA_TTL_TCP_EST] = { .type = NLA_U32 },
	[GA_TTL_TCP_TRANS] = { .type = NLA_U32 },
	[GA_TTL_UDP] = { .type = NLA_U32 },
	[GA_TTL_ICMP] = { .type = NLA_U32 },
	[GA_BIB_LOGGING] = { .type = NLA_U8 },
	[GA_SESSION_LOGGING] = { .type = NLA_U8 },
	[GA_DROP_BY_ADDR] = { .type = NLA_U8 },
	[GA_DROP_EXTERNAL_TCP] = { .type = NLA_U8 },
	[GA_MAX_STORED_PKTS] = { .type = NLA_U32 },
	[GA_JOOLD_ENABLED] = { .type = NLA_U8 },
	[GA_JOOLD_FLUSH_ASAP] = { .type = NLA_U8 },
	[GA_JOOLD_FLUSH_DEADLINE] = { .type = NLA_U32 },
	[GA_JOOLD_CAPACITY] = { .type = NLA_U32 },
	[GA_JOOLD_MAX_PAYLOAD] = { .type = NLA_U32 },
};

struct nla_policy plateau_list_policy[LA_COUNT] = {
	[LA_ENTRY] = { .type = NLA_U16 }
};

/* Note: assumes strlen(iname) < INAME_MAX_SIZE */
void init_request_hdr(struct joolnlhdr *hdr, xlator_type xt, char const *iname,
		__u8 flags)
{
	hdr->version = htonl(xlat_version());
	hdr->xt = xt;
	hdr->flags = flags;
	hdr->reserved1 = 0;
	hdr->reserved2 = 0;
	memset(hdr->iname, 0, sizeof(hdr->iname));
	strcpy(hdr->iname, iname ? iname : "default");
}

/* TODO duplicate code (src/usr/iptables/common.c) */
int iname_validate(const char *iname, bool allow_null)
{
	unsigned int i;

	if (!iname)
		return allow_null ? 0 : -EINVAL;

	for (i = 0; i < INAME_MAX_SIZE; i++) {
		if (iname[i] == '\0')
			return 0;
		if (iname[i] < 32) /* "if not printable" */
			break;
	}

	return -EINVAL;
}

int xt_validate(xlator_type xt)
{
	return (xt == XT_SIIT || xt == XT_NAT64) ? 0 : -EINVAL;
}

int xf_validate(xlator_framework xf)
{
	return (xf == XF_NETFILTER || xf == XF_IPTABLES) ? 0 : -EINVAL;
}

xlator_type xlator_flags2xt(xlator_flags flags)
{
	return flags & 0x03;
}

xlator_framework xlator_flags2xf(xlator_flags flags)
{
	return flags & 0x0C;
}
