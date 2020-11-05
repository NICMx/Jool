#ifndef SRC_USR_ARGP_WARGP_GLOBAL_H_
#define SRC_USR_ARGP_WARGP_GLOBAL_H_

int handle_global_display(char *iname, int argc, char **argv, void const *arg);
void autocomplete_global_display(void const *args);

struct cmd_option *build_global_update_children(void);

#define WOPT_GLOBAL_MAPT_EUI6P(container) { \
		.xt = XT_MAPT, \
		.name = "end-user-ipv6-prefix", \
		.key = 0x4464e6, \
		.doc = "An IPv6 prefix unique to this CE, which will mask the nodes in its IPv4 island.", \
		.offset = offsetof(container, eui6p), \
		.type = &wt_prefix6, \
	}

#define WOPT_GLOBAL_MAPT_EABITS(container) { \
		.xt = XT_MAPT, \
		.name = "ea-bits", \
		.key = 0x4464ea, \
		.doc = "An identifier assigned to this CE, consisting of the concatenation of its assigned IPv4 address's suffix, and its PSID.", \
		.offset = offsetof(container, ea_bits), \
		.type = &wt_u64, \
	}

#define WOPT_GLOBAL_MAPT_BMR6(container) { \
		.xt = XT_MAPT, \
		.name = "bmr.ipv6-prefix", \
		.key = 0x4464b6, \
		.doc = "IPv6 Prefix of the MAP Domain's BMR.", \
		.offset = offsetof(container, bmr_p6), \
		.type = &wt_prefix6, \
	}

#define WOPT_GLOBAL_MAPT_BMR4(container) { \
		.xt = XT_MAPT, \
		.name = "bmr.ipv4-prefix", \
		.key = 0x4464b4, \
		.doc = "IPv4 Prefix of the MAP Domain's BMR.", \
		.offset = offsetof(container, bmr_p4), \
		.type = &wt_prefix4, \
	}

#define WOPT_GLOBAL_MAPT_EBL(container) { \
		.xt = XT_MAPT, \
		.name = "bmr.ea-bits-length", \
		.key = 'o', \
		.doc = "Length of the MAP Domain's EA-bits field. Also known as 'o'.", \
		.offset = offsetof(container, bmr_ebl), \
		.type = &wt_u8, \
	}

#define WOPT_GLOBAL_MAPT_a(container) { \
		.xt = XT_MAPT, \
		.name = "a", \
		.key = 'a', \
		.doc = "Length of the MAP Domain's port structure's 'i' field (aka. 'A'), in bits.", \
		.offset = offsetof(container, a), \
		.type = &wt_u8, \
	}

#define WOPT_GLOBAL_MAPT_k(container) { \
		.xt = XT_MAPT, \
		.name = "k", \
		.key = 'k', \
		.doc = "Length of the MAP Domain's PSID field, in bits. Also known as 'q'.", \
		.offset = offsetof(container, k), \
		.type = &wt_u8, \
	}

#define WOPT_GLOBAL_MAPT_m(container) { \
		.xt = XT_MAPT, \
		.name = "m", \
		.key = 'm', \
		.doc = "Length of the MAP Domain's port structure's 'j' field, in bits.", \
		.offset = offsetof(container, m), \
		.type = &wt_u8, \
	}

#endif /* SRC_USR_ARGP_WARGP_GLOBAL_H_ */
