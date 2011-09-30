#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_nat64.h"
#include "libxt_nat64.h"


static const struct option nat64_tg_opts[] = {
	{.name = "ipsrc", .has_arg = true, .val = '1'},
	{.name = "ipdst", .has_arg = true, .val = '2'},
	{NULL},
};

static struct xtables_target nat64_tg4_reg = {
	.version = XTABLES_VERSION,
	.name = "nat64",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.size = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(xt_nat64_tginfo)),
	.help = nat64_tg_help,
	.parse = nat64_tg4_parse,
	.final_check = nat64_tg_check,
	.print = nat64_tg4_print,
	.save = nat64_tg4_save,
	.extra_opts = nat64_tg_opts,
};

static struct xtables_target nat64_tg6_reg = {
	.version = XTABLES_VERSION,
	.name = "nat64",
	.revision = 0,
	.family = NFPROTO_IPV6,
	.size = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_nat64_tginfo)),
	.help = nat64_tg_help,
	.parse = nat64_tg6_parse,
	.final_check = nat64_tg_check,
	.print = nat64_tg6_print,
	.save = nat64_tg6_save,
	.extra_opts = nat64_tg_opts,
};


static void nat64_tg4_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info ->flags & XT_NAT64_IP_SRC) {
		printf("--ipsrc %s ", xtables_ipaddr_to_numeric(&info->src.in));
	}

	if (info->flags & XT_NAT64_IP_DST) {
		printf("--ipdst %s ", xtables_ipaddr_to_numeric(&info->dst.in));
	}
}

static void nat64_tg6_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info ->flags & XT_nat64_SRC) {
		if (info->flags & XT_nat64_SRC_INV)
			printf("! ");

		printf("--ipsrc %s ", xtables_ip6addr_to_numeric(&info->src.in6));
	}

	if (info->flags & XT_nat64_DST) {
		if (info->flags & XT_nat64_DST_INV)
			printf("! ");

		printf("--ipdst %s ",
				xtables_ip6addr_to_numeric(&info->dst.in6));
	}
}


static void nat64_tg4_print(const void *entry,
		const struct xt_entry_target *target, int numeric)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info->flags & XT_nat64_SRC) {
		printf("src IP ");

		if (info->flags & XT_nat64_SRC_INV)
			printf("! ");

		if (numeric)
			printf("%s ", numeric ?
					xtables_ipaddr_to_numeric(&info->src.in) :
					xtables_ipaddr_to_anyname(&info->src.in));
	}

	if (info->flags & XT_nat64_DST) {
		printf("dst IP ");

		if (info->flags & XT_nat64_DST_INV)
			printf("! ");

		printf("%s ", numeric ?
				xtables_ipaddr_to_numeric(&info->dst.in):
				xtables_ipaddr_to_anyname(&info->dst.in));
	}
}


static void nat64_tg6_print(const void *entry,
		const struct xt_entry_target *target, int numeric)
{
	const struct xt_nat64_tginfo *info = (const void *)target->data;

	if (info->flags & XT_NAT64_IPV6_DST) {
		printf("dst IP ");

		printf("%s ", numeric ?
				xtables_ip6addr_to_numeric(&info->dst.in6):
				xtables_ip6addr_to_anyname(&info->dst.in6));
	}
}

static int nat64_tg4_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	struct xt_nat64_tginfo *info = (void *)(*target)->data;
	struct in_addr *addrs, mask;
	unsigned int naddrs;

	switch (c) {
		case '1': /* --ipsrc */
			if (*flags & XT_NAT64_IP_SRC)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipsrc\" once!");

			*flags |= XT_NAT64_IP_SRC;
			info->flags |= XT_NAT64_IP_SRC;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			/* Copy the single address */
			memcpy(&info->src.in, addrs, sizeof(*addrs));
			return true;

		case '2': /* --ipdst */
			if (*flags & XT_NAT64_IP_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_NAT64_IP_DST;
			info->flags |= XT_NAT64_IP_DST;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->dst.in, addrs, sizeof(*addrs));
			return true;
	}
	return false;
}

static int nat64_tg6_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	struct xt_nat64_tginfo *info = (void *)(*target)->data;
	struct in6_addr *addrs, mask;
	char str[INET6_ADDRSTRLEN];

	switch(c) {
		case '1': /* --ipsrc */
			xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
					"You can't check for the source!");

			return false;

		case '2': /* --ipdst */
			if (*flags & XT_NAT64_IPV6_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_NAT64_IPV6_DST;
			info->flags |= XT_NAT64_IPV6_DST;

			if (invert)
				xtables_error(PARAMETER_PROBLEM, "xt_nat64: "
						"I'm sorry, the invert flag isn't available yet");

			xtables_ip6parse_any(optarg, &addrs, &mask, &naddrs);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->ip6dst.in6, addrs, sizeof(*addrs));
			memcpy(&info->ip6dst_mask.in6, mask, sizeof(*mask));
			return true;
	}

	return false;
}

static void nat64_tg_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "xt_nat64: You need to "
				"specify at least \"--ipsrc\" or \"--ipdst\".");
}


static void nat64_tg_help(void)
{
	printf(
			"nat64 target options:\n"
			"[!] --ipsrc addr target source address of packet\n"
			"[!] --ipdst addr target destination address of packet\n"
		  );
}


void _init(void)
{
	xtables_register_target(&nat64_tg4_reg);
	xtables_register_target(&nat64_tg6_reg);
}

