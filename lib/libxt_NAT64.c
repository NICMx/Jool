#include <stdio.h>
#include <xtables.h>
#include "nat64.h"


static void nat64_tg_help(void)
{
	printf("Just allows packets to arrive to the NAT64 module. Configure the module using the "
			"enclosing application.");
}

static int nat64_tg_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	return false;
}


static struct xtables_target nat64_ipv4_tg_reg = {
	.version = XTABLES_VERSION,
	.name = MODULE_NAME,
	.revision = 0,
	.family = NFPROTO_IPV4,
	.size = 0,
	.userspacesize = 0,
	.help = nat64_tg_help,
	.parse = nat64_tg_parse,
};

static struct xtables_target nat64_ipv6_tg_reg = {
	.version = XTABLES_VERSION,
	.name = MODULE_NAME,
	.revision = 0,
	.family = NFPROTO_IPV6,
	.size = 0,
	.userspacesize = 0,
	.help = nat64_tg_help,
	.parse = nat64_tg_parse,
};


void _init(void)
{
	xtables_register_target(&nat64_ipv4_tg_reg);
	xtables_register_target(&nat64_ipv6_tg_reg);
}
