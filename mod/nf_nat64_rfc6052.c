#include <linux/module.h>
#include <linux/printk.h>

#include "nf_nat64_rfc6052.h"

struct in_addr nat64_extract_ipv4(struct in6_addr *ipv6_original, int prefix_length)
{
	struct in6_addr ipv6_dummy;
	struct in_addr ipv4_result;

	switch (prefix_length) {
	case 32:
		ipv4_result.s_addr = ipv6_original->s6_addr32[1];
		break;
	case 40:
		ipv6_dummy.s6_addr[0] = ipv6_original->s6_addr[5];
		ipv6_dummy.s6_addr[1] = ipv6_original->s6_addr[6];
		ipv6_dummy.s6_addr[2] = ipv6_original->s6_addr[7];
		ipv6_dummy.s6_addr[3] = ipv6_original->s6_addr[9];
		ipv4_result.s_addr = ipv6_dummy.s6_addr32[0];
		break;
	case 48:
		ipv6_dummy.s6_addr[0] = ipv6_original->s6_addr[6];
		ipv6_dummy.s6_addr[1] = ipv6_original->s6_addr[7];
		ipv6_dummy.s6_addr[2] = ipv6_original->s6_addr[9];
		ipv6_dummy.s6_addr[3] = ipv6_original->s6_addr[10];
		ipv4_result.s_addr = ipv6_dummy.s6_addr32[0];
		break;
	case 56:
		ipv6_dummy.s6_addr[0] = ipv6_original->s6_addr[7];
		ipv6_dummy.s6_addr[1] = ipv6_original->s6_addr[9];
		ipv6_dummy.s6_addr[2] = ipv6_original->s6_addr[10];
		ipv6_dummy.s6_addr[3] = ipv6_original->s6_addr[11];
		ipv4_result.s_addr = ipv6_dummy.s6_addr32[0];
		break;
	case 64:
		ipv6_dummy.s6_addr[0] = ipv6_original->s6_addr[9];
		ipv6_dummy.s6_addr[1] = ipv6_original->s6_addr[10];
		ipv6_dummy.s6_addr[2] = ipv6_original->s6_addr[11];
		ipv6_dummy.s6_addr[3] = ipv6_original->s6_addr[12];
		ipv4_result.s_addr = ipv6_dummy.s6_addr32[0];
		break;
	case 96:
		ipv4_result.s_addr = ipv6_original->s6_addr32[3];
		break;
	default:
		// TODO (later) haz algo para reportar esto hacia afuera (hay otro en append).
		pr_err("nat64_extract_ipv4: Cannot translate prefix: %d.\n", prefix_length);
		ipv4_result.s_addr = 0;
		break;
	}

	return ipv4_result;
}

struct in6_addr nat64_append_ipv4(struct in6_addr *prefix, struct in_addr *ipv4_original, int prefix_len)
{
	struct in6_addr ipv4_copy;
	struct in6_addr ipv6_result;

	ipv4_copy.s6_addr32[0] = ipv4_original->s_addr;
	memset(&ipv6_result, 0, sizeof(struct in6_addr));

	switch (prefix_len) {
	case 32:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr32[1] = ipv4_original->s_addr;
		break;
	case 40:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr[4] = prefix->s6_addr[4];
		ipv6_result.s6_addr[5] = ipv4_copy.s6_addr[0];
		ipv6_result.s6_addr[6] = ipv4_copy.s6_addr[1];
		ipv6_result.s6_addr[7] = ipv4_copy.s6_addr[2];
		ipv6_result.s6_addr[9] = ipv4_copy.s6_addr[3];
		break;
	case 48:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr[4] = prefix->s6_addr[4];
		ipv6_result.s6_addr[5] = prefix->s6_addr[5];
		ipv6_result.s6_addr[6] = ipv4_copy.s6_addr[0];
		ipv6_result.s6_addr[7] = ipv4_copy.s6_addr[1];
		ipv6_result.s6_addr[9] = ipv4_copy.s6_addr[2];
		ipv6_result.s6_addr[10] = ipv4_copy.s6_addr[3];
		break;
	case 56:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr[4] = prefix->s6_addr[4];
		ipv6_result.s6_addr[5] = prefix->s6_addr[5];
		ipv6_result.s6_addr[6] = prefix->s6_addr[6];
		ipv6_result.s6_addr[7] = ipv4_copy.s6_addr[0];
		ipv6_result.s6_addr[9] = ipv4_copy.s6_addr[1];
		ipv6_result.s6_addr[10] = ipv4_copy.s6_addr[2];
		ipv6_result.s6_addr[11] = ipv4_copy.s6_addr[3];
		break;
	case 64:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr32[1] = prefix->s6_addr32[1];
		ipv6_result.s6_addr[9]   = ipv4_copy.s6_addr[0];
		ipv6_result.s6_addr[10]  = ipv4_copy.s6_addr[1];
		ipv6_result.s6_addr[11]  = ipv4_copy.s6_addr[2];
		ipv6_result.s6_addr[12]  = ipv4_copy.s6_addr[3];
		break;
	case 96:
		ipv6_result.s6_addr32[0] = prefix->s6_addr32[0];
		ipv6_result.s6_addr32[1] = prefix->s6_addr32[1];
		ipv6_result.s6_addr32[2] = prefix->s6_addr32[2];
		ipv6_result.s6_addr32[3] = ipv4_original->s_addr;
		break;
	default:
		pr_err("nat64_append_ipv4: Cannot translate prefix length: %d.\n", prefix_len);
		break;
	}

	return ipv6_result;
}
