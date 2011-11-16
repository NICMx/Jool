/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Copyright (C) 2010 Viagenie Inc. http://www.viagenie.ca
 *
 * Authors:
 *      Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *      Simon Perreault <simon.perreault@viagenie.ca>
 *      Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _NF_NAT64_CONFIG_H
#define _NF_NAT64_CONFIG_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include "linux/bug.h"

void nat64_config_set_prefix(struct in6_addr prefix, int prefix_len);
void nat64_config_set_nat_addr(struct in_addr);

int nat64_config_prefix_len(void);
struct in6_addr * nat64_config_prefix(void);
struct in_addr * nat64_config_nat_addr(void);

struct in_addr nat64_extract(const struct in6_addr *a6);
void nat64_embed(struct in_addr a4, struct in6_addr *a6);

struct nat64_config_t {
	int prefix_len;
	struct in6_addr prefix;
	struct in_addr nat_addr;
};

static struct nat64_config_t nat64_config;

void nat64_config_set_prefix(struct in6_addr prefix, int prefix_len)
{

	if (prefix_len == 96 && nat64_config.prefix.s6_addr[8] == 0)
		printk(KERN_ERR "nf_nat64: Bits 64 to 71 must be set to 0. See draft-ietf-behave-address-format.\n");
	nat64_config.prefix = prefix;
	nat64_config.prefix_len = prefix_len;
}

void nat64_config_set_nat_addr(struct in_addr addr) 
{
	nat64_config.nat_addr = addr;
}

int nat64_config_prefix_len() 
{
	return nat64_config.prefix_len;
}

struct in6_addr * nat64_config_prefix() 
{
	return &(nat64_config.prefix);
}

struct in_addr * nat64_config_nat_addr()
{
	return &(nat64_config.nat_addr);
}

struct in_addr
nat64_extract(const struct in6_addr *a6)
{
	struct in_addr           a4;

	switch (nat64_config.prefix_len) {
	case 32:
		((uint8_t *)&a4)[0] = a6->s6_addr[4];
		((uint8_t *)&a4)[1] = a6->s6_addr[5];
		((uint8_t *)&a4)[2] = a6->s6_addr[6];
		((uint8_t *)&a4)[3] = a6->s6_addr[7];
		break;
	case 40:
		((uint8_t *)&a4)[0] = a6->s6_addr[5];
		((uint8_t *)&a4)[1] = a6->s6_addr[6];
		((uint8_t *)&a4)[2] = a6->s6_addr[7];
		((uint8_t *)&a4)[3] = a6->s6_addr[9];
		break;
	case 48:
		((uint8_t *)&a4)[0] = a6->s6_addr[6];
		((uint8_t *)&a4)[1] = a6->s6_addr[7];
		((uint8_t *)&a4)[2] = a6->s6_addr[9];
		((uint8_t *)&a4)[3] = a6->s6_addr[10];
		break;
	case 56:
		((uint8_t *)&a4)[0] = a6->s6_addr[7];
		((uint8_t *)&a4)[1] = a6->s6_addr[9];
		((uint8_t *)&a4)[2] = a6->s6_addr[10];
		((uint8_t *)&a4)[3] = a6->s6_addr[11];
		break;
	case 64:
		((uint8_t *)&a4)[0] = a6->s6_addr[9];
		((uint8_t *)&a4)[1] = a6->s6_addr[10];
		((uint8_t *)&a4)[2] = a6->s6_addr[11];
		((uint8_t *)&a4)[3] = a6->s6_addr[12];
		break;
	case 96:
		((uint8_t *)&a4)[0] = a6->s6_addr[12];
		((uint8_t *)&a4)[1] = a6->s6_addr[13];
		((uint8_t *)&a4)[2] = a6->s6_addr[14];
		((uint8_t *)&a4)[3] = a6->s6_addr[15];
		break;
		// XXX kernel equivalent? */
	default:
		WARN_ON_ONCE(1);
	}

	return a4;
}

void
nat64_embed(struct in_addr a4, struct in6_addr *a6)
{
	switch (nat64_config.prefix_len) {
	case 32:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = ((uint8_t *)&a4)[0];
		a6->s6_addr[ 5] = ((uint8_t *)&a4)[1];
		a6->s6_addr[ 6] = ((uint8_t *)&a4)[2];
		a6->s6_addr[ 7] = ((uint8_t *)&a4)[3];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = 0;
		a6->s6_addr[10] = 0;
		a6->s6_addr[11] = 0;
		a6->s6_addr[12] = 0;
		a6->s6_addr[13] = 0;
		a6->s6_addr[14] = 0;
		a6->s6_addr[15] = 0;
		break;
	case 40:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = nat64_config.prefix.s6_addr[4];
		a6->s6_addr[ 5] = ((uint8_t *)&a4)[0];
		a6->s6_addr[ 6] = ((uint8_t *)&a4)[1];
		a6->s6_addr[ 7] = ((uint8_t *)&a4)[2];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = ((uint8_t *)&a4)[3];
		a6->s6_addr[10] = 0;
		a6->s6_addr[11] = 0;
		a6->s6_addr[12] = 0;
		a6->s6_addr[13] = 0;
		a6->s6_addr[14] = 0;
		a6->s6_addr[15] = 0;
		break;
	case 48:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = nat64_config.prefix.s6_addr[4];
		a6->s6_addr[ 5] = nat64_config.prefix.s6_addr[5];
		a6->s6_addr[ 6] = ((uint8_t *)&a4)[0];
		a6->s6_addr[ 7] = ((uint8_t *)&a4)[1];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = ((uint8_t *)&a4)[2];
		a6->s6_addr[10] = ((uint8_t *)&a4)[3];
		a6->s6_addr[11] = 0;
		a6->s6_addr[12] = 0;
		a6->s6_addr[13] = 0;
		a6->s6_addr[14] = 0;
		a6->s6_addr[15] = 0;
		break;
	case 56:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = nat64_config.prefix.s6_addr[4];
		a6->s6_addr[ 5] = nat64_config.prefix.s6_addr[5];
		a6->s6_addr[ 6] = nat64_config.prefix.s6_addr[6];
		a6->s6_addr[ 7] = ((uint8_t *)&a4)[0];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = ((uint8_t *)&a4)[1];
		a6->s6_addr[10] = ((uint8_t *)&a4)[2];
		a6->s6_addr[11] = ((uint8_t *)&a4)[3];
		a6->s6_addr[12] = 0;
		a6->s6_addr[13] = 0;
		a6->s6_addr[14] = 0;
		a6->s6_addr[15] = 0;
		break;
	case 64:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = nat64_config.prefix.s6_addr[4];
		a6->s6_addr[ 5] = nat64_config.prefix.s6_addr[5];
		a6->s6_addr[ 6] = nat64_config.prefix.s6_addr[6];
		a6->s6_addr[ 7] = nat64_config.prefix.s6_addr[7];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = ((uint8_t *)&a4)[0];
		a6->s6_addr[10] = ((uint8_t *)&a4)[1];
		a6->s6_addr[11] = ((uint8_t *)&a4)[2];
		a6->s6_addr[12] = ((uint8_t *)&a4)[3];
		a6->s6_addr[13] = 0;
		a6->s6_addr[14] = 0;
		a6->s6_addr[15] = 0;
		break;
	case 96:
		a6->s6_addr[ 0] = nat64_config.prefix.s6_addr[0];
		a6->s6_addr[ 1] = nat64_config.prefix.s6_addr[1];
		a6->s6_addr[ 2] = nat64_config.prefix.s6_addr[2];
		a6->s6_addr[ 3] = nat64_config.prefix.s6_addr[3];
		a6->s6_addr[ 4] = nat64_config.prefix.s6_addr[4];
		a6->s6_addr[ 5] = nat64_config.prefix.s6_addr[5];
		a6->s6_addr[ 6] = nat64_config.prefix.s6_addr[6];
		a6->s6_addr[ 7] = nat64_config.prefix.s6_addr[7];
		a6->s6_addr[ 8] = 0;
		a6->s6_addr[ 9] = nat64_config.prefix.s6_addr[9];
		a6->s6_addr[10] = nat64_config.prefix.s6_addr[10];
		a6->s6_addr[11] = nat64_config.prefix.s6_addr[11];
		a6->s6_addr[12] = ((uint8_t *)&a4)[0];
		a6->s6_addr[13] = ((uint8_t *)&a4)[1];
		a6->s6_addr[14] = ((uint8_t *)&a4)[2];
		a6->s6_addr[15] = ((uint8_t *)&a4)[3];
		break;
	default:
		WARN_ON_ONCE(1);
	}
}
#endif
