#include "nat64/unit/types.h"
#include "nat64/comm/str_utils.h"

#include <linux/kernel.h>
#include <linux/module.h>

int init_pair6(struct ipv6_pair *pair6, unsigned char *remote_addr, u16 remote_id,
		unsigned char *local_addr, u16 local_id)
{
	int error;

	error = str_to_addr6(remote_addr, &pair6->remote.address);
	if (error) {
		log_warning("Cannot parse '%s' as a valid IPv6 address", remote_addr);
		return error;
	}
	pair6->remote.l4_id = remote_id;

	error = str_to_addr6(local_addr, &pair6->local.address);
	if (error) {
		log_warning("Cannot parse '%s' as a valid IPv6 address", local_addr);
		return error;
	}
	pair6->local.l4_id = local_id;

	return 0;
}

int init_pair4(struct ipv4_pair *pair4, unsigned char *remote_addr, u16 remote_id,
		unsigned char *local_addr, u16 local_id)
{
	int error;

	error = str_to_addr4(remote_addr, &pair4->remote.address);
	if (error) {
		log_warning("Cannot parse '%s' as a valid IPv4 address", remote_addr);
		return error;
	}
	pair4->remote.l4_id = remote_id;

	error = str_to_addr4(local_addr, &pair4->local.address);
	if (error) {
		log_warning("Cannot parse '%s' as a valid IPv4 address", local_addr);
		return error;
	}
	pair4->local.l4_id = local_id;

	return 0;
}


int init_ipv4_tuple(struct tuple *tuple, unsigned char *src_addr, u16 src_port,
		unsigned char *dst_addr, u16 dst_port, l4_protocol l4_proto)
{
	int error;

	error = str_to_addr4(src_addr, &tuple->src.addr.ipv4);
	if (error)
		return error;
	tuple->src.l4_id = src_port;

	error = str_to_addr4(dst_addr, &tuple->dst.addr.ipv4);
	if (error)
		return error;
	tuple->dst.l4_id = dst_port;

	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv6_tuple(struct tuple *tuple, unsigned char *src_addr, u16 src_port,
		unsigned char *dst_addr, u16 dst_port, l4_protocol l4_proto)
{
	int error;

	error = str_to_addr6(src_addr, &tuple->src.addr.ipv6);
	if (error)
		return error;
	tuple->src.l4_id = src_port;

	error = str_to_addr6(dst_addr, &tuple->dst.addr.ipv6);
	if (error)
		return error;
	tuple->dst.l4_id = dst_port;

	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv4_tuple_from_pair(struct tuple *tuple, struct ipv4_pair *pair4, l4_protocol l4_proto)
{
	tuple->src.addr.ipv4 = pair4->remote.address;
	tuple->src.l4_id = pair4->remote.l4_id;

	tuple->dst.addr.ipv4 = pair4->local.address;
	tuple->dst.l4_id = pair4->local.l4_id;

	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv6_tuple_from_pair(struct tuple *tuple, struct ipv6_pair *pair6, l4_protocol l4_proto)
{
	tuple->src.addr.ipv6 = pair6->remote.address;
	tuple->src.l4_id = pair6->remote.l4_id;

	tuple->dst.addr.ipv6 = pair6->local.address;
	tuple->dst.l4_id = pair6->local.l4_id;

	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4_proto;

	return 0;
}
