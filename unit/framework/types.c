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
