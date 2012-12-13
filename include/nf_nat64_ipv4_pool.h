#ifndef _NF_NAT64_IPV4_POOL_H
#define _NF_NAT64_IPV4_POOL_H

#include <linux/slab.h>
#include <linux/inet.h>
#include "nf_nat64_types.h"

struct transport_addr_struct
{
	struct in_addr address;
	__u16 port;
	struct list_head list;
};

struct transport_addr_struct *get_udp_transport_addr(void);
struct transport_addr_struct *get_tcp_transport_addr(void);
struct transport_addr_struct *get_icmp_transport_addr(void);

void return_udp_transport_addr(struct transport_addr_struct *transport_addr);
void return_tcp_transport_addr(struct transport_addr_struct *transport_addr);
void return_icmp_transport_addr(struct transport_addr_struct *transport_addr);

void display(int num);

bool ipv4_pool_get_new_transport_address( u_int8_t protocol, __be16 pi, struct ipv4_tuple_address * new_ipv4_transport_address);

/**
 * Reserves the "new_ipv4_transport_address". It's like the gets above, except the caller decides
 * which address and port it wants.
 *
 * Returns whether the "new_ipv4_transport_address" could be reserved.
 *
 * TODO falta la parte de reservar; solamente está regresando si la dirección está ocupada o no.
 */
bool allocate_given_ipv4_transport_address(uint16_t protocol, struct ipv4_tuple_address * new_ipv4_transport_address);
bool ipv4_pool_get_new_port(struct in_addr address, __be16 pi, struct ipv4_tuple_address *new_ipv4_transport_address);

bool init_pools(void);
void destroy_pools(void);


#endif /* _NF_NAT64_IPV4_POOL_H */
