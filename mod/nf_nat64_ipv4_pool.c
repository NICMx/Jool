#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kernel.h>

#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_config.h"

struct in_addr next_udp_address; 
struct in_addr next_tcp_address;
struct in_addr next_icmp_address;
struct in_addr last_address;

int next_udp_port;
int next_tcp_port;
int next_icmp_port;
int first_udp_port;
int first_tcp_port;
int first_icmp_port;
int last_udp_port;
int last_tcp_port;
int last_icmp_port;

struct list_head free_udp_transport_addr;
struct list_head free_tcp_transport_addr;
struct list_head free_icmp_transport_addr;
struct list_head busy_udp_transport_addr;
struct list_head busy_tcp_transport_addr;
struct list_head busy_icmp_transport_addr;

/* IPv4. These are global. Reference using extern, please. */
struct in_addr ipv4_pool_net;
struct in_addr ipv4_pool_range_first;
struct in_addr ipv4_pool_range_last;
int ipv4_mask_bits;
unsigned ip;

struct in_addr ipv4_netmask;

/* IPv6. These ones are also global. */
char *ipv6_pref_addr_str;
int ipv6_pref_len;	

struct port_list
{
	int puerto[2];
};

// Hash table
#define HTABLE_NAME port_table
#define KEY_TYPE struct in_addr
#define VALUE_TYPE struct port_list
#define GENERATE_PRINT
#include "nf_nat64_hash_table.c"

struct port_table table;
struct port_list ports[] = {{0}, {0}, {0}};

static struct transport_addr_struct *get_transport_addr(struct list_head *head, struct list_head *busy_head,
        struct in_addr *next_address, int *next_port, int *first_port, int *last_port)
{
	if (list_empty(head) == 1) { // if the list is empty
		if (next_address->s_addr > last_address.s_addr) {
			// and the next address is greater than the last address, return NULL
			return NULL;
		} else {
			// get the next address
			struct transport_addr_struct *new_transport_addr =
			        (struct transport_addr_struct *) kmalloc(
			                sizeof(struct transport_addr_struct), GFP_ATOMIC);

			if (new_transport_addr != NULL) {

				new_transport_addr->address.s_addr = next_address->s_addr;

				new_transport_addr->port = (*next_port)++;

				if (*next_port > *last_port) {
					*next_port = *first_port;
					ip = be32_to_cpu(next_address->s_addr);
					ip++;
					next_address->s_addr = cpu_to_be32(ip);
					
					INIT_LIST_HEAD(&new_transport_addr->list);
					list_add(&new_transport_addr->list, busy_head);
					ports[0].puerto[new_transport_addr->port] = -1;
					
				}else{
					ports[0].puerto[new_transport_addr->port] = -1;
				}
				port_table_put(&table, &new_transport_addr->address, &ports[new_transport_addr->port]);
				return new_transport_addr;

			} else {
				return NULL;
			}
		}
	} else { // is not empty
		// get the last address of the list
		struct list_head *prev = head->prev;
		struct transport_addr_struct *transport_addr = list_entry(prev, struct transport_addr_struct, list);
		list_del(prev);
		INIT_LIST_HEAD(&transport_addr->list);
		list_add(&transport_addr->list, busy_head);
		ports[0].puerto[transport_addr->port] = -1;
		port_table_put(&table, &transport_addr->address, &ports[transport_addr->port]);
		return transport_addr;
	}
	
}

//gets

struct transport_addr_struct *get_udp_transport_addr(void)
{
			return get_transport_addr(&free_udp_transport_addr, &busy_udp_transport_addr, &next_udp_address,
	        &next_udp_port, &first_udp_port, &last_udp_port);
}

struct transport_addr_struct *get_tcp_transport_addr(void)
{
	return get_transport_addr(&free_tcp_transport_addr, &busy_tcp_transport_addr, &next_tcp_address,
	        &next_tcp_port, &first_tcp_port, &last_tcp_port);
}

struct transport_addr_struct *get_icmp_transport_addr(void)
{ //se dejo el nombre de puerto por convencion ya que icmp en realidad maneja identificadores
	return get_transport_addr(&free_icmp_transport_addr, &busy_icmp_transport_addr, &next_icmp_address,
	        &next_icmp_port, &first_icmp_port, &last_icmp_port);
}
//end gets

//returns

static void return_transport_addr(struct transport_addr_struct *transport_addr,
        struct list_head *head)
{
	INIT_LIST_HEAD(&transport_addr->list);
	list_add(&transport_addr->list, head);
}

void return_udp_transport_addr(struct transport_addr_struct *transport_addr)
{
	return_transport_addr(transport_addr, &free_udp_transport_addr);
}

void return_tcp_transport_addr(struct transport_addr_struct *transport_addr)
{
	return_transport_addr(transport_addr, &free_tcp_transport_addr);
}

void return_icmp_transport_addr(struct transport_addr_struct *transport_addr)
{
	return_transport_addr(transport_addr, &free_icmp_transport_addr);
}
//end returns 

bool allocate_given_ipv4_transport_address(uint16_t protocol, struct ipv4_tuple_address *new_ipv4_transport_address)
{
	struct list_head *iter, *busy_list;
	struct transport_addr_struct *transport_addr;
	struct port_list *plist;
	
	switch(protocol){
	case IPPROTO_UDP:
		busy_list = &busy_udp_transport_addr;
		break;
	case IPPROTO_TCP:
		busy_list = &busy_tcp_transport_addr;
		break;
	default:
		return false;
	}
	
	if (list_empty(busy_list) == 1)
		return true;

	list_for_each(iter, busy_list) {
		transport_addr = list_entry(iter, struct transport_addr_struct, list);
		if(new_ipv4_transport_address->address.s_addr == transport_addr->address.s_addr)
			return false;

		plist = port_table_get(&table, &new_ipv4_transport_address->address);
		if (!plist)
			return true;

		if(plist->puerto[new_ipv4_transport_address->pi.port] == -1)
			return false;
	}

	return true;
}

/** Retrieve a new transport address from IPv4 pool.
 * 
 * @param[in]	protocol	In what protocolo we should look at?
 * @param[in]	pi			Look for a port within the same range and parity.
 * @param[out]	new_ipv4_transport_address	New transport address obtained from the PROTOCOL's pool.
 * @return	true if everything went OK, false otherwise.
 * */
bool ipv4_pool_get_new_transport_address(u_int8_t protocol, __be16 pi, struct ipv4_tuple_address *new_ipv4_transport_address)
{
	struct transport_addr_struct * new_transport_addr;
	switch(protocol){
	case IPPROTO_UDP:
		new_transport_addr = get_udp_transport_addr();
		break;
	case IPPROTO_TCP:
		new_transport_addr = get_tcp_transport_addr();
		break;
	case IPPROTO_ICMP:
		new_transport_addr = get_icmp_transport_addr();
		break;
	default:
		return false;
	}
		
	new_ipv4_transport_address->address.s_addr = new_transport_addr->address.s_addr;
	new_ipv4_transport_address->pi.port = new_transport_addr->port;
	return true;
}

/** Retrieve a new port for the specified IPv4 pool address.
 * 
 * @param[in]	protocol	In what protocolo we should look at?
 * @param[in]	pi			Look for a port within the same range and parity.
 * @param[out]	new_ipv4_transport_address	New transport address obtained from the PROTOCOL's pool.
 * @return	true if everything went OK, false otherwise.
 * */
bool ipv4_pool_get_new_port(struct in_addr address, __be16 pi, struct ipv4_tuple_address *new_ipv4_transport_address)
{
	__be16 pair, odd;

	new_ipv4_transport_address->address.s_addr = address.s_addr;

	if(pi < 1024){
		pair = 0;
		odd = 1;
			if(pi%2==0){
				while(pair<1024){
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[pair] == -1){
						pair+=2; 
					}else{
						new_ipv4_transport_address->pi.port = pair;
						ports[0].puerto[new_ipv4_transport_address->pi.port] = -1;
						port_table_put(&table, &new_ipv4_transport_address->address, &ports[new_ipv4_transport_address->pi.port]);
						return true;
					}
				}
			}else{	//impar
				while(odd<1024){ 	
				if(port_table_get(&table, &new_ipv4_transport_address->address) == NULL)
					return false;
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[odd] == -1){
					odd+=2; 	
					}else{
						new_ipv4_transport_address->pi.port = odd; 
						return true;
					}
				}
			}
	}else{
		pair = 1024;
		odd = 1025;
			if(pi%2==0){
				while(pair<65535){
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[pair] == -1){
						pair+=2;
					}else{
						new_ipv4_transport_address->pi.port = pair;
						return true;
					}
				}
			}else{	//impar
				while(odd<=65535){
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[odd] == -1){
					odd+=2;
					}else{
						new_ipv4_transport_address->pi.port = odd;
						return true;
					}
				}
			}
	}
			
	return false;
}

bool init_pools(void)
{
	port_table_init(&table, &ipv4_addr_equals, &ipv4_addr_hash_code);
	
	next_udp_address.s_addr = config.ipv4_pool_range_first.s_addr;
	next_tcp_address.s_addr = config.ipv4_pool_range_first.s_addr;
	next_icmp_address.s_addr = config.ipv4_pool_range_first.s_addr;
	last_address.s_addr = config.ipv4_pool_range_last.s_addr;

	first_tcp_port = 0; // config.ipv4_tcp_port_first;
	first_udp_port = 0; // config.ipv4_tcp_port_first;
	next_udp_port = first_udp_port;
	next_tcp_port = first_tcp_port;
	last_tcp_port = 1; // config.ipv4_tcp_port_last;
	last_udp_port = 1; // config.ipv4_udp_port_last;

	log_debug("Configured the IPv4 pool.");
	log_debug("  UDP addresses: %pI4 - %pI4", &next_udp_address.s_addr, &last_address.s_addr);
	log_debug("  UDP ports: %u - %u", first_udp_port, last_udp_port);
	log_debug("  TCP addresses: %pI4 - %pI4", &next_tcp_address.s_addr, &last_address.s_addr);
	log_debug("  TCP ports: %u - %u", first_tcp_port, last_tcp_port);

	INIT_LIST_HEAD(&free_udp_transport_addr);
	INIT_LIST_HEAD(&free_tcp_transport_addr);
	INIT_LIST_HEAD(&free_icmp_transport_addr);
	INIT_LIST_HEAD(&busy_udp_transport_addr);
	INIT_LIST_HEAD(&busy_tcp_transport_addr);
	INIT_LIST_HEAD(&busy_icmp_transport_addr);

	return true;
}

void destroy_pools(void)
{
	port_table_empty(&table, true, false);
}
