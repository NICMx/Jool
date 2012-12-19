#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include "nf_nat64_ipv4_pool.h"

struct in_addr next_udp_address; 
struct in_addr next_tcp_address;
struct in_addr next_icmp_address;
struct in_addr last_address;

__u16 next_udp_port;
__u16 next_tcp_port;
__u16 next_icmp_port;
__u16 first_udp_port;
__u16 first_tcp_port;
__u16 first_icmp_port;
__u16 last_udp_port;
__u16 last_tcp_port;
__u16 last_icmp_port;

struct list_head free_udp_transport_addr;
struct list_head free_tcp_transport_addr;
struct list_head free_icmp_transport_addr;
struct list_head busy_udp_transport_addr;
struct list_head busy_tcp_transport_addr;
struct list_head busy_icmp_transport_addr;
struct list_head transport_addr;

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

extern struct config_struct cs;

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

static void return_transport_addr(struct transport_addr_struct *transport_addr,
        struct list_head *head)
{
	//INIT_LIST_HEAD(&transport_addr->list);
	list_add(&transport_addr->list, head);
}

static struct transport_addr_struct *get_transport_addr(struct list_head *head, struct list_head *busy_head,
        struct in_addr *next_address, __u16 *next_port, __u16 *first_port, __u16 *last_port)
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
					
					return_transport_addr(new_transport_addr,  &busy_udp_transport_addr);
					
					ports[0].puerto[new_transport_addr->port] = 1;
					
				}else{
					ports[0].puerto[new_transport_addr->port] = 1;
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
		display(0);
		list_del(prev); 
		display(0);
		//~ INIT_LIST_HEAD(&transport_addr->list);
		//~ list_add(&transport_addr->list, busy_head);
		ports[0].puerto[transport_addr->port] = 1;
		port_table_put(&table, &transport_addr->address, &ports[transport_addr->port]);
		return transport_addr;
	}
	
}

//gets

void display(int num){
	
	struct list_head *iter, *aux;
	if(num < 1){
		printk("Display begin...  \n");
		if (list_empty(&free_udp_transport_addr) == 1) {
			printk("Display NULL...  \n");
		}else{
	struct transport_addr_struct *transport_addr;
	list_for_each_safe(iter, aux, &free_udp_transport_addr) {
							transport_addr = list_entry(iter, struct transport_addr_struct, list);
							printk("Display:	%pI4  \n", &transport_addr->address.s_addr);
						}
					}
		printk("Display ends...  \n");
	}else{
			printk("Display busy begin...  \n");
		if (list_empty(&busy_udp_transport_addr) == 1) {
			printk("Display busy NULL...  \n");
		}else{
	struct transport_addr_struct *transport_addr;
	list_for_each_safe(iter, aux, &busy_udp_transport_addr) {
							transport_addr = list_entry(iter, struct transport_addr_struct, list);
							printk("Display busy:	%pI4  \n", &transport_addr->address.s_addr);
						}
					}
		printk("Display busy ends...  \n");

	}
	
}

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

void return_udp_transport_addr(struct transport_addr_struct *transport_addr)
{
	//~ struct list_head *prev = &busy_udp_transport_addr.prev;
	//~ list_del(prev); 
	//display(1);
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

bool allocate_given_ipv4_transport_address(uint16_t protocol, struct ipv4_tuple_address * new_ipv4_transport_address)
{
	struct list_head *iter;
	struct transport_addr_struct *transport_addr;
	
	switch(protocol){
		case IPPROTO_UDP:		if (list_empty(&busy_udp_transport_addr) == 1) { 
						return true;
					}else{
						list_for_each(iter, &busy_udp_transport_addr) {
							transport_addr = list_entry(iter, struct transport_addr_struct, list);
							if(new_ipv4_transport_address->address.s_addr == transport_addr->address.s_addr){
								return false;
							}else{
								if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[new_ipv4_transport_address->pi.port] == 1)
								return false;
							}
						}
					}
					return true;
			
		case IPPROTO_TCP:		if (list_empty(&busy_tcp_transport_addr) == 1) { 
						return true;
					}else{
						list_for_each(iter, &busy_tcp_transport_addr) {
							transport_addr = list_entry(iter, struct transport_addr_struct, list);
							if(new_ipv4_transport_address->address.s_addr == transport_addr->address.s_addr){
								return false;
							}else{
								if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[new_ipv4_transport_address->pi.port] == 1)
								return false;
							}
						}
					}
					
					return true;
			
		case IPPROTO_ICMP:	if (list_empty(&busy_icmp_transport_addr) == 1) { 
								return true;
							}else{
								list_for_each(iter, &busy_icmp_transport_addr) {
									transport_addr = list_entry(iter, struct transport_addr_struct, list);
									if(new_ipv4_transport_address->address.s_addr == transport_addr->address.s_addr){
										return false;
									}else{
										if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[new_ipv4_transport_address->pi.port] == 1)
										return false;
									}
								}
							}
							return true;
		default:
			return false;
	}
	
}

/** Retrieve a new transport address from IPv4 pool.
 * 
 * @param[in]	protocol	In what protocolo we should look at?
 * @param[in]	pi			Look for a port within the same range and parity.
 * @param[out]	new_ipv4_transport_address	New transport address obtained from the PROTOCOL's pool.
 * @return	true if everything went OK, false otherwise.
 * */
bool ipv4_pool_get_new_transport_address( u_int8_t protocol, __be16 pi, struct ipv4_tuple_address * new_ipv4_transport_address)
{
	struct transport_addr_struct * new_transport_addr;
	switch(protocol){
		case IPPROTO_UDP:	new_transport_addr = get_transport_addr(&free_udp_transport_addr, &busy_udp_transport_addr, &next_udp_address,
							&next_udp_port, &first_udp_port, &last_udp_port); 
							new_ipv4_transport_address->address.s_addr = new_transport_addr->address.s_addr; 
							new_ipv4_transport_address->pi.port = new_transport_addr->port;
					return true;
		case IPPROTO_TCP:	new_transport_addr = get_transport_addr(&free_tcp_transport_addr, &busy_tcp_transport_addr, &next_tcp_address,
							&next_tcp_port, &first_tcp_port, &last_tcp_port);
							new_ipv4_transport_address->address.s_addr = new_transport_addr->address.s_addr;
							new_ipv4_transport_address->pi.port = new_transport_addr->port;
					return true;
		case IPPROTO_ICMP:	new_transport_addr = get_transport_addr(&free_icmp_transport_addr, &busy_icmp_transport_addr, &next_icmp_address,
							&next_icmp_port, &first_icmp_port, &last_icmp_port);
							new_ipv4_transport_address->address.s_addr = new_transport_addr->address.s_addr;
							new_ipv4_transport_address->pi.port = new_transport_addr->port;
					return true;
		default:
			return false;
	}
		
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
					if(port_table_get(&table, &new_ipv4_transport_address->address.s_addr)->puerto[pair] == 1){
						pair+=2; 
					}else{
						new_ipv4_transport_address->pi.port = pair;
						ports[0].puerto[new_ipv4_transport_address->pi.port] = 1;
						port_table_put(&table, &new_ipv4_transport_address->address.s_addr, &ports[new_ipv4_transport_address->pi.port]);
						return true;
					}
				}
			}else{	//impar
				while(odd<1024){ 	
				if(port_table_get(&table, &new_ipv4_transport_address->address.s_addr) == NULL)
					return false;
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[odd] == 1){
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
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[pair] == 1){
						pair+=2;
					}else{
						new_ipv4_transport_address->pi.port = pair;
						return true;
					}
				}
			}else{	//impar
				while(odd<=65535){
					if(port_table_get(&table, &new_ipv4_transport_address->address)->puerto[odd] == 1){
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

void init_pools(struct config_struct *cs)
{
	port_table_init(&table, &ipv4_addr_equals, &ipv4_addr_hashcode);
	
	next_udp_address.s_addr = (*cs).ipv4_pool_range_first.s_addr;
	next_tcp_address.s_addr = (*cs).ipv4_pool_range_first.s_addr;
	next_icmp_address.s_addr = (*cs).ipv4_pool_range_first.s_addr;

	last_address.s_addr = (*cs).ipv4_pool_range_last.s_addr;

	first_tcp_port = 0; //(*cs).ipv4_tcp_port_first; // FIRST_PORT;
	first_udp_port = 0; //(*cs).ipv4_tcp_port_first;
	next_udp_port = first_udp_port;
	next_tcp_port = first_tcp_port;
	last_tcp_port = 1; //(*cs).ipv4_tcp_port_last; // LAST_PORT;
	last_udp_port = 1; //(*cs).ipv4_udp_port_last;

	pr_debug("NAT64: Configuring IPv4 pool.");
	
	pr_debug("NAT64:	UDP First address: %pI4 - Last address: %pI4\n", &next_udp_address.s_addr, &last_address.s_addr);
	pr_debug("NAT64:	TCP First address: %pI4 - Last address: %pI4\n", &next_tcp_address.s_addr, &last_address.s_addr);
	pr_debug("NAT64:	First UDP port: %u - Last port: %u\n", first_udp_port, last_udp_port);
	pr_debug("NAT64:	First TCP port: %u - Last port: %u\n", first_tcp_port, last_tcp_port);

	INIT_LIST_HEAD(&free_udp_transport_addr);
	INIT_LIST_HEAD(&free_tcp_transport_addr);
	INIT_LIST_HEAD(&free_icmp_transport_addr);
	INIT_LIST_HEAD(&busy_udp_transport_addr);
	INIT_LIST_HEAD(&busy_tcp_transport_addr);
	INIT_LIST_HEAD(&busy_icmp_transport_addr);
	INIT_LIST_HEAD(&transport_addr);
}
