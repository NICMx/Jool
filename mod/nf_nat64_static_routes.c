/** 
 * @file nf_nat64_static_routes.c 
 *
 * This module implements the feature mentioned in the RFC6146, 
 * about managing static routes. It allows to add a new entry in
 * the BIB and Session tables from Userspace.
 *
 */
#include "nf_nat64_static_routes.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"

// TODO (miguel) hay demasiado overkill aquí;
// por un lado el código de los tres diferentes cases es exactamente igual. ¿Por qué está repetido?
// y lo otro es que demasiado consiste en traducir de route_struct a pairs. Como los route_structs
// no se usan más que en configuración, ¿No podemos deshacernos de ellos y traernos de una vez los
// pairs desde userspace?
bool nat64_add_static_route(struct route_struct *rst){

	struct bib_entry *bib_entry_p;
	struct session_entry *session_entry_p;
	struct ipv4_pair pair_4;
	struct ipv6_pair pair_6;
	struct ipv4_tuple_address ip4;
	struct ipv6_tuple_address ip6;

	int result;

	uint16_t p1=0; 
	uint16_t p2=0;
	uint16_t p3=0; 
	uint16_t p4=0;
	u_int8_t proto;

	struct in6_addr addr1 = IN6ADDR_ANY_INIT;
	struct in6_addr addr2 = IN6ADDR_ANY_INIT;
	struct in_addr addr3;
	struct in_addr addr4;

	addr1 = (*rst).ipv6_src_address;
	addr2 = (*rst).ipv6_dst_address;
	addr3 = (*rst).ipv4_src_address;
	addr4 = (*rst).ipv4_dst_address;
	p1 = (*rst).ipv6_src_port_or_id;
	p2 = (*rst).ipv6_dst_port_or_id;
	p3 = (*rst).ipv4_src_port_or_id;
	p4 = (*rst).ipv4_dst_port_or_id;
	proto = (*rst).protocol;
	pr_debug("NAT64 src Address: %pI6 port: %d\n", &addr1.s6_addr, ntohs(p1));
	pr_debug("NAT64 dst Address: %pI6 port: %d\n", &addr2.s6_addr, ntohs(p2));
	pr_debug("NAT64 src Address: %pI4 port: %d\n", &addr3.s_addr, ntohs(p3));
	pr_debug("NAT64 dst Address: %pI4 port: %d\n", &addr4.s_addr, ntohs(p4));
	pr_debug("NAT64 protocol: %d\n", proto);


	switch(proto) {
		case 1:	
			pair_6.remote.address = addr1;
			pair_6.remote.pi.id = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.id = p2;
			pair_4.remote.address = addr4;
			pair_4.remote.pi.id = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.id = p3;

			ip6.address = addr1;
			ip6.pi.id = p1;
			ip4.address = addr3;
			ip4.pi.id = p3;
		 
/*			
			result = allocate_given_ipv4_transport_address(proto, pair_4.local);
			if ( result == false ) {
				pr_warning("NAT64: Could NOT allocate a new IPv4 transport address for TCP.");
				kfree(bib_entry_p);
				return;
			} 
*/

			// Allocate memory for a new BIB entry
            bib_entry_p = nat64_create_bib_entry(&ip4, &ip6);
            if ( bib_entry_p == NULL ){
                pr_warning("NAT64: Could NOT create a new BIB entry for ICMP route.");
                return false;
            }

			result = nat64_add_bib_entry( bib_entry_p, proto);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new BIB entry for ICMP route.");
				kfree(bib_entry_p);
				return false;
			}

 			// Allocate memory for a new Session entry
            session_entry_p = nat64_create_static_session_entry(&pair_4, &pair_6, bib_entry_p, proto);
            if (session_entry_p == NULL) {
            	pr_warning("NAT64: Could NOT create a new SESSION entry for ICMP route.");
            	nat64_remove_bib_entry( bib_entry_p, proto);
            	// TODO (miguel) me parece que hay que liberar a bib_entry_p también.
            	return false;
            }

			// Add the session entry
			result = nat64_add_session_entry(session_entry_p);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new session entry for ICMP route.");
				kfree(session_entry_p);
				nat64_remove_bib_entry( bib_entry_p, proto);
				// TODO (miguel) me parece que hay que liberar a bib_entry_p también.
				// Mejor inicialízalas ambas como NULL y en lugar de hacer esto siempre haz un goto
				// failure que quite tanto la BIB como la sesión de la tabla y que también las
				// libere.
				return false ;
			}

			break;
		case 6:			
			pair_6.remote.address = addr1;
			pair_6.remote.pi.port = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.port = p2;
			pair_4.remote.address = addr4;
			pair_4.remote.pi.port = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.port = p3;

			ip6.address = addr1;
			ip6.pi.port = p1;
			ip4.address = addr3;
			ip4.pi.port = p3;
			// Allocate memory for a new BIB entry

/*			
			result = allocate_given_ipv4_transport_address(proto, pair_4.local);
			if ( result == false ) {
				pr_warning("NAT64: Could NOT allocate a new IPv4 transport address for TCP.");
				kfree(bib_entry_p);
				return;
			} 
*/

			// Allocate memory for a new BIB entry
 			bib_entry_p = nat64_create_bib_entry(&ip4, &ip6);
            if ( bib_entry_p == NULL ){
            	pr_warning("NAT64: Could NOT create a new BIB entry for TCP route.");
                return false;
            }

			result = nat64_add_bib_entry( bib_entry_p, proto);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new BIB entry for TCP route.");
				kfree(bib_entry_p);
				return false;
			}

			// Allocate memory for a new Session entry
            session_entry_p = nat64_create_static_session_entry(&pair_4, &pair_6, bib_entry_p, proto);
            if (session_entry_p == NULL) {
                pr_warning("NAT64: Could NOT create a new SESSION entry for TCP route.");
                nat64_remove_bib_entry( bib_entry_p, proto);
            	return false;
            }

			// Add the session entry
			result = nat64_add_session_entry(session_entry_p);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new session entry for TCP route.");
				kfree(session_entry_p);
				nat64_remove_bib_entry( bib_entry_p, proto);
				return false;
			}
			break;
		case 17:	
			pair_6.remote.address = addr1;
			pair_6.remote.pi.port = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.port = p2;
			pair_4.remote.address = addr4;
			pair_4.remote.pi.port = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.port = p3;

			ip6.address = addr1;
			ip6.pi.port = p1;
			ip4.address = addr3;
			ip4.pi.port = p3;		
			
/*			
			result = allocate_given_ipv4_transport_address(proto, pair_4.local);
			if ( result == false ) {
				pr_warning("NAT64: Could NOT allocate a new IPv4 transport address for UDP.");
				kfree(bib_entry_p);
				return;
			} 
*/
			
			// Allocate memory for a new BIB entry
            bib_entry_p = nat64_create_bib_entry(&ip4, &ip6);
            if ( bib_entry_p == NULL ){
            	pr_warning("NAT64: Could NOT create a new BIB entry for UDP route.");
                return false;
            }

			result = nat64_add_bib_entry( bib_entry_p, proto);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new BIB entry for UDP route.");
				kfree(bib_entry_p);
				return false;
			}

			// Allocate memory for a new Session entry
            session_entry_p = nat64_create_static_session_entry(&pair_4, &pair_6, bib_entry_p, proto);
            if (session_entry_p == NULL) {
            	pr_warning("NAT64: Could NOT create a new SESSION entry for UDP route.");
                nat64_remove_bib_entry( bib_entry_p, proto);
               	return false;
            }

			// Add the session entry
			result = nat64_add_session_entry(session_entry_p);
			if (result == false) {
				pr_warning("NAT64: Could NOT add a new session entry for UDP route.");
				kfree(session_entry_p);
				nat64_remove_bib_entry( bib_entry_p, proto);
				return false;
			}
			break;
		default:
			break;
	}

	return true;
}

// TODO (miguel) igual que la función anterior
bool nat64_delete_static_route(struct route_struct *rst) {
	struct session_entry *session_entry_p;
	struct ipv4_pair pair_4;
	struct ipv6_pair pair_6;

	int result;

	uint16_t p1=0; 
	uint16_t p2=0;
	uint16_t p3=0; 
	uint16_t p4=0;
	u_int8_t proto;

	struct in6_addr addr1 = IN6ADDR_ANY_INIT;
	struct in6_addr addr2 = IN6ADDR_ANY_INIT;
	struct in_addr addr3;
	struct in_addr addr4;
	
	proto = (*rst).protocol;
	pr_debug("NAT64 protocol: %d\n", proto);
	
	switch(proto) {
		case 2:
			addr1 = (*rst).ipv6_src_address;
			addr2 = (*rst).ipv6_dst_address;
			p1 = (*rst).ipv6_src_port_or_id;
			p2 = (*rst).ipv6_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI6 port: %d\n", &addr1.s6_addr, ntohs(p1));
			pr_debug("NAT64 dst Address: %pI6 port: %d\n", &addr2.s6_addr, ntohs(p2));

			pair_6.remote.address = addr1;
			pair_6.remote.pi.id = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.id = p2;

			session_entry_p = nat64_get_session_entry_by_ipv6(&pair_6, IPPROTO_ICMPV6);
			if ( session_entry_p != NULL){
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false) { 
					pr_warning("NAT64: Could NOT remove the session entry for IPv6 UDP route.");
					return false;
				}
				kfree(session_entry_p);
			}
			break;
		case 3:
			addr3 = (*rst).ipv4_src_address;
			addr4 = (*rst).ipv4_dst_address;
			p3 = (*rst).ipv4_src_port_or_id;
			p4 = (*rst).ipv4_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI4 port: %d\n", &addr3.s_addr, ntohs(p3));
			pr_debug("NAT64 dst Address: %pI4 port: %d\n", &addr4.s_addr, ntohs(p4));

			pair_4.remote.address = addr4;
			pair_4.remote.pi.id = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.id = p3;


			session_entry_p = nat64_get_session_entry_by_ipv4(&pair_4, IPPROTO_ICMP);
			if ( session_entry_p != NULL){
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false) { 
					pr_warning("NAT64: Could NOT remove the session entry for IPv4 UDP route.");
					return false;
				}
				kfree(session_entry_p);
			}
			break;
		case 7:
			addr1 = (*rst).ipv6_src_address;
			addr2 = (*rst).ipv6_dst_address;
			p1 = (*rst).ipv6_src_port_or_id;
			p2 = (*rst).ipv6_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI6 port: %d\n", &addr1.s6_addr, ntohs(p1));
			pr_debug("NAT64 dst Address: %pI6 port: %d\n", &addr2.s6_addr, ntohs(p2));

			pair_6.remote.address = addr1;
			pair_6.remote.pi.port = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.port = p2;

			session_entry_p = nat64_get_session_entry_by_ipv6(&pair_6, IPPROTO_TCP);
			if ( session_entry_p != NULL){
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false) {
					pr_warning("NAT64: Could NOT remove the session entry for IPv6 UDP route.");
					return false;
				}
				kfree(session_entry_p);
			}
			break;
		case 8:
			addr3 = (*rst).ipv4_src_address;
			addr4 = (*rst).ipv4_dst_address;
			p3 = (*rst).ipv4_src_port_or_id;
			p4 = (*rst).ipv4_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI4 port: %d\n", &addr3.s_addr, ntohs(p3));
			pr_debug("NAT64 dst Address: %pI4 port: %d\n", &addr4.s_addr, ntohs(p4));

			pair_4.remote.address = addr4;
			pair_4.remote.pi.port = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.port = p3;

			session_entry_p = nat64_get_session_entry_by_ipv4(&pair_4, IPPROTO_TCP);
			if ( session_entry_p != NULL){
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false) {
					pr_warning("NAT64: Could NOT remove the session entry for IPv4 UDP route.");
					return false;
				}
				kfree(session_entry_p);
			}
			break;
		case 18:
			addr1 = (*rst).ipv6_src_address;
			addr2 = (*rst).ipv6_dst_address;
			p1 = (*rst).ipv6_src_port_or_id;
			p2 = (*rst).ipv6_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI6 port: %d\n", &addr1.s6_addr, ntohs(p1));
			pr_debug("NAT64 dst Address: %pI6 port: %d\n", &addr2.s6_addr, ntohs(p2));

			pair_6.remote.address = addr1;
			pair_6.remote.pi.port = p1;
			pair_6.local.address = addr2;
			pair_6.local.pi.port = p2;

			session_entry_p = nat64_get_session_entry_by_ipv6(&pair_6, IPPROTO_UDP);
			if ( session_entry_p != NULL) {
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false) {
					pr_warning("NAT64: Could NOT remove the session entry for IPv6 UDP route.");
					return false;
				} 
				kfree(session_entry_p);
			}
			break;
		case 19:
			addr3 = (*rst).ipv4_src_address;
			addr4 = (*rst).ipv4_dst_address;
			p3 = (*rst).ipv4_src_port_or_id;
			p4 = (*rst).ipv4_dst_port_or_id;
			pr_debug("NAT64 src Address: %pI4 port: %d\n", &addr3.s_addr, ntohs(p3));
			pr_debug("NAT64 dst Address: %pI4 port: %d\n", &addr4.s_addr, ntohs(p4));

			pair_4.remote.address = addr4;
			pair_4.remote.pi.port = p4;
			pair_4.local.address = addr3;
			pair_4.local.pi.port = p3;

			session_entry_p = nat64_get_session_entry_by_ipv4(&pair_4, IPPROTO_UDP);
			if ( session_entry_p != NULL) {
				result = nat64_remove_session_entry(session_entry_p);
				if (result == false){ 
					pr_warning("NAT64: Could NOT remove the session entry for IPv4 UDP route.");
					return false;
				}  
				kfree(session_entry_p);
			}
		break;
		default:
			break;
	}

	return true;
}

bool nat64_print_bib_table(struct route_struct *rst, __u32 *count_out,
		struct bib_entry_us **bibs_us_out)
{
	struct bib_entry **bibs_ks = NULL; // ks = kernelspace. Array of pointers to bib entries.
	struct bib_entry_us *bibs_us = NULL; // us = userspace. Array of bib entries.
	__u32 counter, count;

	count = nat64_bib_to_array(rst->protocol, &bibs_ks);
	if (count < 1)
		goto failure;

	bibs_us = kmalloc(count * sizeof(struct bib_entry_us), GFP_ATOMIC);
	if (!bibs_us)
		goto failure;

	for (counter = 0; counter < count; counter++) {
		bibs_us[counter].ipv4 = bibs_ks[counter]->ipv4;
		bibs_us[counter].ipv6 = bibs_ks[counter]->ipv6;
	}

	kfree(bibs_ks);
	*count_out = count;
	*bibs_us_out = bibs_us;
	return true;

failure:
	kfree(bibs_ks);
	return false;
}

bool nat64_print_session_table(struct route_struct *rst, __u32 *count_out,
		struct session_entry_us **sessions_us_out)
{
	struct session_entry **sessions_ks = NULL;
	struct session_entry_us *sessions_us = NULL;
	__u32 counter, count;

	count = nat64_session_table_to_array(rst->protocol, &sessions_ks);
	if (count < 1)
		goto failure;
	
	sessions_us = kmalloc(count * sizeof(struct session_entry_us), GFP_ATOMIC);
	if (!sessions_us)
		goto failure;

	for (counter = 0; counter < count; counter++) {
		sessions_us[counter].ipv6 = sessions_ks[counter]->ipv6;
		sessions_us[counter].ipv4 = sessions_ks[counter]->ipv4;
		sessions_us[counter].is_static = sessions_ks[counter]->is_static;
		sessions_us[counter].dying_time = sessions_ks[counter]->dying_time;
		sessions_us[counter].l4protocol = sessions_ks[counter]->l4protocol;
	}
	
	kfree(sessions_ks);
	*count_out = count;
	*sessions_us_out = sessions_us;
	return true;

failure:
	kfree(sessions_ks);
	return false;
}
