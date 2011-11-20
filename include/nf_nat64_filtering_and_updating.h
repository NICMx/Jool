//
//  nat64_filtering_n_updating.h
//  
//
//  Created by David Valenzuela Rodríguez on 29/10/11.
//  Copyright 2011 ITESM. All rights reserved.
//

#ifndef _nat64_filtering_n_updating_h
#define _nat64_filtering_n_updating_h

/*	Data structures	*/

//IPv4 transport address

struct nat64_ipv4_ta {
	struct in_addr ip4a;	//32 bits
	__be16 port;		//16 bits
};

//IPv6 transport address

struct nat64_ipv6_ta {
	struct in6_addr ip6a;	//128 bits
	__be16 port;		//16 bits
};

//ST entry (TCP/UDP)

struct nat64_st_entry {
	struct nat64_ipv6_ta src_ta_6;
	struct nat64_ipv6_ta dst_ta_6;
	struct nat64_ipv4_ta src_ta_4;
	struct nat64_ipv4_ta dst_ta_4;
	int timestamp;		//timestamp in seconds
};

//ST node (TCP/UDP)

struct nat64_st_node {
	struct nat64_st_entry *info;
	struct nat64_st_node *next;
	struct nat64_st_node *prev;
};

//ST (TCP/UDP): doubly linked list

struct nat64_st {
	struct nat64_st_node *newest;
	struct nat64_st_node *oldest;
};

//BIB entry (TCP/UDP)

struct nat64_bib_entry {
	struct nat64_ipv6_ta ta_6;
	struct nat64_ipv4_ta ta_4;
};

//BIB node (TCP/UDP)

struct nat64_bib_node {
	struct nat64_bib_entry *info;
	struct nat64_bib_node *next;
	//struct nat64_st st_fragment;	//Each BIB node contains a fragment of the ST
};

//BIB (TCP/UDP): singly linked list

struct nat64_bib {
	struct nat64_bib_node *head;
};

struct nat64_pool_entry {
	struct nat64_ipv4_ta ta_4;
	struct nat64_pool_entry *next;
};


/*	Algorithms	*/

/*
 * This procedure initializes a given IPv6 transport address field.
 */
static inline void nat64_initialize_ipv6_ta(struct nat64_ipv6_ta *ta_6, struct in6_addr *ip6a, __be16 port)
{
	memcpy(&(ta_6->ip6a), ip6a, sizeof(struct in6_addr));
	ta_6->port = port;
	pr_debug("%pI6: ", (&ta_6->ip6a)->in6_u.u6_addr32);
	pr_debug("%hu", ta_6->port);
}

/*
 * This procedure initializes a given IPv4 transport address field.
 */
static inline void nat64_initialize_ipv4_ta(struct nat64_ipv4_ta *ta_4, struct in_addr *ip4a, __be16 port)
{
	//It's assumed that the prefix is already removed
	memcpy(&(ta_4->ip4a), ip4a, sizeof(struct in_addr));
	ta_4->port = port;
//	pr_debug("%dI4: ", (&ta_4->ip4a)->s_addr);
//	pr_debug("%hu", htons(port));
}

/*
 * This function receives the relevant information from a 5-tuple
 * and populates it into the structure defined for BIB entries.
 * 
 * BIB entries are created when an IPv6 node wants to communicate
 * with an IPv4 node.
 */
static inline void nat64_initialize_bib_entry(struct nat64_bib_entry
		*new_bib_entry, struct in6_addr *ip6a, __be16 port1,
		struct in_addr *ip4a, __be16 port2)
{
	nat64_initialize_ipv6_ta(&(new_bib_entry->ta_6), ip6a, port1);
	nat64_initialize_ipv4_ta(&(new_bib_entry->ta_4), ip4a, port2);
//	pr_debug("%pI6: ", ((&(new_bib_entry->ta_6))->ip6a).in6_u.u6_addr32);
//	pr_debug("%hu", htons(port1));
//	pr_debug("%dI4: ", ((&(new_bib_entry->ta_4))->ip4a).s_addr);
//	pr_debug("%hu", htons(port2));
}

/*
 * This function populates the structure defined for ST entries.
 * 
 * ST entries are created when an IPv6 node wants to communicate
 * with an IPv4 node.
 */
static inline void nat64_initialize_st_entry(struct nat64_st_entry *new_st_entry,
		struct in6_addr *src_ip6a, __be16 src_port1, struct in6_addr
		*dst_ip6a, __be16 dst_port1, struct in_addr *src_ip4a,
		__be16 src_port2, struct in_addr *dst_ip4a, __be16 dst_port2,
		int cpu_time)
{
	nat64_initialize_ipv6_ta(&(new_st_entry->src_ta_6), src_ip6a, src_port1);
	nat64_initialize_ipv6_ta(&(new_st_entry->dst_ta_6), dst_ip6a, dst_port1);
	nat64_initialize_ipv4_ta(&(new_st_entry->src_ta_4), src_ip4a, src_port2);
	nat64_initialize_ipv4_ta(&(new_st_entry->dst_ta_4), dst_ip4a, dst_port2);
	new_st_entry->timestamp = cpu_time;
}

static inline int nat64_ipv6_cmp(struct in6_addr *ip6a1, __be16 port1, struct in6_addr *ip6a2, __be16 port2)
{
	int res;
	res = memcmp(ip6a1, ip6a2, sizeof(struct in6_addr));
	if (res == 0) {
        	if (port1 < port2) {
			res = -1;
		} else if (port1 > port2) {
			res = 1;        
		}
	}
	return res;
}

static inline int nat64_ipv4_cmp(struct in_addr *ip4a1, __be16 port1, struct in_addr *ip4a2, __be16 port2)
{
	int res;
	
	res = memcmp(ip4a1, ip4a2, sizeof(struct in_addr));

	if (res == 0) {
		if (port1 < port2) {
			res = -1;
		} else if (port1 > port2) {
			res = 1;
		}
	}
	return res;
}

static inline void nat64_bib_free_entry(struct nat64_bib_entry *bib_entry)
{
	kfree(bib_entry);
}

static inline void nat64_bib_free_node(struct nat64_bib_node *bib_node)
{
	nat64_bib_free_entry(bib_node->info);
	kfree(bib_node);
}

//BIB

//Esta función regresa true si encuentra el BIB y false si no. Deja Null a la referencia de bib_entry si no encuentra la BIB.
//Si encuentra la BIB, la modifica por referencia. 
static inline bool nat64_bib_select(struct nat64_bib *bib, struct in6_addr *ip6a, __be16 port, struct nat64_bib_entry * bib_entry)
{
	struct nat64_bib_node * current_node;

	bib_entry = NULL;
	current_node = bib->head;
	
	while (current_node != NULL) {
		if (nat64_ipv6_cmp(ip6a, port, &current_node->info->ta_6.ip6a, current_node->info->ta_6.port) == 0) {
			bib_entry = current_node->info;
			return true;
        	}
         	current_node = current_node->next;
	}
   	return false;
}

//Esta función inserta un registro en BIB, usando como parámetro el registro
static inline void nat64_bib_insert(struct nat64_bib *bib, struct nat64_bib_entry *bib_entry)
{
	struct nat64_bib_node *bib_node, *previous, *current_node;
	bib_node = (struct nat64_bib_node *) kmalloc(sizeof(struct nat64_bib_node *), GFP_KERNEL);

	if (bib_node != NULL) {
		bib_node->info = bib_entry;
		previous = NULL;
		current_node = bib->head;
		
		//Iterate through the list
		while (current_node != NULL && nat64_ipv6_cmp(&bib_entry->ta_6.ip6a, bib_entry->ta_6.port, &current_node->info->ta_6.ip6a, current_node->info->ta_6.port) > 0) {
			previous = current_node;
			current_node = current_node->next;
		}
		
		if (current_node == NULL) {
			bib_node->next = NULL;
			if (previous == NULL) {
				//First node: quiere decir que tiene el t.a.
				bib->head = bib_node;
			} else {
				//Last node: quiere decir que tiene el t.a.
				previous->next = bib_node;
			}
		} else {
			//Any other node
			bib_node->next = current_node;
			previous->next = bib_node;
		}
	}
}

//Esta función elimina un registro de BIB, usando como parámetro la IPv6 t.a.
static inline void nat64_bib_delete(struct nat64_bib *bib, struct in6_addr *ip6a, __be16 port)
{
	struct nat64_bib_node *previous, *current_node;
	previous = NULL;
	current_node = bib->head;
	
	while (current_node != NULL) {
		if (nat64_ipv6_cmp(ip6a, port, &current_node->info->ta_6.ip6a, current_node->info->ta_6.port) == 0) {
			if (previous == NULL) {
				bib->head = current_node->next;
			} else {
				previous->next = current_node->next;
			}
			nat64_bib_free_node(current_node);
			break;
	        }
		previous = current_node;
		current_node = current_node->next;
	}
}

//ST

//Esta función regresa un registro de ST, usando como parámetros la IPv4 t.a. fuente y la IPv4 t.a. destino
//Se debe utilizar la estructura de árbol binario (para agilizar la búsqueda por dirección de transporte)
static inline struct nat64_st_entry *nat64_st_select(struct nat64_st *st, struct in_addr *src_ip4a, __be16 src_port, struct in_addr *dst_ip4a, __be16 dst_port)
{
    struct nat64_st_entry *st_entry;
    struct nat64_st_node *current_node;
    
    st_entry = NULL;
    //FIXME NO HAY HEAD EN nat64_st por eso falla: current_node = st->head; Se usa la siguiente linea:
    current_node = st->oldest; //FIXME ASUMO que OLDEST es la cabeza de la lista
    
    while (current_node != NULL) {
        if (nat64_ipv4_cmp(src_ip4a, src_port, &current_node->info->src_ta_4.ip4a, current_node->info->src_ta_4.port) == 0
        		&& nat64_ipv4_cmp(dst_ip4a, dst_port, &current_node->info->dst_ta_4.ip4a, current_node->info->dst_ta_4.port) == 0)
        {
            st_entry = current_node->info;
            break;
        }
        current_node = current_node->next;
    }
    
    return st_entry;
}

//Esta función inserta un registro en ST, usando como parámetro el registro
//Se debe utilizar la estructura de árbol binario (para agilizar la inserción por dirección de transporte)
// y lista encadenada (para que se agregue al inicio de acuerdo a su timestamp)
static inline void nat64_st_insert(struct nat64_st *st, struct nat64_st_entry *st_entry)
{
	struct nat64_st_node *st_node;
	//struct nat64_st_node *current_node;
	st_node = (struct nat64_st_node *) kmalloc(sizeof(struct nat64_st_node *), GFP_KERNEL);
	
	if (st_node != NULL) {
		st_node->info = st_entry;
		st_node->next = NULL;
		//current_node = st->head;

		if (st->newest == NULL) {
			//ST is empty
			st_node->prev = NULL;
			st->oldest = st_node;
		} else {
			//ST is not empty
			st_node->prev = st->newest;
			st->newest->next = st_node;
		}

		st->newest = st_node;
        /*
         BINARY TREE
         if (current_node == NULL) {
         //First node
         st_node->next = NULL;
         st_node->prev = NULL;
         st->head = st_node;
         } else {
         if (nat64_ipv6_cmp(bib_entry->ta_6.ip6a, bib_entry->ta_6.port, current_node->info->ta_6.ip6a, current_node->info->ta_6.port) < 0) {
         //First node
         bib_node->next = current_node;
         bib->head = bib_node;
         } else {
         while (current_node != NULL && nat64_ipv6_cmp(bib_entry->ta_6.ip6a, bib_entry->ta_6.port, current_node->info->ta_6.ip6a, current_node->info->ta_6.port) > 0) {
         current_node = current_node->next;
         }
         //Any other node after the first
         bib_node->next = current_node->next;
         current_node->next = bib_node;
         }
         }
         */
	}
}

//Esta función elimina todo registro de ST cuyo "timestamp" indique que su "lifetime" ha terminado
//Se debe utilizar la estructura de lista encadenada, navegando desde el nodo más antiguo
static inline void nat64_st_delete(struct nat64_st *st, int lapse, int current_nodeTime)
{
	if (st->oldest != NULL) {
		if (st->oldest->next == NULL) {
			if (st->oldest->info->timestamp < current_nodeTime - lapse) {
				kfree(st->oldest);
				st->oldest = NULL;
			}
		} else {
			while (st->oldest != NULL && st->oldest->info->timestamp < current_nodeTime - lapse) {
				//Close session
				st->oldest = st->oldest->next;
				kfree(st->oldest->prev);	//CHECK ME
				st->oldest->prev = NULL;
			}
		}
	}
}

//Esta función actualiza el campo "timestamp", usando como parámetro el nuevo "timestamp", y lleva al registro al inicio de la fila
//Se debe utilizar el árbol binario para la búsqueda
//Se debe utilizar la lista encadenada para cambiar el nodo de posición
static inline void nat64_st_update(struct nat64_st *st, struct in_addr *src_ip4a, __be16 src_port, struct in_addr *dst_ip4a, __be16 dst_port, int new_timestamp)
{
	struct nat64_st_node *current_node;
	current_node = st->oldest;

	while (current_node != NULL) {
		if (nat64_ipv4_cmp(src_ip4a, src_port, &current_node->info->src_ta_4.ip4a, current_node->info->src_ta_4.port) == 0
			&& nat64_ipv4_cmp(dst_ip4a, dst_port, &current_node->info->dst_ta_4.ip4a, current_node->info->dst_ta_4.port) == 0)
		{
			//move
			if (current_node->next != NULL) {
				(current_node->prev)->next = current_node->next;
				(current_node->next)->prev = current_node->prev;
				(st->newest)->next = current_node;
				current_node->prev = st->newest;
				current_node->next = NULL;
				st->newest = current_node;
			}
			//update timestamp
			(st->newest)->info->timestamp = new_timestamp;
			break;
		}
		current_node = current_node->next;
	}
}

//Other functions

static inline struct nat64_ipv4_ta *nat64_ipv4_pool_address_available(struct nat64_ipv6_ta *ta_6) {

	/* Mask used to obtain some bits from the IPv6 to make the translation */
	struct in6_addr *ip6_mask_addr;

	/* Final IPv4 obtained from the incoming IPv6 */
  	struct in_addr *ip_pool_addr;

	/* Return struct */
	struct nat64_ipv4_ta *outgoing_ipv4_from_pool;

	int ret = 0;
	pr_debug("INSIDE THE MODULE");
	ip_pool_addr = (struct in_addr *) kmalloc (sizeof(struct in_addr), GFP_KERNEL);
	ip6_mask_addr = (struct in6_addr *) kmalloc (sizeof(struct in6_addr), GFP_KERNEL);
	
	ret = in4_pton("10.0.0.0",-1, (u_int8_t *)ip_pool_addr, '\x0', NULL);
	if (!ret) {
		pr_debug("NAT64: Cannot set the base IPv4.");
	}
	//pr_debug("%pI4",&(ip_pool_addr->s_addr));

	if (ip_pool_addr != NULL) {	
		if (ip6_mask_addr != NULL) {
			/* in6_pton sets IPv6 mask to 1's */
			ret = in6_pton("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", -1, (u_int8_t *)ip6_mask_addr, '\x0', NULL);
			if (!ret) {
				pr_debug("NAT64: Cannot set the IPv6 mask to 1's.");
				return NULL;
			}
			//pr_debug("%pI6", &(ip6_mask_addr->s6_addr16));
				
		}
	} else {
		pr_debug("NAT64: Not enough space to store the IPv4.");
		return NULL;
	}
	pr_debug("EXIT MODULE");
	return outgoing_ipv4_from_pool;	

   	
   	//ip_pool_addr.s_addr = NULL;
   	//ta_6->ip6a.in6u.u6_addr32 & ip6_mask;
/*
* Single range specification.
  32struct nf_nat_range {
          //Set to OR of flags above.
         unsigned int flags;
  
          //Inclusive: network order. 
          __be32 min_ip, max_ip;
  
         //Inclusive: network order 
          union nf_conntrack_man_proto min, max;
  };

*/
}

/*
 * Returns the Greatest Common Divisor
 */
static inline int gcd(int a, int b)
{
	int c, d, e, f;
	
	e = 2;
	f = 1;
	
	if (a < b) {
		c = a;
		d = b;
	} else {
		c = b;
		d = a;
	}
	
	do {
		if (c % e == 0 && d % e == 0) {
			f = f * e;
			c = c / e;
			d = d / e;
			e = 2;
		} else {
			e++;
		}
	} while (e <= c);
	return f;
}
#endif

