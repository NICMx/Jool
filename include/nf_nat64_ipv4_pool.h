#ifndef _NF_NAT64_IPV4_POOL_H
#define _NF_NAT64_IPV4_POOL_H

#include <linux/slab.h>
#include <linux/inet.h>
#include "nf_nat64_types.h"
#include "nf_nat64_config.h"


// TODO (ramiro) quitar tipos dependientes de arquitectura.
// TODO (ramiro) quitar globales que no se usan.
// TODO (ramiro) poner 64k de puertos.

struct transport_addr_struct
{
	struct in_addr address;
	__u16 port;
	struct list_head list;
};

/**
 * TODO (ramiro) tiene aritmética que incluye big endian.
 *
 */
struct transport_addr_struct *get_udp_transport_addr(void);
struct transport_addr_struct *get_tcp_transport_addr(void);
struct transport_addr_struct *get_icmp_transport_addr(void);

void return_udp_transport_addr(struct transport_addr_struct *transport_addr);
void return_tcp_transport_addr(struct transport_addr_struct *transport_addr);
void return_icmp_transport_addr(struct transport_addr_struct *transport_addr);

void display(int num);

/**
 * Just like the gets above, except it stores the resulting address and port in "result" as a tuple
 * address, instead of returning it as a transport address.
 *
 * TODO (ramiro) el código está repetido 3 veces, y debería referenciar a los gets de arriba.
 * TODO (ramiro) pi no se usa.
 *
 * @param protocol Which protocol pool should we look the address in?
 * @param result will be filled with the new transport address obtained from the "protocol"'s pool.
 * @return true if an address could be extracted from the pool, false otherwise.
 */
bool ipv4_pool_get_new_transport_address(u_int8_t protocol, __be16 pi,
		struct ipv4_tuple_address *result);

/**
 * Reserves the "new_ipv4_transport_address". It's like the gets above, except the caller decides
 * which address and port it wants.
 *
 * Returns whether the "new_ipv4_transport_address" could be reserved.
 *
 * TODO (ramiro) falta la parte de reservar; solamente está regresando si la dirección está ocupada
 * o no.
 * TODO (ramiro) si nunca se han sacado puertos para la dirección "address", va a tronar porque no
 * valida que su port list exista a pesar de que usa lazy init.
 * TODO (ramiro) el código está repetido 3 veces.
 */
bool allocate_given_ipv4_transport_address(uint16_t protocol, struct ipv4_tuple_address * result);

/**
 * TODO (ramiro) está usando __be's que deberían ser u's.
 * TODO (ramiro) los contadores son de 16 bits, por lo que se arma un ciclo infinito.
 * TODO (ramiro) si nunca se han sacado puertos para la dirección "address", va a tronar porque no
 * valida que su port list exista a pesar de que usa lazy init.
 * TODO (ramiro) además no allocatea la lista de puertos que inserta a la tabla, por lo que todas
 * las entradas de la tabla apuntan a la misma lista de puertos.
 * TODO (ramiro) el código está repetido 4 veces.
 */
bool ipv4_pool_get_new_port(struct in_addr address, __be16 pi, struct ipv4_tuple_address *result);

void init_pools(struct config_struct *cs);
void destroy_pools(void);


#endif /* _NF_NAT64_IPV4_POOL_H */
