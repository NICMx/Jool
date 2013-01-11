#ifndef _NF_NAT64_IPV4_POOL_H
#define _NF_NAT64_IPV4_POOL_H

/**
 * @file
 * The pool of IPv4 addresses (and their ports).
 */

#include "nf_nat64_types.h"

// TODO recuerda revisar be's vs u's.


/**
 * Readies the rest of this module for future use.
 *
 * @param "true" if the initialization was successful, false otherwise.
 */
bool pool4_init(void);
/**
 * Frees resources allocated by the pool.
 */
void pool4_destroy(void);

/**
 * Inserts the "address" address (along with its 64k ports) into the "l4protocol" pool.
 * These elements will then become borrowable through the pool_get_* functions.
 */
bool pool4_register(u_int8_t l4protocol, struct in_addr *address);
/**
 * Removes the "address" address (along with its 64k ports) from the "l4_protocol" pool.
 * If something was borrowed (not in the pool at the moment) it will be erased later, when the pool
 * retrieves it.
 */
bool pool4_remove(u_int8_t l4protocol, struct in_addr *address);

/**
 * Reserves and returns some available IPv4 address from the "l4protocol" pool, along with one of
 * its ports. This port will be 'compatible' with "port".
 * 'Compatible' means same parity (mandatory) and range (only if available). See RFC 6146 section
 * 3.5.1.1 for more details on this port hack.
 *
 * @return the address/port you want to borrow.
 *		Will return NULL if there's nothing available (and compatible) in the pool.
 *		This resulting object will be stored in the heap. If you never return it (by means of
 *		pool4_return()), you're expected to kfree it once you're done with it.
 */
struct ipv4_tuple_address *pool4_get_any(u_int8_t l4protocol, __be16 port);
/**
 * Reserves and returns a transport address from the "l4protocol" pool.
 * The address's IPv4 address will be "address.address" and its port will be 'compatible' with
 * "address.pi.port".
 * 'Compatible' means same parity (mandatory) and range (only if available). See RFC 6146 section
 * 3.5.1.1 for more details on this port hack.
 *
 * @return the address/port you want to borrow.
 *		Will return NULL if there's nothing available (and compatible) in the pool.
 *		This resulting object will be stored in the heap. If you never return it (by means of
 *		pool4_return()), you're expected to kfree it once you're done with it.
 */
struct ipv4_tuple_address *pool4_get_similar(u_int8_t l4protocol, struct ipv4_tuple_address *address);
/**
 * Puts the (previously borrowed) address "address" back into the "l4protocol" pool. Meant to revert
 * the effect of the pool4_get_* functions.
 *
 * @paran address please note that, in order to maintain the symmetry with the pool4_get_*
 *		functions, and since we're assuming "address" is the one we returned there, this function
 *		will kfree "address" if successful. So don't use it after a successful call to this
 *		function.
 */
bool pool4_return(u_int8_t l4protocol, struct ipv4_tuple_address *address);


#endif /* _NF_NAT64_IPV4_POOL_H */


/**
 * TODO (ramiro) los contadores son de 16 bits, por lo que se arma un ciclo infinito.
 * TODO (ramiro) si nunca se han sacado puertos para la dirección "address", va a tronar porque no
 * valida que su port list exista a pesar de que usa lazy init.
 * TODO (ramiro) además no allocatea la lista de puertos que inserta a la tabla, por lo que todas
 * las entradas de la tabla apuntan a la misma lista de puertos.
 * TODO (ramiro) el código está repetido 4 veces.
 */
