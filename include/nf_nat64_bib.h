#ifndef _NF_NAT64_BIB_H
#define _NF_NAT64_BIB_H

#include "nf_nat64_types.h"

/** Un registro BIB, normalmente parte de alguna de las tablas. */
struct bib_entry
{
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;

	// Registros de sesión que pertenecen a este BIB.
	struct list_head session_entries;
};

/**
 * Inicializa las tres tablas (UDP, TCP e ICMP).
 * Llamar al principio desde afuera una sola vez antes de llamar al resto de las funciones.
 */
void nat64_bib_init(void);
/**
 * Agrega el registro "entry" a la tabla "protocol".
 * Warning: No se preocupa por averiguar si el registro ya esta en la tabla.
 */
bool nat64_add_bib_entry(struct bib_entry *entry, int protocol);
/**
 * Devuelve el registro BIB de la tabla "protocol" cuya direccion IPv4 es "addr".
 */
struct bib_entry* nat64_get_bib_entry_by_ipv4_addr(struct ipv4_tuple_address *addr, int l4protocol);
/**
 * Devuelve el registro BIB de la tabla "protocol" cuya direccion IPv6 es "addr".
 */
struct bib_entry* nat64_get_bib_entry_by_ipv6_addr(struct ipv6_tuple_address *addr, int l4protocol);
/**
 * Intenta remover el registro "entry" de la tabla "protocol".
 * No lo va a lograr si "entry" todavia tiene registros de sesion vivos.
 */
bool nat64_remove_bib_entry(struct bib_entry *entry, int l4protocol);

void nat64_bib_destroy(void);

/**
 * Genera la BIB entry EN MEMORIA DINÁMICA.
 * Esto es, si no la vas a insertar a alguna tabla TIENES QUE BORRARLA MANUALMENTE.
 * (Si la insertas a una tabla, ella se encarga de borrarlo cuando le toca cuello.)
 */
struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6);
bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2);

#endif
