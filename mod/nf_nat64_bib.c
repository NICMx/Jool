#include <linux/module.h>
#include <linux/printk.h>

#include "nf_nat64_bib.h"

/********************************************
 * Estructuras y variables privadas.
 ********************************************/

// Tabla de hash que indexa por direcciones de IPv4.
// (este código genera la estructura "ipv4_table" que se usa abajo).
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_tuple_address
#define VALUE_TYPE struct bib_entry
#include "nf_nat64_hash_table.c"

// Tabla de hash que indexa por direcciones de IPv6.
// (este código genera la estructura "ipv6_table" que se usa abajo).
#define HTABLE_NAME ipv6_table
#define KEY_TYPE struct ipv6_tuple_address
#define VALUE_TYPE struct bib_entry
#include "nf_nat64_hash_table.c"

// Definición de una BIB.
struct bib_table
{
	/** Indexa los registros por direccion de IPv4. */
	struct ipv4_table ipv4;
	/** Indexa los registros por direccion de IPv6. */
	struct ipv6_table ipv6;
};

// Las tres instancias de BIB.
static struct bib_table bib_udp;
static struct bib_table bib_tcp;
static struct bib_table bib_icmp;

/********************************************
 * Funciones auxiliares, privadas.
 ********************************************/

static struct bib_table *get_bib_table(int l4protocol)
{
	switch (l4protocol) {
	case IPPROTO_UDP:
		return &bib_udp;
	case IPPROTO_TCP:
		return &bib_tcp;
	case IPPROTO_ICMP:
		return &bib_icmp;
	}

	printk(KERN_CRIT "Error: Unknown l4 protocol (%d); no BIB mapped to it.", l4protocol);
	return NULL;
}

/*******************************
 * Funciones Publicas.
 *******************************/

void nat64_bib_init(void)
{
	ipv4_table_init(&bib_udp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_udp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);

	ipv4_table_init(&bib_tcp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_tcp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);

	ipv4_table_init(&bib_icmp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_icmp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);
}

struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6)
{
	struct bib_entry *result = (struct bib_entry *) kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	return result;
}

bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2)
{
	if (bib_1 == bib_2)
		return true;
	if (bib_1 == NULL || bib_2 == NULL)
		return false;

	if (!ipv4_tuple_address_equals(&bib_1->ipv4, &bib_2->ipv4))
		return false;
	if (!ipv6_tuple_address_equals(&bib_1->ipv6, &bib_2->ipv6))
		return false;

	return true;
}

bool nat64_add_bib_entry(struct bib_entry *entry, int l4protocol)
{
	bool indexed_by_ipv4, indexed_by_ipv6;
	struct bib_table *bib = get_bib_table(l4protocol);

	indexed_by_ipv4 = ipv4_table_put(&bib->ipv4, &entry->ipv4, entry);
	indexed_by_ipv6 = ipv6_table_put(&bib->ipv6, &entry->ipv6, entry);

	if (!indexed_by_ipv4 || !indexed_by_ipv6) {
		ipv4_table_remove(&bib->ipv4, &entry->ipv4, false, false);
		ipv6_table_remove(&bib->ipv6, &entry->ipv6, false, false);
		return false;
	}

	return true;
}

struct bib_entry *nat64_get_bib_entry_by_ipv4_addr(struct ipv4_tuple_address *addr, int l4protocol)
{
	printk(KERN_DEBUG "Searching BIB entry for address %pI4#%d...", &addr->address, addr->pi.port);
	return ipv4_table_get(&get_bib_table(l4protocol)->ipv4, addr);
}

struct bib_entry *nat64_get_bib_entry_by_ipv6_addr(struct ipv6_tuple_address *addr, int l4protocol)
{
	printk(KERN_DEBUG "Searching BIB for address %pI6#%d...", &addr->address, addr->pi.port);
	return ipv6_table_get(&get_bib_table(l4protocol)->ipv6, addr);
}

/**
 * Remueve a "entry" de la tabla "protocol" (Nótese que solamente lo saca de la tabla; no lo kfreea).
 * Se asume que "entry" realmente existe dentro de "protocol".
 */
bool nat64_remove_bib_entry(struct bib_entry *entry, int l4protocol)
{
	bool removed_from_ipv4, removed_from_ipv6;
	struct bib_table *table = get_bib_table(l4protocol);

	// Si todavía hay sesiones relacionadas con esta BIB, ignorar la petición de borrarla.
	if (!list_empty(&entry->session_entries))
		return false;

	// Liberar la memoria de ambas tablas.
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);

	if (removed_from_ipv4 && removed_from_ipv6)
		return true;
	if (!removed_from_ipv4 && !removed_from_ipv6)
		return false;

	// Por qué estaba indexada en una tabla pero no en la otra? Error de programación.
	printk(KERN_CRIT "Programming error: Weird BIB removal: ipv4:%d; ipv6:%d.", removed_from_ipv4, removed_from_ipv6);
	return true;
}

void nat64_bib_destroy(void)
{
	printk(KERN_DEBUG "Emptying the BIB tables...");

	// Las llaves no se necesitan liberar porque son parte de los valores.
	// Los valores solo se necesitan liberar en una sola tabla porque es el mismo valor en ambas tablas.

	ipv4_table_empty(&bib_udp.ipv4, false, false);
	ipv6_table_empty(&bib_udp.ipv6, false, true);

	ipv4_table_empty(&bib_tcp.ipv4, false, false);
	ipv6_table_empty(&bib_tcp.ipv6, false, true);

	ipv4_table_empty(&bib_icmp.ipv4, false, false);
	ipv6_table_empty(&bib_icmp.ipv6, false, true);
}
