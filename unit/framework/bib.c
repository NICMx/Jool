#include "nat64/unit/bib.h"
#include "nat64/common/str_utils.h"

static int bib_print_aux(struct bib_entry *bib, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI4#%u]",
			bib->is_static ? "Static" : "Dynamic",
			&bib->ipv6.l3, bib->ipv6.l4,
			&bib->ipv4.l3, bib->ipv4.l4);
	return 0;
}

int bib_print(struct bib *db, l4_protocol l4_proto)
{
	log_debug("BIB:");
	return bibdb_foreach(db, l4_proto, bib_print_aux, NULL, NULL);
}

struct bib_entry *bib_inject(struct bib *db,
		char *addr6, u16 port6,
		char *addr4, u16 port4,
		l4_protocol proto)
{
	struct ipv4_transport_addr taddr4;
	struct ipv6_transport_addr taddr6;
	struct bib_entry *entry;
	int error;

	if (str_to_addr4(addr4, &taddr4.l3))
		return NULL;
	if (str_to_addr6(addr6, &taddr6.l3))
		return NULL;
	taddr4.l4 = port4;
	taddr6.l4 = port6;

	entry = bibentry_create(&taddr4, &taddr6, false, proto);
	if (!entry) {
		log_err("Could not allocate the BIB entry.");
		return NULL;
	}

	error = bibdb_add(db, entry);
	if (error) {
		log_err("Errcode %d on BIB DB add.", error);
		return NULL;
	}

	return entry;
}

