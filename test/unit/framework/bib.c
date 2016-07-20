#include "nat64/unit/bib.h"
#include "nat64/common/str_utils.h"

static int bib_print_aux(struct bib_entry *bib, bool is_static, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI4#%u]",
			is_static ? "Static" : "Dynamic",
			&bib->ipv6.l3, bib->ipv6.l4,
			&bib->ipv4.l3, bib->ipv4.l4);
	return 0;
}

int bib_print(struct bib *db, l4_protocol l4_proto)
{
	struct bib_foreach_func func = { .cb = bib_print_aux, .arg = NULL, };
	log_debug("BIB:");
	return bib_foreach(db, l4_proto, &func, NULL);
}

int bib_inject(struct bib *db, char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol proto, struct bib_entry *entry)
{
	int error;

	error = str_to_addr4(addr4, &entry->ipv4.l3);
	if (error)
		return error;
	error = str_to_addr6(addr6, &entry->ipv6.l3);
	if (error)
		return error;
	entry->ipv4.l4 = port4;
	entry->ipv6.l4 = port6;

	error = bib_add_static(db, entry, NULL);
	if (error) {
		log_err("Errcode %d on BIB DB add.", error);
		return error;
	}

	return 0;
}

