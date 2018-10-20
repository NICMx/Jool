#include "framework/bib.h"
#include "common/str_utils.h"

int bib_inject(struct xlator *jool,
		char *addr6, u16 port6, char *addr4, u16 port4,
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

	error = bib_add_static(jool, entry, NULL);
	if (error) {
		log_err("Errcode %d on BIB DB add.", error);
		return error;
	}

	return 0;
}

