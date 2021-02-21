#include "framework/bib.h"

#include "framework/address.h"

int bib_inject(struct xlator *jool,
		char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol proto, struct bib_entry *entry)
{
	struct jnl_state *state;
	int error;

	error = str_to_addr4(addr4, &entry->addr4.l3);
	if (error)
		return error;
	error = str_to_addr6(addr6, &entry->addr6.l3);
	if (error)
		return error;
	entry->addr4.l4 = port4;
	entry->addr6.l4 = port6;

	state = jnls_create(jool);
	if (!state)
		return -ENOMEM;

	error = bib_add_static(jool->nat64.bib, entry, state);

	jnls_destroy(state);

	return error;
}
EXPORT_UNIT_SYMBOL(bib_inject)
