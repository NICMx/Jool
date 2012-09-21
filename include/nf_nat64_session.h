#ifndef _NF_NAT64_SESSION_H
#define _NF_NAT64_SESSION_H

#include "nf_nat64_types.h"
#include "nf_nat64_bib.h"

struct session_entry
{
	int l4protocol;
	/** BIB que posee a esta sesion.*/
	struct bib_entry *bib;
	/** Que si debe no expirar o si. */
	bool is_static;
	/** Número de milisegundo en el cual este registro debe morir. */
	unsigned int dying_time;

	struct ipv6_pair ipv6;
	struct ipv4_pair ipv4;

	struct list_head entries_from_bib;
	struct list_head all_sessions;
};

void nat64_session_init(void);
bool nat64_add_session_entry(struct session_entry *entry);
struct session_entry *nat64_get_session_entry_by_ipv4(struct ipv4_tuple_address *remote,
		struct ipv4_tuple_address *local, int l4protocol);
struct session_entry* nat64_get_session_entry_by_ipv6(struct ipv6_tuple_address *local,
		struct ipv6_tuple_address *remote, int l4protocol);
void nat64_update_session_lifetime(struct session_entry *entry, unsigned int ttl);
bool nat64_remove_session_entry(struct session_entry *entry);
void nat64_clean_old_sessions(void);
void nat64_session_destroy(void);

/** Solamente considera el protocolo, direcciones y puertos. */
bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2);

#endif
