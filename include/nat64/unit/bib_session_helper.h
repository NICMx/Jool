#include <linux/types.h>

#include "nat64/mod/bib_db.h"
#include "nat64/mod/session_db.h"


bool bib_assert(l4_protocol l4_proto, struct bib_entry **expected_bibs);
#define BIB_ASSERT(l4_proto, ...) bib_assert(l4_proto, (struct bib_entry*[]) { __VA_ARGS__ , NULL })

bool session_assert(l4_protocol l4_proto, struct session_entry **expected_sessions);
#define SESSION_ASSERT(l4_proto, ...) session_assert(l4_proto, (struct session_entry*[]) { __VA_ARGS__ , NULL })

int print_bibs(l4_protocol l4_proto);
int print_sessions(l4_protocol l4_proto);
