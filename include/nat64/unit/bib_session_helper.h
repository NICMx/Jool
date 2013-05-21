#include <linux/types.h>

#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"


bool bib_assert(int l4_proto, struct bib_entry **expected_bibs);
#define BIB_ASSERT(l4_proto, ...) bib_assert(l4_proto, (struct bib_entry*[]) { __VA_ARGS__ , 0 })

bool session_assert(int l4_proto, struct session_entry **expected_sessions);
#define SESSION_ASSERT(l4_proto, ...) session_assert(l4_proto, (struct session_entry*[]) { __VA_ARGS__ , 0 })

int print_bibs(int l4_proto);
int print_sessions(int l4_proto);
