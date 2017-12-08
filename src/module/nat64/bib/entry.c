#include "nat64/mod/stateful/bib/entry.h"
#include "nat64/mod/common/address.h"

void bib_session_init(struct bib_session *bs)
{
	bs->bib_set = false;
	bs->session_set = false;
}

bool session_equals(const struct session_entry *s1,
		const struct session_entry *s2)
{
	return taddr6_equals(&s1->src6, &s2->src6)
			&& taddr6_equals(&s1->dst6, &s2->dst6)
			&& taddr4_equals(&s1->src4, &s2->src4)
			&& taddr4_equals(&s1->dst4, &s2->dst4)
			&& (s1->proto == s2->proto);
}
