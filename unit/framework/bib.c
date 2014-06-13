#include "nat64/unit/bib.h"
#include "nat64/comm/str_utils.h"

static int count_bibs(struct bib_entry *bib, void *arg)
{
	u16 *result = arg;
	(*result)++;
	return 0;
}

bool bib_assert(l4_protocol l4_proto, struct bib_entry **expected_bibs)
{
	int expected_count = 0;
	int actual_count = 0;

	if (is_error(bibdb_for_each(l4_proto, count_bibs, &actual_count))) {
		log_err("Could not count the BIB entries in the database for some reason.");
		return false;
	}

	while (expected_bibs[expected_count] != NULL) {
		struct bib_entry *expected = expected_bibs[expected_count];
		struct bib_entry *actual;
		int error;

		error = bibdb_get_by_ipv6(&expected->ipv6, l4_proto, &actual);
		if (error) {
			log_err("Error %d while trying to find BIB entry [%pI6c#%u, %pI4#%u] in the DB.",
					error, &expected->ipv6.address, expected->ipv6.l4_id,
					&expected->ipv4.address, expected->ipv4.l4_id);
			return false;
		}

		expected_count++;
	}

	if (expected_count != actual_count) {
		log_err("Expected %d BIB entries in the database. Found %d.", expected_count,
				actual_count);
		return false;
	}

	return true;
}

static int bib_print_aux(struct bib_entry *bib, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI4#%u]",
			bib->is_static ? "Static" : "Dynamic",
			&bib->ipv6.address, bib->ipv6.l4_id,
			&bib->ipv4.address, bib->ipv4.l4_id);
	return 0;
}

int bib_print(l4_protocol l4_proto)
{
	log_debug("BIB:");
	return bibdb_for_each(l4_proto, bib_print_aux, NULL);
}

bool bib_inject_str(unsigned char *addr4_str, u16 port4, unsigned char *addr6_str, u16 port6,
		l4_protocol l4_proto)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (is_error(str_to_addr4(addr4_str, &addr4)))
		return false;
	if (is_error(str_to_addr6(addr6_str, &addr6)))
		return false;

	return bib_inject(&addr4, port4, &addr6, port6, l4_proto);
}

bool bib_inject(struct in_addr *addr4, u16 port4, struct in6_addr *addr6, u16 port6,
		l4_protocol l4_proto)
{
	struct ipv4_tuple_address taddr4 = {
			.address = *addr4,
			.l4_id = port4,
	};
	struct ipv6_tuple_address taddr6 = {
			.address = *addr6,
			.l4_id = port6,
	};
	struct bib_entry *bib;
	int error;

	bib = bib_create(&taddr4, &taddr6, false, l4_proto);
	if (!bib) {
		log_err("Could not allocate the BIB entry.");
		return false;
	}

	error = bibdb_add(bib, l4_proto);
	if (error) {
		log_err("Could not insert the BIB entry to the table: %d", error);
		return false;
	}

	return true;
}
