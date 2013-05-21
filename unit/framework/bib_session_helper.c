#include "nat64/unit/bib_session_helper.h"

static int count_bibs(struct bib_entry *bib, void *arg)
{
	u16 *result = arg;
	(*result)++;
	return 0;
}

bool bib_assert(int l4_proto, struct bib_entry **expected_bibs)
{
	int expected_count = 0;
	int actual_count = 0;

	if (bib_for_each(l4_proto, count_bibs, &actual_count) != 0) {
		log_warning("Could not count the BIB entries in the database for some reason.");
		return false;
	}

	while (expected_bibs[expected_count] != NULL) {
		struct bib_entry *expected = expected_bibs[expected_count];
		struct bib_entry *actual = bib_get_by_ipv6(&expected->ipv6, l4_proto);

		if (!actual) {
			log_warning("Could not find BIB entry [%pI6c#%u, %pI4#%u] in the database.",
					&expected->ipv6.address, expected->ipv6.l4_id,
					&expected->ipv4.address, expected->ipv4.l4_id);
			return false;
		}

		expected_count++;
	}

	if (expected_count != actual_count) {
		log_warning("Expected %d BIB entries in the database. Found %d.", expected_count,
				actual_count);
		return false;
	}

	return true;
}

static int count_sessions(struct session_entry *session, void *arg)
{
	u16 *result = arg;
	(*result)++;
	return 0;
}

bool session_assert(int l4_proto, struct session_entry **expected_sessions)
{
	int expected_count = 0;
	int actual_count = 0;

	if (session_for_each(l4_proto, count_sessions, &actual_count) != 0) {
		log_warning("Could not count the session entries in the database for some reason.");
		return false;
	}

	while (expected_sessions[expected_count] != NULL) {
		struct session_entry *expected = expected_sessions[expected_count];
		struct session_entry *actual = session_get_by_ipv6(&expected->ipv6, l4_proto);

		if (!actual) {
			log_warning("Could not find session entry %d [%pI6c#%u, %pI6c#%u, %pI4#%u, %pI4#%u] "
					"in the database.", expected_count,
					&expected->ipv6.remote.address, expected->ipv6.remote.l4_id,
					&expected->ipv6.local.address, expected->ipv6.local.l4_id,
					&expected->ipv4.local.address, expected->ipv4.local.l4_id,
					&expected->ipv4.remote.address, expected->ipv4.remote.l4_id);
			return false;
		}

		expected_count++;
	}

	if (expected_count != actual_count) {
		log_warning("Expected %d session entries in the database. Found %d.", expected_count,
				actual_count);
		return false;
	}

	return true;
}

static int print_bibs_aux(struct bib_entry *bib, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI4#%u]",
			bib->is_static ? "Static" : "Dynamic",
			&bib->ipv6.address, bib->ipv6.l4_id,
			&bib->ipv4.address, bib->ipv4.l4_id);
	return 0;
}

int print_bibs(int l4_proto)
{
	log_debug("BIB:");
	return bib_for_each(l4_proto, print_bibs_aux, NULL);
}

static int print_sessions_aux(struct session_entry *session, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI6c#%u, %pI4#%u, %pI4#%u]",
			session->bib->is_static ? "Static" : "Dynamic",
			&session->ipv6.remote.address, session->ipv6.remote.l4_id,
			&session->ipv6.local.address, session->ipv6.local.l4_id,
			&session->ipv4.local.address, session->ipv4.local.l4_id,
			&session->ipv4.remote.address, session->ipv4.remote.l4_id);
	return 0;
}

int print_sessions(int l4_proto)
{
	log_debug("Sessions:");
	return session_for_each(l4_proto, print_sessions_aux, NULL);
}
