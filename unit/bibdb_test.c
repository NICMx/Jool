#include <linux/module.h>
#include <linux/printk.h>
#include "nat64/unit/unit_test.h"
#include "nat64/unit/bib.h"
#include "nat64/mod/common/config.h"
#include "bib/db.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("BIB DB module test.");

static const l4_protocol PROTO = L4PROTO_TCP;
static struct bib_entry *bibs4[4][25];
static struct bib_entry *bibs6[4][25];

static bool assert4(unsigned int addr_id, unsigned int port)
{
	struct bib_entry *bib = NULL;
	struct ipv4_transport_addr taddr;
	bool success = true;

	taddr.l3.s_addr = cpu_to_be32(0xc0000200 | addr_id);
	taddr.l4 = port;

	if (bibs4[addr_id][port]) {
		success &= ASSERT_INT(0, bibdb_get4(&taddr, PROTO, &bib),
				"7th (%u %u) - get4", addr_id, port);
		success &= ASSERT_BOOL(true, bibdb_contains4(&taddr, PROTO),
				"7th (%u %u) - contains4", addr_id, port);
		success &= ASSERT_BIB(bibs4[addr_id][port], bib, "7th by 4");
	} else {
		success &= ASSERT_INT(-ESRCH, bibdb_get4(&taddr, PROTO, &bib),
				"get4 fails (%u %u)", addr_id, port);
		success &= ASSERT_BOOL(false, bibdb_contains4(&taddr, PROTO),
				"contains4 fails (%u %u)", addr_id, port);
	}

	if (bib)
		bibdb_return(bib);

	return success;
}

static bool assert6(unsigned int addr_id, unsigned int port)
{
	struct bib_entry *bib = NULL;
	struct ipv6_transport_addr taddr;
	bool success = true;

	taddr.l3.s6_addr32[0] = cpu_to_be32(0x20010db8);
	taddr.l3.s6_addr32[1] = 0;
	taddr.l3.s6_addr32[2] = 0;
	taddr.l3.s6_addr32[3] = cpu_to_be32(addr_id);
	taddr.l4 = port;

	if (bibs6[addr_id][port]) {
		success &= ASSERT_INT(0, bibdb_get6(&taddr, PROTO, &bib),
				"7th (%u %u) - get6", addr_id, port);
		success &= ASSERT_BIB(bibs6[addr_id][port], bib, "7th by 6");
	} else {
		success &= ASSERT_INT(-ESRCH, bibdb_get6(&taddr, PROTO, &bib),
				"get6 fails (%u %u)", addr_id, port);
	}

	if (bib)
		bibdb_return(bib);

	return success;
}

static bool test_db(void)
{
	unsigned int addr; /* Actual address is 192.0.2.addr. */
	unsigned int port;
	bool success = true;

	for (addr = 0; addr < 4; addr++) {
		for (port = 0; port < 25; port++) {
			success &= assert4(addr, port);
			success &= assert6(addr, port);
		}
	}

	return success;
}

static bool insert_test_bibs(void)
{
	struct bib_entry *bibs[8];
	unsigned int i;

	memset(bibs4, 0, sizeof(bibs4));
	memset(bibs6, 0, sizeof(bibs6));

	bibs[0] = bib_inject("2001:db8::2", 18, "192.0.2.3", 20, PROTO);
	bibs[1] = bib_inject("2001:db8::0", 10, "192.0.2.1", 21, PROTO);
	bibs[2] = bib_inject("2001:db8::0", 20, "192.0.2.2", 12, PROTO);
	bibs[3] = bib_inject("2001:db8::3", 10, "192.0.2.3", 10, PROTO);
	bibs[4] = bib_inject("2001:db8::3", 20, "192.0.2.2", 22, PROTO);
	bibs[5] = bib_inject("2001:db8::1", 19, "192.0.2.0", 20, PROTO);
	bibs[6] = bib_inject("2001:db8::2", 8, "192.0.2.0", 10, PROTO);
	bibs[7] = bib_inject("2001:db8::1", 9, "192.0.2.1", 11, PROTO);
	for (i = 0; i < ARRAY_SIZE(bibs); i++) {
		if (!bibs[i]) {
			log_debug("Allocation failed in index %u.", i);
			return false;
		}
		bibs[i]->is_static = true;
	}

	bibs6[2][18] = bibs4[3][20] = bibs[0];
	bibs6[0][10] = bibs4[1][21] = bibs[1];
	bibs6[0][20] = bibs4[2][12] = bibs[2];
	bibs6[3][10] = bibs4[3][10] = bibs[3];
	bibs6[3][20] = bibs4[2][22] = bibs[4];
	bibs6[1][19] = bibs4[0][20] = bibs[5];
	bibs6[2][8] = bibs4[0][10] = bibs[6];
	bibs6[1][9] = bibs4[1][11] = bibs[7];

	return test_db();
}

static bool test_flow(void)
{
	struct ipv4_prefix prefix;
	struct port_range range;
	bool success = true;

	if (!insert_test_bibs())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Delete full addresses using bibdb_delete_taddr4s().");
	prefix.address.s_addr = cpu_to_be32(0xc0000200);
	prefix.len = 31;
	range.min = 0;
	range.max = 65535;
	bibdb_delete_taddr4s(&prefix, &range);

	bibs6[0][10] = bibs4[1][21] = NULL;
	bibs6[1][19] = bibs4[0][20] = NULL;
	bibs6[2][8] = bibs4[0][10] = NULL;
	bibs6[1][9] = bibs4[1][11] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Delete only certain ports using bibdb_delete_taddr4s().");
	prefix.address.s_addr = cpu_to_be32(0xc0000202);
	prefix.len = 31;
	range.min = 11;
	range.max = 20;
	bibdb_delete_taddr4s(&prefix, &range);

	bibs6[2][18] = bibs4[3][20] = NULL;
	bibs6[0][20] = bibs4[2][12] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Flush using bibdb_delete_taddr4s().");
	prefix.address.s_addr = cpu_to_be32(0x00000000);
	prefix.len = 0;
	range.min = 0;
	range.max = 65535;
	bibdb_delete_taddr4s(&prefix, &range);

	bibs6[3][10] = bibs4[3][10] = NULL;
	bibs6[3][20] = bibs4[2][22] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	if (!insert_test_bibs())
		return false;

	log_debug("Flush using bibdb_flush().");
	bibdb_flush();
	memset(bibs4, 0, sizeof(bibs4));
	memset(bibs6, 0, sizeof(bibs6));
	success &= test_db();

	/* ---------------------------------------------------------- */

	if (!insert_test_bibs())
		return false;

	log_debug("Test bibdb_return().");

	bibdb_return(bibs4[3][20]);
	bibs6[2][18] = bibs4[3][20] = NULL;
	success &= test_db();

	bibdb_return(bibs4[1][21]);
	bibs6[0][10] = bibs4[1][21] = NULL;
	success &= test_db();

	bibdb_return(bibs4[2][12]);
	bibs6[0][20] = bibs4[2][12] = NULL;
	success &= test_db();

	bibdb_return(bibs4[3][10]);
	bibs6[3][10] = bibs4[3][10] = NULL;
	success &= test_db();

	bibdb_return(bibs4[2][22]);
	bibs6[3][20] = bibs4[2][22] = NULL;
	success &= test_db();

	bibdb_return(bibs4[0][20]);
	bibs6[1][19] = bibs4[0][20] = NULL;
	success &= test_db();

	bibdb_return(bibs4[0][10]);
	bibs6[2][8] = bibs4[0][10] = NULL;
	success &= test_db();

	bibdb_return(bibs4[1][11]);
	bibs6[1][9] = bibs4[1][11] = NULL;
	success &= test_db();

	return success;
}

static bool init(void)
{
	if (config_init(false))
		return false;

	if (bibdb_init()) {
		config_destroy();
		return false;
	}

	return true;
}

static void end(void)
{
	bibdb_destroy();
	config_destroy();
}

int init_module(void)
{
	START_TESTS("BIB");

	INIT_CALL_END(init(), test_flow(), end(), "Flow");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
