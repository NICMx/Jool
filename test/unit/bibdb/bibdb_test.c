#include <linux/module.h>
#include <linux/printk.h>
#include "nat64/unit/unit_test.h"
#include "nat64/unit/bib.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("BIB DB module test.");

static struct bib *db;
static const l4_protocol PROTO = L4PROTO_TCP;
static struct bib_entry bibs[8];
static struct bib_entry *bibs4[4][25];
static struct bib_entry *bibs6[4][25];

static bool assert4(unsigned int addr_id, unsigned int port)
{
	struct bib_entry bib;
	struct ipv4_transport_addr taddr;
	bool success = true;

	taddr.l3.s_addr = cpu_to_be32(0xc0000200 | addr_id);
	taddr.l4 = port;

	if (bibs4[addr_id][port]) {
		success &= ASSERT_INT(0, bib_find4(db, PROTO, &taddr, &bib),
				"7th (%u %u) - get4", addr_id, port);
		success &= ASSERT_BIB(bibs4[addr_id][port], &bib, "7th by 4");
	} else {
		success &= ASSERT_INT(-ESRCH, bib_find4(db, PROTO, &taddr, NULL),
				"get4 fails (%u %u)", addr_id, port);
	}

	return success;
}

static bool assert6(unsigned int addr_id, unsigned int port)
{
	struct bib_entry bib;
	struct ipv6_transport_addr taddr;
	bool success = true;

	taddr.l3.s6_addr32[0] = cpu_to_be32(0x20010db8);
	taddr.l3.s6_addr32[1] = 0;
	taddr.l3.s6_addr32[2] = 0;
	taddr.l3.s6_addr32[3] = cpu_to_be32(addr_id);
	taddr.l4 = port;

	if (bibs6[addr_id][port]) {
		success &= ASSERT_INT(0, bib_find6(db, PROTO, &taddr, &bib),
				"7th (%u %u) - get6", addr_id, port);
		success &= ASSERT_BIB(bibs6[addr_id][port], &bib, "7th by 6");
	} else {
		success &= ASSERT_INT(-ESRCH, bib_find6(db, PROTO, &taddr, &bib),
				"get6 fails (%u %u)", addr_id, port);
	}

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

static void drop_bib(int addr6, int port6, int addr4, int port4)
{
	bibs6[addr6][port6] = NULL;
	bibs4[addr4][port4] = NULL;
}

/**
 * Returns @bibs4 and @bibs6 to factory condition.
 */
static void drop_test_bibs(void)
{
	unsigned int addr, port;

	for (addr = 0; addr < 4; addr++) {
		for (port = 0; port < 25; port++) {
			if (bibs6[addr][port])
				drop_bib(addr, port, 0, 0);
		}
	}

	memset(bibs4, 0, sizeof(bibs4));
}

static bool insert_test_bibs(void)
{
	drop_test_bibs();

	/* TODO error results? */
	bib_inject(db, "2001:db8::2", 18, "192.0.2.3", 20, PROTO, &bibs[0]);
	bib_inject(db, "2001:db8::0", 10, "192.0.2.1", 21, PROTO, &bibs[1]);
	bib_inject(db, "2001:db8::0", 20, "192.0.2.2", 12, PROTO, &bibs[2]);
	bib_inject(db, "2001:db8::3", 10, "192.0.2.3", 10, PROTO, &bibs[3]);
	bib_inject(db, "2001:db8::3", 20, "192.0.2.2", 22, PROTO, &bibs[4]);
	bib_inject(db, "2001:db8::1", 19, "192.0.2.0", 20, PROTO, &bibs[5]);
	bib_inject(db, "2001:db8::2", 8, "192.0.2.0", 10, PROTO, &bibs[6]);
	bib_inject(db, "2001:db8::1", 9, "192.0.2.1", 11, PROTO, &bibs[7]);

	bibs6[2][18] = bibs4[3][20] = &bibs[0];
	bibs6[0][10] = bibs4[1][21] = &bibs[1];
	bibs6[0][20] = bibs4[2][12] = &bibs[2];
	bibs6[3][10] = bibs4[3][10] = &bibs[3];
	bibs6[3][20] = bibs4[2][22] = &bibs[4];
	bibs6[1][19] = bibs4[0][20] = &bibs[5];
	bibs6[2][8] = bibs4[0][10] = &bibs[6];
	bibs6[1][9] = bibs4[1][11] = &bibs[7];

	return test_db();
}

/* TODO update log_debugs */
static bool test_flow(void)
{
	struct ipv4_range range;
	bool success = true;

	if (!insert_test_bibs())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Delete full addresses using bibdb_delete_taddr4s().");
	range.prefix.address.s_addr = cpu_to_be32(0xc0000200);
	range.prefix.len = 31;
	range.ports.min = 0;
	range.ports.max = 65535;
	bib_rm_range(db, PROTO, &range);

	drop_bib(0, 10, 1, 21);
	drop_bib(1, 19, 0, 20);
	drop_bib(2, 8, 0, 10);
	drop_bib(1, 9, 1, 11);
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Delete only certain ports using bibdb_delete_taddr4s().");
	range.prefix.address.s_addr = cpu_to_be32(0xc0000202);
	range.prefix.len = 31;
	range.ports.min = 11;
	range.ports.max = 20;
	bib_rm_range(db, PROTO, &range);

	drop_bib(2, 18, 3, 20);
	drop_bib(0, 20, 2, 12);
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Flush using bibdb_delete_taddr4s().");
	range.prefix.address.s_addr = cpu_to_be32(0x00000000);
	range.prefix.len = 0;
	range.ports.min = 0;
	range.ports.max = 65535;
	bib_rm_range(db, PROTO, &range);

	drop_bib(3, 10, 3, 10);
	drop_bib(3, 20, 2, 22);
	success &= test_db();

	/* ---------------------------------------------------------- */

	if (!insert_test_bibs())
		return false;

	log_debug("Flush using bibdb_flush().");
	bib_flush(db);
	drop_test_bibs();
	success &= test_db();

	return success;
}

enum session_fate tcp_est_expire_cb(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	if (bib_init())
		return false;
	db = bib_create();
	if (!db)
		bib_destroy();
	return db;
}

static void end(void)
{
	bib_put(db);
	bib_destroy();
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
