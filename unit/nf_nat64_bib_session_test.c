#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "unit_test.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"

#define BIB_PRINT_KEY "BIB [%pI4#%d, %pI6#%d]"
#define SESSION_PRINT_KEY "session [%pI4#%d, %pI4#%d, %pI6#%d, %pI6#%d]"
#define PRINT_BIB(bib) \
	&bib->ipv4.address, bib->ipv4.pi.port, &bib->ipv6.address, bib->ipv6.pi.port
#define PRINT_SESSION(session) \
	&session->ipv4.remote.address, session->ipv4.remote.pi.port, \
	&session->ipv4.local.address, session->ipv4.local.pi.port, \
	&session->ipv6.local.address, session->ipv6.local.pi.port, \
	&session->ipv6.remote.address, session->ipv6.remote.pi.port

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("BIB-Session module test.");

const char* IPV4_ADDRS[] = { "0.0.0.0", "255.1.2.3", "65.0.123.2", "0.1.0.3", //
		"55.55.55.55", "10.11.12.13", "13.12.11.10", "255.255.255.255", //
		"1.2.3.4", "4.3.2.1", "2.3.4.5", "5.4.3.2", //
		"3.4.5.6", "6.5.4.3", "4.5.6.7", "7.6.5.4", //
		"56.56.56.56" };
const __be16 IPV4_PORTS[] = { 0, 456, 9556, 7523, //
		65535, 536, 284, 231, //
		1234, 4321, 2345, 5432, //
		3456, 6543, 4567, 7654, //
		6384 };
const char* IPV6_ADDRS[] = { "::1", "5:3::2", "4::", "44:55:66::", //
		"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "123::4", "::0", "44:1:1::2:9", //
		"1:2:3:4::", "4:3:2:1::", "2:3:4:5::", "5:4:3:2::", //
		"3:4:5:6::", "6:5:4:3::", "4:5:6:7::", "7:6:5:4::", //
		"56:56:56:56::" };
const __be16 IPV6_PORTS[] = { 334, 0, 9556, 65535, //
		55555, 825, 1111, 99, //
		1234, 4321, 2345, 5432, //
		3456, 6543, 4567, 7654, //
		6384 };

/********************************************
 * Funciones auxiliares.
 ********************************************/

void init_ipv4_tuple_address(struct ipv4_tuple_address* ta, int index)
{
	ta->address.s_addr = in_aton(IPV4_ADDRS[index]);
	ta->pi.port = IPV4_PORTS[index];
}

void init_ipv6_tuple_address(struct ipv6_tuple_address* ta, int index)
{
	if (!in6_pton(IPV6_ADDRS[index], -1, (u8*) &ta->address, '\\', NULL)) {
		printk(KERN_WARNING "No puedo convertir el texto '%s' a in6_addr. Esto va a tronar...", IPV6_ADDRS[index]);
		return;
	}
	ta->pi.port = IPV6_PORTS[index];
}

struct bib_entry *init_bib_entry(int ipv4_index, int ipv6_index)
{
	struct bib_entry *entry = (struct bib_entry*) kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	init_ipv4_tuple_address(&entry->ipv4, ipv4_index);
	init_ipv6_tuple_address(&entry->ipv6, ipv6_index);
	INIT_LIST_HEAD(&entry->session_entries);

	return entry;
}

struct session_entry *init_session_entry(struct bib_entry* bib, int ipv4_remote_id, int ipv4_local_id, int ipv6_local_id,
		int ipv6_remote_id, int l4protocol, unsigned int dying_time)
{
	struct session_entry* entry = (struct session_entry *) kmalloc(sizeof(struct session_entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->l4protocol = l4protocol;
	entry->bib = bib;
	entry->is_static = false;
	init_ipv4_tuple_address(&entry->ipv4.remote, ipv4_remote_id);
	init_ipv4_tuple_address(&entry->ipv4.local, ipv4_local_id);
	init_ipv6_tuple_address(&entry->ipv6.local, ipv6_local_id);
	init_ipv6_tuple_address(&entry->ipv6.remote, ipv6_remote_id);
	entry->dying_time = dying_time;

	return entry;
}

void init_tuple(struct nf_conntrack_tuple *tuple,
		union tuple_address *src, union tuple_address *dst,
		int l4protocol, int l3protocol)
{
	if (l3protocol == NFPROTO_IPV4) {
		tuple->ipv4_src_addr = src->ipv4.address;
		tuple->ipv4_dst_addr = dst->ipv4.address;
		tuple->src_port = src->ipv4.pi.port;
		tuple->dst_port = dst->ipv4.pi.port;
	} else {
		tuple->ipv6_src_addr = src->ipv6.address;
		tuple->ipv6_dst_addr = dst->ipv6.address;
		tuple->src_port = src->ipv6.pi.port;
		tuple->dst_port = dst->ipv6.pi.port;
	}

	tuple->l4_protocol = l4protocol;
	tuple->l3_protocol = l3protocol;
}

bool assert_bib_entry_equals(struct bib_entry* expected, struct bib_entry* actual, char* test_name)
{
	if (expected == actual)
		return true;

	if (expected == NULL) {
		printk(KERN_WARNING "Test '%s' failed: Expected null, obtained " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(actual));
		return false;
	}
	if (actual == NULL) {
		printk(KERN_WARNING "Test '%s' failed: Expected " BIB_PRINT_KEY ", obtained null.",
				test_name, PRINT_BIB(expected));
		return false;
	}
	if (!bib_entry_equals(expected, actual)) {
		printk(KERN_WARNING "Test '%s' failed: Expected " BIB_PRINT_KEY " obtained " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(expected), PRINT_BIB(actual));
		return false;
	}

	return true;
}

bool assert_session_entry_equals(struct session_entry* expected, struct session_entry* actual, char* test_name)
{
	if (expected == actual)
		return true;

	if (expected == NULL) {
		printk(KERN_WARNING "Test '%s' failed: Expected null, obtained " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(actual));
		return false;
	}
	if (actual == NULL) {
		printk(KERN_WARNING "Test '%s' failed: Expected " SESSION_PRINT_KEY ", obtained null.",
				test_name, PRINT_SESSION(expected));
		return false;
	}
	if (!session_entry_equals(expected, actual)) {
		printk(KERN_WARNING "Test '%s' failed: Expected " SESSION_PRINT_KEY ", obtained session " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(expected), PRINT_SESSION(actual));
		return false;
	}

	return true;
}

bool assert_bib(char* test_name, struct bib_entry* key_entry, bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	int l4protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	bool table_has_it[] = { udp_table_has_it, tcp_table_has_it, icmp_table_has_it };
	int i;
	struct bib_entry *expected_bib_entry;
	struct bib_entry *retrieved_bib_entry;

	struct nf_conntrack_tuple tuple;
	struct ipv4_tuple_address dummy_ipv4;
	struct ipv6_tuple_address dummy_ipv6;
	init_ipv4_tuple_address(&dummy_ipv4, 16);
	init_ipv6_tuple_address(&dummy_ipv6, 16);

	for (i = 0; i < 3; i++) {
		expected_bib_entry = table_has_it[i] ? key_entry : NULL;

		init_tuple(&tuple, (union tuple_address *) &dummy_ipv4, (union tuple_address *) &key_entry->ipv4, l4protocols[i], NFPROTO_IPV4);
		retrieved_bib_entry = nat64_get_bib_entry(&tuple);
		if (!assert_bib_entry_equals(expected_bib_entry, retrieved_bib_entry, test_name))
			return false;

		init_tuple(&tuple, (union tuple_address *) &key_entry->ipv6, (union tuple_address *) &dummy_ipv6, l4protocols[i], NFPROTO_IPV6);
		retrieved_bib_entry = nat64_get_bib_entry(&tuple);
		if (!assert_bib_entry_equals(expected_bib_entry, retrieved_bib_entry, test_name))
			return false;
	}

	return true;
}

bool assert_session(char* test_name, struct session_entry* key_entry, bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	int l4protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	bool table_has_it[] = { udp_table_has_it, tcp_table_has_it, icmp_table_has_it };
	int i;
	struct session_entry *expected_entry;
	struct session_entry *retrieved_entry;

	struct nf_conntrack_tuple tuple;

	for (i = 0; i < 3; i++) {
		expected_entry = table_has_it[i] ? key_entry : NULL;

		init_tuple(&tuple, //
				(union tuple_address *) &key_entry->ipv4.remote, //
				(union tuple_address *) &key_entry->ipv4.local, //
				l4protocols[i], NFPROTO_IPV4);
		retrieved_entry = nat64_get_session_entry(&tuple);
		if (!assert_session_entry_equals(expected_entry, retrieved_entry, test_name))
			return false;

		init_tuple(&tuple, //
				(union tuple_address *) &key_entry->ipv6.remote, //
				(union tuple_address *) &key_entry->ipv6.local, //
				l4protocols[i], NFPROTO_IPV6);
		retrieved_entry = nat64_get_session_entry(&tuple);
		if (!assert_session_entry_equals(expected_entry, retrieved_entry, test_name))
			return false;
	}

	return true;
}

/********************************************
 * Pruebas.
 ********************************************/

/**
 * Inserta un solo registro, lo valida, lo remueve, valida de nuevo.
 * Solamente maneja la tabla BIB.
 */
bool simple_bib(void)
{
	struct bib_entry *inserted_bib = init_bib_entry(0, 0);

	printk(KERN_DEBUG "asd 1");

	// Prueba de agregar un solo registro en la tabla BIB.
	if (!nat64_add_bib_entry(inserted_bib, IPPROTO_TCP)) {
		printk(KERN_WARNING "Test 'BIB insertion' failed: Insertion of bib entry claimed to have failed.");
		return false;
	}
	if (!assert_bib("BIB insertion", inserted_bib, false, true, false))
		return false;

	printk(KERN_DEBUG "asd 2");

	// Prueba de remover el registro.
	if (!nat64_remove_bib_entry(inserted_bib, IPPROTO_TCP)) {
		printk(KERN_WARNING "Test 'BIB removal' failed: Removal of sessionless bib entry claimed to have failed.");
		return false;
	}
	if (!assert_bib("BIB removal", inserted_bib, false, false, false))
		return false;

	// Terminado; limpiar.
	nat64_bib_destroy();
	return true;
}

bool simple_bib_session(void)
{
	struct bib_entry *inserted_bib;
	struct session_entry *inserted_session;

	inserted_bib = init_bib_entry(0, 0);
	inserted_session = init_session_entry(inserted_bib, 1, 0, 1, 0, IPPROTO_TCP, 12345);

	// Insertar BIB.
	if (!nat64_add_bib_entry(inserted_bib, IPPROTO_TCP)) {
		printk(KERN_WARNING "Test 'BIB insertion' failed: Insertion of bib entry claimed to have failed.");
		return false;
	}
	if (!assert_bib("BIB insertion", inserted_bib, false, true, false))
		return false;

	// Insertar sesión.
	if (!nat64_add_session_entry(inserted_session)) {
		printk(KERN_WARNING "Test 'Session insertion' failed: Insertion of session entry claimed to have failed.");
		return false;
	}
	if (!assert_session("Session insertion", inserted_session, false, true, false))
		return false;

	// Remover el registro BIB debe fallar porque tiene una sesión.
	if (nat64_remove_bib_entry(inserted_bib, IPPROTO_TCP)) {
		printk(KERN_WARNING "Test 'Bib removal' failed: Removal of session-carrying BIB entry claimed to have succeeded.");
		return false;
	}
	if (!assert_bib("Bib removal (bib table)", inserted_bib, false, true, false))
		return false;
	if (!assert_session("BIB removal (session table)", inserted_session, false, true, false))
		return false;

	// Prueba de remover el registro de sesión.
	if (!nat64_remove_session_entry(inserted_session)) {
		printk(KERN_WARNING "Test 'Session removal' failed: Removal of session entry claimed to have failed.");
		return false;
	}
	if (!assert_bib("Session removal (bib table)", inserted_bib, false, false, false))
		return false;
	if (!assert_session("Session removal (session table)", inserted_session, false, false, false))
		return false;

	// Terminado; limpiar.
	nat64_session_destroy();
	nat64_bib_destroy();
	return true;
}

#define BIB_COUNT 4
#define SESSIONS_PER_BIB 3

#define FOR_EACH_BIB \
	for (cbib = 0; cbib < BIB_COUNT; cbib++)
#define FOR_EACH_SESSION \
	FOR_EACH_BIB \
		for (csession = 0; csession < SESSIONS_PER_BIB; csession++)

#define ASSERT_SINGLE_BIB(test_name, bib_id, bib_is_alive, s1_is_alive, s2_is_alive, s3_is_alive) \
	if (!assert_bib(test_name, bibs[bib_id], bib_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][0], s1_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][1], s2_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][2], s3_is_alive, false, false)) return false;

bool test_clean_old_sessions(void)
{
	struct bib_entry *bibs[BIB_COUNT];
	struct session_entry *sessions[BIB_COUNT][SESSIONS_PER_BIB];
	// "Contador de BIBs, contador de sesiones".
	// Me di el lujo de abreviarlos porque se usan demasiado.
	int cbib, csession;

	const unsigned int time_before = jiffies_to_msecs(jiffies) - 1000;
	const unsigned int time_after = jiffies_to_msecs(jiffies) + 1000;

	// Inicializar.
	FOR_EACH_BIB
		bibs[cbib] = init_bib_entry(cbib, cbib);
	FOR_EACH_SESSION
		sessions[cbib][csession] = init_session_entry(bibs[cbib], cbib, csession + 5, cbib, csession + 5, IPPROTO_UDP, time_after);
	sessions[3][1]->is_static = true;

	// Insertar a las tablas.
	FOR_EACH_BIB
		nat64_add_bib_entry(bibs[cbib], IPPROTO_UDP);
	FOR_EACH_SESSION
			nat64_add_session_entry(sessions[cbib][csession]);

	// 1. Nada ha caducado:
	// Probar que se borre nada.
	nat64_clean_old_sessions();

	FOR_EACH_BIB
		if (!assert_bib("Clean deletes nothing", bibs[cbib], true, false, false))
			return false;
	FOR_EACH_SESSION
			if (!assert_session("Clean deletes nothing", sessions[cbib][csession], true, false, false))
				return false;

	// 2. Todas las sesiones de una BIB caducan:
	// Probar que se borren tanto BIB como sesiones.
	sessions[1][0]->dying_time = time_before;
	sessions[1][1]->dying_time = time_before;
	sessions[1][2]->dying_time = time_before;

	nat64_clean_old_sessions();

	ASSERT_SINGLE_BIB("Whole BIB dies", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Whole BIB dies", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Whole BIB dies", 2, true, true, true, true);
	ASSERT_SINGLE_BIB("Whole BIB dies", 3, true, true, true, true);

	// 3. Algunas sesiones de una BIB caducan:
	// Probar que se borren esas sesiones, pero no el resto ni la BIB.
	sessions[2][0]->dying_time = time_before;
	sessions[2][1]->dying_time = time_before;

	nat64_clean_old_sessions();

	ASSERT_SINGLE_BIB("Some sessions die", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Some sessions die", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Some sessions die", 2, true, false, false, true);
	ASSERT_SINGLE_BIB("Some sessions die", 3, true, true, true, true);

	// 4. El resto de las sesiones de esa BIB caducan:
	// Probar que la BIB se sigue comportando como se espera. Quizá innecesario.
	sessions[2][2]->dying_time = time_before;

	nat64_clean_old_sessions();

	ASSERT_SINGLE_BIB("Last session dies", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Last session dies", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Last session dies", 2, false, false, false, false);
	ASSERT_SINGLE_BIB("Last session dies", 3, true, true, true, true);

	// 5. Todas las sesiones de una BIB caducan pero una es estática;
	// Probar que solamente se mueran las dinámicas.
	sessions[3][0]->dying_time = time_before;
	sessions[3][1]->dying_time = time_before;
	sessions[3][2]->dying_time = time_before;

	nat64_clean_old_sessions();

	ASSERT_SINGLE_BIB("Static session doesn't die", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Static session doesn't die", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Static session doesn't die", 2, false, false, false, false);
	ASSERT_SINGLE_BIB("Static session doesn't die", 3, true, false, true, false);

	// Terminado; limpiar.
	nat64_session_destroy();
	nat64_bib_destroy();
	return true;
}

#undef BIB_COUNT
#undef SESSIONS_PER_BIB
#undef FOR_EACH_BIB
#undef FOR_EACH_SESSION
#undef ASSERT_SINGLE_BIB

bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id, int dst_port_id, bool expected)
{
	union tuple_address src, dst;
	struct nf_conntrack_tuple tuple;

	src.ipv4.address.s_addr = in_aton(IPV4_ADDRS[src_addr_id]);
	src.ipv4.pi.port = IPV4_PORTS[src_port_id];
	dst.ipv4.address.s_addr = in_aton(IPV4_ADDRS[dst_addr_id]);
	dst.ipv4.pi.port = IPV4_PORTS[dst_port_id];

	init_tuple(&tuple, &src, &dst, IPPROTO_UDP, NFPROTO_IPV4);

	return (expected == nat64_is_allowed_by_address_filtering(&tuple));
}

bool test_address_filtering(void)
{
	struct bib_entry *bib;
	struct session_entry *session;

	bib = init_bib_entry(0, 0);
	session = init_session_entry(bib, 0, 0, 0, 0, IPPROTO_UDP, 12345);
	nat64_add_bib_entry(bib, IPPROTO_UDP);
	nat64_add_session_entry(session);

	// Test the packet is allowed when the tuple and the session match perfectly.
	if (!test_address_filtering_aux(0, 0, 0, 0, true))
		return false;

	// Test a tuple that completely mismatches the session.
	if (!test_address_filtering_aux(1, 1, 1, 1, false))
		return false;

	// Now test tuples that nearly match the session.
	if (!test_address_filtering_aux(0, 0, 0, 1, false))
		return false;
	if (!test_address_filtering_aux(0, 0, 1, 0, false))
		return false;
	if (!test_address_filtering_aux(0, 1, 0, 0, true))
		return false; // The remote port is the only one that doesn't matter.
	if (!test_address_filtering_aux(1, 0, 0, 0, false))
		return false;

	nat64_session_destroy();
	nat64_bib_destroy();
	return true;
}

/********************************************
 * Main.
 ********************************************/

int init_module(void)
{
	START_TESTS("BIB-Session");

	nat64_bib_init();
	nat64_session_init();

	CALL_TEST(simple_bib(), "Single BIB");
	CALL_TEST(simple_bib_session(), "Single BIB-Session");
	CALL_TEST(test_clean_old_sessions(), "Session cleansing.");
	CALL_TEST(test_address_filtering(), "Address-dependent filtering.");

	END_TESTS;
}

void cleanup_module(void)
{
	// Sin codigo.
}
