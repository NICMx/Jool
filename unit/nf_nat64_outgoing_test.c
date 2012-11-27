#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "unit_test.h"
#include "nf_nat64_outgoing.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_DESCRIPTION("Outgoing module test");


bool add_bib(char *ip4_addr, __u16 ip4_port, char *ip6_addr, __u16 ip6_port)
{
	// Generate the BIB.
	struct bib_entry *bib = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!bib) {
		printk(KERN_WARNING "Unable to allocate a dummy BIB.");
		goto failure;
	}

	bib->ipv4.address.s_addr = in_aton(ip4_addr);
	bib->ipv4.pi.port = cpu_to_be16(ip4_port);
	in6_pton(ip6_addr, -1, (u8 *) &bib->ipv6.address, '\\', NULL);
	bib->ipv6.pi.port = cpu_to_be16(ip6_port);
	INIT_LIST_HEAD(&bib->session_entries);

	// Imprimir las direcciones para ver que las haya traducido bien.
	// Quítalo si quieres o cuando acabes.
	printk(KERN_DEBUG "BIB [%pI4#%d, %pI6#%d]",
			&bib->ipv4.address, be16_to_cpu(bib->ipv4.pi.port),
			&bib->ipv6.address, be16_to_cpu(bib->ipv6.pi.port));

	// Add it to the table.
	if (!nat64_add_bib_entry(bib, IPPROTO_TCP)) {
		printk(KERN_WARNING "Can't add the dummy BIB to the table.");
		goto failure;
	}

	return true;

failure:
	kfree(bib);
	return false;
}

/**
 * Prepares the environment for the tests.
 *
 * @return whether the initialization was successful or not. An error message has been printed to
 *		the kernel ring buffer.
 */
bool init(void)
{
	nat64_bib_init();

	if (!add_bib("192.168.2.4", 45, "12a:bcd::", 874))
		return false;
	if (!add_bib("192.168.2.7", 41, "11a:bcd:aaa::", 7878))
		return false;

	return true;
}

/**
 * Frees from memory the stuff we created during init().
 */
void cleanup(void)
{
	nat64_bib_destroy();
}

bool test_tuple5_function(void)
{
	return true;
}

bool test_tuple3_function(void)
{
	return true;
}

int init_module(void)
{
	START_TESTS("Outgoing");

	if (!init())
		return -EINVAL;

	CALL_TEST(test_tuple5_function(), "Tuple 5 function");
	CALL_TEST(test_tuple3_function(), "Tuple 3 function");

	cleanup();

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
