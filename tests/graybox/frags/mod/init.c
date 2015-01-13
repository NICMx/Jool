#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>

#include "types.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME);

int frags_init(void)
{
	int error;

	log_debug("Inserting the module...");

	error = config_init();
	if (error)
		return error;

	log_debug(MODULE_NAME " module inserted.");
	return error;
}

void frags_exit(void)
{
	config_destroy();
	log_debug(MODULE_NAME " module removed.");
}

module_init(frags_init);
module_exit(frags_exit);
