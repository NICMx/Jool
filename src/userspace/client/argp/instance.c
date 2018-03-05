#include "instance.h"

#include <string.h>
#include <net/if.h>

#include "requirements.h"
#include "wargp.h"
#include "netlink/instance.h"

#define ARGP_SIIT 's'
#define ARGP_NAT64 'n'

struct add_args {
	struct wargp_bool siit;
	struct wargp_bool nat64;
};

static struct wargp_option add_opts[] = {
	{
		.name = "siit",
		.key = ARGP_SIIT,
		.doc = "Initialize the instance as a SIIT (default)",
		.offset = offsetof(struct add_args, siit),
		.type = &wt_bool,
	}, {
		.name = "nat64",
		.key = ARGP_NAT64,
		.doc = "Initialize the instance as a NAT64",
		.offset = offsetof(struct add_args, nat64),
		.type = &wt_bool,
	},
	{ 0 },
};

int handle_instance_add(char *instance, int argc, char **argv)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (aargs.siit.value && aargs.nat64.value) {
		log_err("The translator can not be initialized as both SIIT and NAT64 at the same time.");
		return -EINVAL;
	}

	return instance_add(aargs.nat64.value ? XLATOR_NAT64 : XLATOR_SIIT,
			instance);
}

void print_instance_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
}

static struct wargp_option remove_opts[] = {
	{ 0 },
};

int handle_instance_remove(char *instance, int argc, char **argv)
{
	int error;

	error = wargp_parse(remove_opts, argc, argv, NULL);
	if (error)
		return error;

	return instance_rm(instance);
}

void print_instance_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
}
