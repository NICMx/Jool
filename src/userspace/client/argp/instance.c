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
	char name[IFNAMSIZ];
};

static int parse_name(void *input, int key, char *str)
{
	if (strlen(str) > IFNAMSIZ - 1) {
		log_err("Instance name '%s' is too long. (max: %u)", str,
				IFNAMSIZ - 1);
		return -EINVAL;
	}

	strcpy(input, str);
	return 0;
}

struct wargp_type wt_name = {
	.doc = "<instance name>",
	.parse = parse_name,
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
	}, {
		.name = "Instance name",
		.key = ARGP_KEY_ARG,
		.doc = "Name of the new instance",
		.offset = offsetof(struct add_args, name),
		.type = &wt_name,
	},
	{ 0 },
};

int handle_instance_add(int argc, char **argv)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (strlen(aargs.name) == 0) {
		struct requirement reqs[] = {
			{ false, "an instance name" },
		};
		return requirement_print(reqs);
	}

	if (aargs.siit.value && aargs.nat64.value) {
		log_err("The translator can not be initialized as both SIIT and NAT64 at the same time.");
		return -EINVAL;
	}

	return instance_add(aargs.nat64.value ? XLATOR_NAT64 : XLATOR_SIIT,
			aargs.name);
}

void print_instance_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
}

struct rm_args {
	char name[IFNAMSIZ];
};

static struct wargp_option remove_opts[] = {
	{
		.name = "Instance name",
		.key = ARGP_KEY_ARG,
		.doc = "Name of the instance you want to remove",
		.offset = offsetof(struct rm_args, name),
		.type = &wt_name,
	},
	{ 0 },
};

int handle_instance_remove(int argc, char **argv)
{
	struct rm_args rargs = { 0 };
	int error;

	error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (error)
		return error;

	if (!rargs.name) {
		struct requirement reqs[] = {
			{ rargs.name, "an instance name" },
		};
		return requirement_print(reqs);
	}

	return instance_rm(rargs.name);
}

void print_instance_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
}
