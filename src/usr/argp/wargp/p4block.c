#include "usr/argp/wargp/p4block.h"

#include "usr/argp/log.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/nl/core.h"
#include "usr/nl/p4block.h"
#include "usr/util/str_utils.h"

#define P4BLOCK_SYNTAX "<IPv4 address>:<Port>-<Port>"

int handle_p4block_display(char *iname, int argc, char **argv, void const *arg)
{
	struct joolnl_socket sk;
	struct jool_result result;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joolnl_p4block_foreach(&sk, iname);

	joolnl_teardown(&sk);

	if (result.error)
		return pr_result(&result);

	printf("Done; see dmesg.\n");
	return 0;
}

void autocomplete_p4block_display(void const *args)
{
	/* No code */
}

struct update_args {
	struct p4block blk;
};

static int parse_p4block_column(void *void_field, int key, char *str)
{
	struct p4block *blk = void_field;
	struct jool_result result;
	char *colon, *dash;

	colon = strchr(str, ':');
	if (colon == NULL)
		goto parse_failure;

	*colon = '\0';
	result = str_to_addr4(str, &blk->addr);
	if (result.error)
		return pr_result(&result);
	*colon = ':';

	str = colon + 1;
	dash = strchr(str, '-');
	if (dash == NULL)
		goto parse_failure;

	*dash = '\0';
	result = str_to_u16(str, &blk->ports.min);
	if (result.error)
		return pr_result(&result);
	*dash = '-';

	str = dash + 1;
	result = str_to_u16(str, &blk->ports.max);
	return pr_result(&result);

parse_failure:
	result = result_from_error(-EINVAL, "Unrecognized syntax; please use "
			P4BLOCK_SYNTAX ".\n");
	return pr_result(&result);
}

struct wargp_type wt_p4block = {
	.argument = P4BLOCK_SYNTAX,
	.parse = parse_p4block_column,
};

static struct wargp_option update_opts[] = {
	{
		.name = "block entry",
		.key = ARGP_KEY_ARG,
		.doc = "IPv4 transport address block",
		.offset = offsetof(struct update_args, blk),
		.type = &wt_p4block,
	},
	{ 0 },
};

static int handle_p4block_update(char *iname, int argc, char **argv,
	struct jool_result (*cb)(struct joolnl_socket *, char const *, struct p4block const *))
{
	struct update_args uargs = { 0 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(update_opts, argc, argv, &uargs);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = cb(&sk, iname, &uargs.blk);

	joolnl_teardown(&sk);
	return pr_result(&result);
}

int handle_p4block_add(char *iname, int argc, char **argv, void const *arg)
{
	return handle_p4block_update(iname, argc, argv, joolnl_p4block_add);
}

void autocomplete_p4block_add(void const *args)
{
	print_wargp_opts(update_opts);
}

int handle_p4block_remove(char *iname, int argc, char **argv, void const *arg)
{
	return handle_p4block_update(iname, argc, argv, joolnl_p4block_rm);
}

void autocomplete_p4block_remove(void const *args)
{
	print_wargp_opts(update_opts);
}
