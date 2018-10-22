/**
 * Main for the `jool` userspace application.
 * Handles the first arguments (often "mode" and "operation") and multiplexes
 * the rest of the work to the corresponding .c's.
 */

#include <argp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common/config.h"
#include "common/xlat.h"
#include "usr/common/command.h"
#include "usr/common/log.h"
#include "usr/common/str_utils.h"
#include "usr/common/argp/bib.h"
#include "usr/common/argp/blacklist4.h"
#include "usr/common/argp/eamt.h"
#include "usr/common/argp/file.h"
#include "usr/common/argp/instance.h"
#include "usr/common/argp/pool4.h"
#include "usr/common/argp/global.h"
#include "usr/common/argp/session.h"
#include "usr/common/argp/stats.h"

#define DISPLAY "display"
#define ADD "add"
#define UPDATE "update"
#define REMOVE "remove"
#define FLUSH "flush"

static int handle_autocomplete(char *junk, int argc, char **argv, void *arg);

static struct cmd_option instance_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_BOTH,
			.handler = handle_instance_display,
			.print_opts = print_instance_display_opts,
		}, {
			.label = ADD,
			.xt = XT_BOTH,
			.handler = handle_instance_add,
			.print_opts = print_instance_add_opts,
		}, {
			.label = REMOVE,
			.xt = XT_BOTH,
			.handler = handle_instance_remove,
			.print_opts = print_instance_remove_opts,
		}, {
			.label = FLUSH,
			.xt = XT_BOTH,
			.handler = handle_instance_flush,
			.print_opts = print_instance_flush_opts,
		},
		{ 0 },
};

static struct cmd_option stats_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_BOTH,
			.handler = handle_stats_display,
			.print_opts = print_stats_display_opts,
		},
		{ 0 },
};

static struct cmd_option global_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_BOTH,
			.handler = handle_global_display,
			.print_opts = print_global_display_opts,
		}, {
			.label = UPDATE,
			.xt = XT_BOTH,
			.child_builder = build_global_update_children,
		},
		{ 0 },
};

static struct cmd_option eamt_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_SIIT,
			.handler = handle_eamt_display,
			.print_opts = print_eamt_display_opts,
		}, {
			.label = ADD,
			.xt = XT_SIIT,
			.handler = handle_eamt_add,
			.print_opts = print_eamt_add_opts,
		}, {
			.label = REMOVE,
			.xt = XT_SIIT,
			.handler = handle_eamt_remove,
			.print_opts = print_eamt_remove_opts,
		}, {
			.label = FLUSH,
			.xt = XT_SIIT,
			.handler = handle_eamt_flush,
			.print_opts = print_eamt_flush_opts,
		},
		{ 0 },
};

static struct cmd_option blacklist4_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_SIIT,
			.handler = handle_blacklist4_display,
			.print_opts = print_blacklist4_display_opts,
		}, {
			.label = ADD,
			.xt = XT_SIIT,
			.handler = handle_blacklist4_add,
			.print_opts = print_blacklist4_add_opts,
		}, {
			.label = REMOVE,
			.xt = XT_SIIT,
			.handler = handle_blacklist4_remove,
			.print_opts = print_blacklist4_remove_opts,
		}, {
			.label = FLUSH,
			.xt = XT_SIIT,
			.handler = handle_blacklist4_flush,
			.print_opts = print_blacklist4_flush_opts,
		},
		{ 0 },
};

struct cmd_option pool4_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_NAT64,
			.handler = handle_pool4_display,
			.print_opts = print_pool4_display_opts,
		}, {
			.label = ADD,
			.xt = XT_NAT64,
			.handler = handle_pool4_add,
			.print_opts = print_pool4_add_opts,
		}, {
			.label = REMOVE,
			.xt = XT_NAT64,
			.handler = handle_pool4_remove,
			.print_opts = print_pool4_remove_opts,
		}, {
			.label = FLUSH,
			.xt = XT_NAT64,
			.handler = handle_pool4_flush,
			.print_opts = print_pool4_flush_opts,
		},
		{ 0 },
};

static struct cmd_option bib_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_NAT64,
			.handler = handle_bib_display,
			.print_opts = print_bib_display_opts,
		}, {
			.label = ADD,
			.xt = XT_NAT64,
			.handler = handle_bib_add,
			.print_opts = print_bib_add_opts,
		}, {
			.label = REMOVE,
			.xt = XT_NAT64,
			.handler = handle_bib_remove,
			.print_opts = print_bib_remove_opts,
		},
		{ 0 },
};

static struct cmd_option session_ops[] = {
		{
			.label = DISPLAY,
			.xt = XT_NAT64,
			.handler = handle_session_display,
			.print_opts = print_session_display_opts,
		},
		{ 0 },
};

static struct cmd_option file_ops[] = {
		{
			.label = UPDATE,
			.xt = XT_BOTH,
			.handler = handle_file_update,
			.print_opts = print_file_update_opts,
		},
		{ 0 },
};

struct cmd_option tree[] = {
		{
			.label = "instance",
			.xt = XT_BOTH,
			.children = instance_ops,
		}, {
			.label = "stats",
			.xt = XT_BOTH,
			.children = stats_ops,
		}, {
			.label = "global",
			.xt = XT_BOTH,
			.children = global_ops,
		}, {
			.label = "eamt",
			.xt = XT_SIIT,
			.children = eamt_ops,
		}, {
			.label = "blacklist4",
			.xt = XT_SIIT,
			.children = blacklist4_ops,
		}, {
			.label = "pool4",
			.xt = XT_NAT64,
			.children = pool4_ops,
		}, {
			.label = "bib",
			.xt = XT_NAT64,
			.children = bib_ops,
		}, {
			.label = "session",
			.xt = XT_NAT64,
			.children = session_ops,
		}, {
			.label = "file",
			.xt = XT_BOTH,
			.children = file_ops,
		}, {
			.label = "autocomplete",
			.xt = XT_BOTH,
			.hidden = true,
			.handler  = handle_autocomplete,
		},
		{ 0 },
};

static int init_cmd_option_array(struct cmd_option *layer)
{
	struct cmd_option *node;
	int error;

	if (!layer)
		return 0;

	for (node = layer; node->label; node++) {
		if (node->child_builder) {
			node->children = node->child_builder();
			if (!node->children)
				return -ENOMEM;
		}

		error = init_cmd_option_array(node->children);
		if (error)
			return error;
	}

	return 0;
}

static void teardown_cmd_option_array(struct cmd_option *layer)
{
	struct cmd_option *node;

	if (!layer)
		return;

	for (node = layer; node->label; node++) {
		teardown_cmd_option_array(node->children);
		if (node->child_builder)
			free(node->children);
	}
}

/**
 * Returns the nodes from the @options array whose label start with @prefix.
 * (They will be chained via result->next.)
 *
 * Special cases:
 * - If there is a node whose entire label is @prefix, it returns that one only.
 * - If a node is hidden, it will have to match perfectly.
 */
static struct cmd_option *find_matches(struct cmd_option *options, char *prefix)
{
	struct cmd_option *option;
	struct cmd_option *first = NULL;
	struct cmd_option *last = NULL;

	if (!options)
		return NULL;

	for (option = options; option->label; option++) {
		if (!(xlat_type() & option->xt))
			continue;

		if (option->hidden) {
			if (strcmp(option->label, prefix) == 0)
				return option;
			continue;
		}

		if (memcmp(option->label, prefix, strlen(prefix)) == 0) {
			/*
			 * The labels never overlap like this so this isn't
			 * really useful right now.
			 * I'm including this only for the sake of correctness.
			 */
			if (strcmp(option->label, prefix) == 0)
				return option;

			if (first)
				last->next = option;
			else
				first = option;
			last = option;
			last->next = NULL;
		}
	}

	return first;
}

static int unexpected_token(struct cmd_option *nodes, char *token)
{
	fprintf(stderr, "Unexpected token: '%s'\n", token);
	fprintf(stderr, "Available options: ");
	for (; nodes->label; nodes++) {
		if (!cmdopt_is_hidden(nodes))
			fprintf(stderr, "%s ", nodes->label);
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int ambiguous_token(struct cmd_option *nodes, char *token)
{
	fprintf(stderr, "Ambiguous token: '%s'\n", token);
	fprintf(stderr, "Available options: ");
	for (; nodes; nodes = nodes->next) {
		if (!cmdopt_is_hidden(nodes))
			fprintf(stderr, "%s ", nodes->label);
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int more_args_expected(struct cmd_option *nodes)
{
	fprintf(stderr, "More arguments expected.\n");
	fprintf(stderr, "Possible follow-ups: ");
	for (; nodes->label; nodes++) {
		if (!cmdopt_is_hidden(nodes))
			fprintf(stderr, "%s ", nodes->label);
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int __handle(char *iname, int argc, char **argv)
{
	struct cmd_option *nodes = &tree[0];
	struct cmd_option *node = NULL;
	int i;

	if (argc == 0)
		return more_args_expected(nodes);

	for (i = 0; i < argc; i++) {
		node = find_matches(nodes, argv[i]);
		if (!node)
			return unexpected_token(nodes, argv[i]);
		if (node->next)
			return ambiguous_token(node, argv[i]);

		if (node->handler) {
			return node->handler(iname, argc - i, &argv[i],
					node->args);
		}

		nodes = node->children;
	}

	return more_args_expected(node->children);
}

static int handle(char *iname, int argc, char **argv)
{
	int error;

	error = init_cmd_option_array(tree);
	if (error)
		return error;

	error = __handle(iname, argc, argv);

	teardown_cmd_option_array(tree);
	return error;
}

static int print_opts(struct cmd_option *node, char *token)
{
	/* All flags are candidates for "-". */
	if (strcmp("-", token) == 0) {
		node->print_opts("");
		return 0;
	}

	/* Does the token start with "--"? */
	if (strncmp("--", token, strlen("--")) == 0) {
		node->print_opts(token + 2);
		return 0;
	}

	/* Token is not a flag so there are no candidates. */
	return 0;
}

/**
 * Never fails because there's no point yet.
 */
static int handle_autocomplete(char *junk, int argc, char **argv, void *arg)
{
	struct cmd_option *node = &tree[0];
	char *current_token = "";
	int i;

	argc -= 1;
	argv += 1;

	if (argc != 0) {
		for (i = 0; i < argc - 1; i++) {
			node = find_matches(node, argv[i]);
			if (!node)
				return 0; /* Prefix does not exist. */
			if (node->next)
				return 0; /* Ambiguous prefix. */

			if (!node->children)
				return print_opts(node, argv[argc - 1]);

			node = node->children;
		}
		current_token = argv[i];
	}

	for (node = find_matches(node, current_token); node; node = node->next)
		printf("%s\n", node->label);

	return 0;
}

static int show_usage(char *program_name)
{
	printf("%s (\n", program_name);
	printf("        [-i <INSTANCE NAME>] <MODE> <OPERATION> <ARGS>\n");
	printf("        | [-h|--help]\n");
	printf("        | (-V|--version)\n");
	printf("        | --usage\n");
	printf(")\n");
	return 0;
}

static int show_help(char *program_name)
{
	struct cmd_option *mode;
	struct cmd_option *op;

	printf("Usage\n");
	printf("=====\n");
	show_usage(program_name);
	printf("\n");

	printf("<INSTANCE NAME>\n");
	printf("===============\n");
	printf("Name of the Jool instance to operate on.\n");
	printf("Ascii string, 15 characters max. Defaults to `%s`.\n",
			INAME_DEFAULT);
	printf("\n");

	printf("<MODE> -> <OPERATION>s\n");
	printf("======================\n");
	for (mode = tree; mode && mode->label; mode++) {
		if (cmdopt_is_hidden(mode))
			continue;

		printf("- %s -> ", mode->label);
		for (op = mode->children; op && op->label; op++) {
			if (!cmdopt_is_hidden(op))
				printf("%s ", op->label);
		}
		printf("\n");
	}
	printf("\n");

	printf("<ARGS>\n");
	printf("======\n");
	printf("Depends on <MODE> and <OPERATION>. Normally, see respective --help for details.\n");
	printf("(Example: %s instance add --help)\n", program_name);
	printf("\n");

	printf("Report bugs to %s.", argp_program_bug_address);
	printf("\n");
	return 0;
}

static int show_version(void)
{
	log_info(JOOL_VERSION_STR);
	return 0;
}

int main(int argc, char **argv)
{
	char *iname = NULL;

	if (argc == 1)
		return show_help(argv[0]);
	if (STR_EQUAL(argv[1], "--help") || STR_EQUAL(argv[1], "-?"))
		return show_help(argv[0]);
	if (STR_EQUAL(argv[1], "--version") || STR_EQUAL(argv[1], "-V"))
		return show_version();
	if (STR_EQUAL(argv[1], "--usage"))
		return show_usage(argv[0]);
	if (STR_EQUAL(argv[1], "-i")) {
		if (argc == 2) {
			log_err("-i requires a string as argument.");
			return -EINVAL;
		}
		iname = argv[2];
		argc -= 2;
		argv += 2;
	}

	return handle(iname, argc - 1, argv + 1);
}
