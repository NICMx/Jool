/**
 * Main for the `jool` userspace application.
 * Handles the first arguments (often "mode" and "operation") and multiplexes
 * the rest of the work to the corresponding .c's.
 */

#include <argp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common/xlat.h"
#include "usr/common/command.h"
#include "usr/common/log.h"
#include "usr/common/str_utils.h"
#include "usr/common/argp/bib.h"
#include "usr/common/argp/eamt.h"
#include "usr/common/argp/file.h"
#include "usr/common/argp/instance.h"
#include "usr/common/argp/pool4.h"
#include "usr/common/argp/global.h"
#include "usr/common/argp/session.h"

#define DISPLAY "display"
#define ADD "add"
#define UPDATE "update"
#define REMOVE "remove"
#define FLUSH "flush"

// TODO Improve this and give it some use. */
//const char *argp_program_bug_address = "jool@nic.mx";

static int handle_autocomplete(char *junk, int argc, char **argv, void *arg);

static struct cmd_option instance_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_instance_display,
			.print_opts = print_instance_display_opts,
		}, {
			.label = ADD,
			.handler = handle_instance_add,
			.print_opts = print_instance_add_opts,
		}, {
			.label = REMOVE,
			.handler = handle_instance_remove,
			.print_opts = print_instance_remove_opts,
		}, {
			.label = FLUSH,
			.handler = handle_instance_flush,
			.print_opts = print_instance_flush_opts,
		},
		{ 0 },
};

static struct cmd_option global_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_global_display,
			.print_opts = print_global_display_opts,
		}, {
			.label = UPDATE,
			.child_builder = build_global_update_children,
		},
		{ 0 },
};

static struct cmd_option eamt_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_eamt_display,
			.print_opts = print_eamt_display_opts,
		}, {
			.label = ADD,
			.handler = handle_eamt_add,
			.print_opts = print_eamt_add_opts,
		}, {
			.label = REMOVE,
			.handler = handle_eamt_remove,
			.print_opts = print_eamt_remove_opts,
		}, {
			.label = FLUSH,
			.handler = handle_eamt_flush,
			.print_opts = print_eamt_flush_opts,
		},
		{ 0 },
};

struct cmd_option pool4_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_pool4_display,
			.print_opts = print_pool4_display_opts,
		}, {
			.label = ADD,
			.handler = handle_pool4_add,
			.print_opts = print_pool4_add_opts,
		}, {
			.label = REMOVE,
			.handler = handle_pool4_remove,
			.print_opts = print_pool4_remove_opts,
		}, {
			.label = FLUSH,
			.handler = handle_pool4_flush,
			.print_opts = print_pool4_flush_opts,
		},
		{ 0 },
};

static struct cmd_option bib_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_bib_display,
			.print_opts = print_bib_display_opts,
		}, {
			.label = ADD,
			.handler = handle_bib_add,
			.print_opts = print_bib_add_opts,
		}, {
			.label = REMOVE,
			.handler = handle_bib_remove,
			.print_opts = print_bib_remove_opts,
		},
		{ 0 },
};

static struct cmd_option session_ops[] = {
		{
			.label = DISPLAY,
			.handler = handle_session_display,
			.print_opts = print_session_display_opts,
		},
		{ 0 },
};

static struct cmd_option file_ops[] = {
		{
			.label = UPDATE,
			.handler = handle_file_update,
			.print_opts = print_file_update_opts,
		},
		{ 0 },
};

struct cmd_option tree[] = {
		{ .label = "instance",     .children = instance_ops, },
		{ .label = "global",       .children = global_ops, },
		{ .label = "eamt",         .children = eamt_ops, },
		{ .label = "pool4",        .children = pool4_ops, },
		{ .label = "bib",          .children = bib_ops, },
		{ .label = "session",      .children = session_ops, },
		{ .label = "file",         .children = file_ops, },
		/* TODO autocomplete autocomplete? */
		{ .label = "autocomplete", .handler  = handle_autocomplete, },
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
 * Returns the nodes from @iterator whose label start with @prefix.
 * (They will be chained via result->next.)
 * However, if there is a node whose entire label is @prefix, it returns that
 * one only.
 */
static struct cmd_option *find_matches(struct cmd_option *iterator, char *prefix)
{
	struct cmd_option *first = NULL;
	struct cmd_option *last = NULL;

	if (!iterator)
		return NULL;

	for (; iterator->label; iterator++) {
		if (memcmp(iterator->label, prefix, strlen(prefix)) == 0) {
			/*
			 * The labels never overlap like this so this isn't
			 * really useful right now.
			 * I'm including this only for the sake of correctness.
			 */
			if (strcmp(iterator->label, prefix) == 0)
				return iterator;

			if (first)
				last->next = iterator;
			else
				first = iterator;
			last = iterator;
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
		fprintf(stderr, "%s", nodes->label);
		if ((nodes + 1)->label)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int ambiguous_token(struct cmd_option *nodes, char *token)
{
	fprintf(stderr, "Ambiguous token: '%s'\n", token);
	fprintf(stderr, "Available options: ");
	for (; nodes; nodes = nodes->next) {
		fprintf(stderr, "%s", nodes->label);
		if (nodes->next)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int more_args_expected(struct cmd_option *nodes)
{
	fprintf(stderr, "More arguments expected.\n");
	fprintf(stderr, "Possible follow-ups: ");
	for (; nodes->label; nodes++) {
		fprintf(stderr, "%s", nodes->label);
		if ((nodes + 1)->label)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int __handle(char *instance, int argc, char **argv)
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
			return node->handler(instance, argc - i, &argv[i],
					node->args);
		}
		nodes = node->children;
	}

	if (!node->handler)
		return more_args_expected(node->children);

	log_info("Calling handler 2"); /* TODO */
	return node->handler(instance, argc - i, &argv[i], node->args);
}

static int handle(char *instance, int argc, char **argv)
{
	int error;

	error = init_cmd_option_array(tree);
	if (error)
		return error;

	error = __handle(instance, argc, argv);

	teardown_cmd_option_array(tree);
	return error;
}

static int print_opts(struct cmd_option *node, char *token)
{
	/* Does the token start with "--"? */
	if (strncmp("--", token, strlen("--")))
		return 0; /* Token is not a flag so there are no candidates. */

	node->print_opts(token + 2);
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

	argc -= 2;
	argv += 2;

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
		log_info("%s", node->label);

	return 0;
}

static int show_help(void)
{
	/* TODO */
	log_info("<help text goes here.>");
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

	/* Get rid of the program name. */
	argc--;
	argv++;

	if (argc == 0)
		return show_help();
	if (STR_EQUAL(argv[0], "--help") || STR_EQUAL(argv[0], "-h"))
		return show_help();
	if (STR_EQUAL(argv[0], "--version") || STR_EQUAL(argv[0], "-v"))
		return show_version();
	if (STR_EQUAL(argv[0], "-i")) {
		if (argc == 1) {
			log_err("-i requires a string as argument.");
			return -EINVAL;
		}
		iname = argv[1];
		argc -= 2;
		argv += 2;
	}

	return handle(iname, argc, argv);
}
