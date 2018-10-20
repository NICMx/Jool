#include "global.h"

#include <argp.h>
#include <stdlib.h>
#include <string.h>

#include "common/common-global.h"
#include "usr/common/command.h"
#include "usr/common/netlink.h"
#include "usr/common/userspace-types.h"
#include "usr/common/wargp.h"
#include "usr/common/nl/global.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
};

static struct wargp_option display_opts[] = {
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

#define get_field(config, field) ((void *)config + field->offset)

static int handle_display_response(struct display_args *qargs,
		struct globals *conf)
{
	struct global_field *field;
	print_function print;

	if (show_csv_header(qargs->no_headers.value, qargs->csv.value))
		printf("Field,Value\n");

	get_global_fields(&field, NULL);

	for (; field->name; field++) {
		if ((xlat_type() & field->xt) == 0)
			continue;

		if (!qargs->csv.value)
			printf("  ");
		printf("%s%s", field->name, qargs->csv.value ? "," : ": ");
		print = field->print ? : field->type->print;
		print(get_field(conf, field), qargs->csv.value);
		printf("\n");
	}

	return 0;
}

int handle_global_display(char *iname, int argc, char **argv, void *arg)
{
	struct display_args dargs = { 0 };
	struct globals config;
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	error = netlink_setup();
	if (error)
		return error;

	error = global_query(iname, &config);

	netlink_teardown();

	return error ? : handle_display_response(&dargs, &config);
}

void print_global_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}

struct update_args {
	struct wargp_string global_str;
	struct wargp_bool force;
};

static struct wargp_option update_opts[] = {
	WARGP_FORCE(struct update_args, force),
	{
		.name = "Value",
		.key = ARGP_KEY_ARG,
		.doc = "New value the variable should be changed to",
		.offset = offsetof(struct update_args, global_str),
		.type = &wt_string,
	},
	{ 0 },
};

static int handle_global_update(char *iname, int argc, char **argv, void *arg)
{
	struct update_args uargs = { 0 };
	struct global_field *field = arg;
	void *value;
	int error;

	error = wargp_parse(update_opts, argc, argv, &uargs);
	if (error)
		return error;

	if (!uargs.global_str.value) {
		log_err("Missing value of key %s.", argv[0]);
		return -EINVAL;
	}

	value = malloc(field->type->size);
	if (!value)
		return -ENOMEM;

	error = field->type->parse(field, uargs.global_str.value, value);
	if (error)
		goto end;

	error = netlink_setup();
	if (error)
		goto end;
	error = global_update(iname, field, value, uargs.force.value);
	netlink_teardown();
	/* Fall through */

end:
	free(value);
	return error;
}

void print_global_update_opts(char *prefix)
{
	print_wargp_opts(update_opts, prefix);
}

struct cmd_option *build_global_update_children(void)
{
	struct global_field *global_fields;
	unsigned int field_count;
	struct cmd_option *opts;
	unsigned int i;

	get_global_fields(&global_fields, &field_count);

	opts = calloc(field_count + 1, sizeof(struct cmd_option));
	if (!opts)
		return NULL;

	for (i = 0; i < field_count; i++) {
		opts[i].label = global_fields[i].name;
		opts[i].xt = global_fields[i].xt;
		opts[i].handler = handle_global_update;
		opts[i].args = &global_fields[i];
		opts[i].print_opts = print_global_update_opts;
	}

	return opts;
}
