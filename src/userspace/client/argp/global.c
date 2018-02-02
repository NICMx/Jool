#include "global.h"

#include <argp.h>
#include <stdlib.h>

#include "common-global.h"
#include "nl-protocol.h"
#include "userspace-types.h"
#include "usr-str-utils.h"
#include "netlink/global.h"

#define ARGP_CSV 2003
#define ARGP_NO_HEADERS 2004

struct query_args {
	display_flags flags;
};

static struct argp_option argp_query_opts[] = {
	{
		.name = "no-headers",
		.key = ARGP_NO_HEADERS,
		.doc = "Do not print table headers.",
	},
	{
		.name = "csv",
		.key = ARGP_CSV,
		.doc = "Print in CSV format.",
	},
	{ 0 },
};

static int parse_query_opts(int key, char *str, struct argp_state *state)
{
	struct query_args *args = state->input;

	switch (key) {
	case ARGP_CSV:
		args->flags |= DF_CSV_FORMAT;
		return 0;
	case ARGP_NO_HEADERS:
		args->flags |= DF_NO_HEADERS;
	}

	return ARGP_ERR_UNKNOWN;
}

#define get_field(config, field) ((void *)config + field->offset)

static int handle_display_response(struct full_config *conf,
		display_flags flags, bool csv)
{
	struct global_field *field;
	print_function print;

	if (show_csv_header(flags))
		printf("Field,Value\n");

	get_global_fields(&field, NULL);

	for (; field->name; field++) {
		printf("%s%s", field->name, csv ? "," : ": ");
		print = field->print ? : field->type->print;
		print(get_field(conf, field));
		printf("\n");
	}

	return 0;
}

int handle_global_display(int argc, char **argv)
{
	static struct argp argp = { argp_query_opts, parse_query_opts, NULL, NULL };
	struct query_args qargs;
	struct full_config config;
	int error;

	memset(&qargs, 0, sizeof(qargs));
	error = argp_parse(&argp, argc, argv, 0, NULL, &qargs);
	if (error)
		return error;

	error = global_query(&config);
	if (error)
		return error;

	return (qargs.flags & DF_CSV_FORMAT)
			? handle_display_response(&config, qargs.flags, true)
			: handle_display_response(&config, qargs.flags, false);
}

struct update_args {
	unsigned int field;
	void *value;
};

static int parse_update_opts(int key, char *str, struct argp_state *state)
{
	struct update_args *uargs = state->input;
	struct global_field *field;
	unsigned int field_count;
	int error;

	get_global_fields(&field, &field_count);
	if (key >= field_count)
		return ARGP_ERR_UNKNOWN;
	field = &field[key];

	uargs->field = key;
	uargs->value = malloc(field->type->size);
	if (!uargs->value)
		return -ENOMEM;

	error = field->type->parse(field, str, uargs->value);
	if (error)
		free(uargs->value);

	return error;
}

int handle_global_update(int argc, char **argv)
{
	struct global_field *global_fields;
	unsigned int field_count;
	static struct argp argp = { .parser = parse_update_opts, };
	struct argp_option *opts;
	struct update_args uargs = { .field = 0, .value = NULL, };
	unsigned int i;
	int error;

	if (argc == 1) {
		log_err("Expected at least one global configuration keyvalue.");
		log_err("(See `update --help')");
		return -EINVAL;
	}

	get_global_fields(&global_fields, &field_count);

	opts = calloc(field_count + 1, sizeof(struct argp_option));
	if (!opts)
		return -ENOMEM;
	argp.options = opts;

	for (i = 0; i < field_count; i++) {
		opts[i].name = global_fields[i].name;
		opts[i].key = i;
		opts[i].arg = global_fields[i].type->name;
		opts[i].doc = global_fields[i].doc;
	}

	error = argp_parse(&argp, argc, argv, 0, NULL, &uargs);
	free(opts);
	if (error)
		return error;

	if (uargs.value) {
		error = global_update(uargs.field, uargs.value);
		free(uargs.value);
	}

	return error;
}
