#include "global.h"

#include <argp.h>
#include <stdlib.h>

#include "common-global.h"
#include "userspace-types.h"
#include "wargp.h"
#include "netlink/global.h"

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
		struct full_config *conf)
{
	struct global_field *field;
	print_function print;

	if (show_csv_header(qargs->no_headers.value, qargs->csv.value))
		printf("Field,Value\n");

	get_global_fields(&field, NULL);

	for (; field->name; field++) {
		printf("%s%s", field->name, qargs->csv.value ? "," : ": ");
		print = field->print ? : field->type->print;
		print(get_field(conf, field));
		printf("\n");
	}

	return 0;
}

int handle_global_display(int argc, char **argv)
{
	struct display_args dargs = { 0 };
	struct full_config config;
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	error = global_query(&config);
	if (error)
		return error;

	return handle_display_response(&dargs, &config);
}

void print_global_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
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
		log_err("(See `%s --help')", argv[0]);
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
	free(opts); /* TODO --help and --usage skip this. */
	if (error)
		return error;

	if (uargs.value) {
		error = global_update(uargs.field, uargs.value);
		free(uargs.value);
	}

	return error;
}

void print_global_update_opts(char *prefix)
{
	struct global_field *field;
	get_global_fields(&field, NULL);

	for (; field->name; field++)
		if (strncmp(prefix, field->name, strlen(prefix)) == 0)
			printf("--%s\n", field->name);
}
