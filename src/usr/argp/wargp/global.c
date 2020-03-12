#include "usr/argp/wargp/global.h"

#include "usr/argp/command.h"
#include "usr/argp/log.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/nl/core.h"
#include "usr/nl/global.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
};

static struct wargp_option display_opts[] = {
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

#define get_field(config, field) ((unsigned char *)config + field->offset)

static int handle_display_response(struct display_args *qargs,
		struct globals *conf)
{
	struct global_field *field;
	print_function print;

	if (show_csv_header(qargs->no_headers.value, qargs->csv.value))
		printf("Field,Value\n");

	get_global_fields(&field, NULL);

	for (; field->name; field++) {
		if ((xt_get() & field->xt) == 0)
			continue;

		if (!qargs->csv.value)
			printf("  ");
		printf("%s%s", field->name, qargs->csv.value ? "," : ": ");
		print = field->print ? field->print : field->type->print;
		print(get_field(conf, field), qargs->csv.value);
		printf("\n");
	}

	return 0;
}

int handle_global_display(char *iname, int argc, char **argv, void *arg)
{
	struct display_args dargs = { 0 };
	struct joolnl_socket sk;
	struct globals config;
	struct jool_result result;

	result.error = wargp_parse(display_opts, argc, argv, &dargs);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joolnl_global_query(&sk, iname, &config);

	joolnl_teardown(&sk);

	if (result.error)
		return pr_result(&result);

	return handle_display_response(&dargs, &config);
}

void autocomplete_global_display(void *args)
{
	print_wargp_opts(display_opts);
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
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(update_opts, argc, argv, &uargs);
	if (result.error)
		return result.error;

	if (!uargs.global_str.value) {
		pr_err("Missing value of key %s.", argv[0]);
		return -EINVAL;
	}

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);
	result = joolnl_global_update(&sk, iname, field, uargs.global_str.value, uargs.force.value);
	joolnl_teardown(&sk);

	return pr_result(&result);
}

void autocomplete_global_update(void *arg)
{
	struct global_field *field = arg;

	if (field->candidates)
		printf("%s ", field->candidates);
	else if (field->type->candidates)
		printf("%s ", field->type->candidates);

	print_wargp_opts(update_opts);
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
		opts[i].handle_autocomplete = autocomplete_global_update;
		opts[i].args = &global_fields[i];
	}

	return opts;
}
