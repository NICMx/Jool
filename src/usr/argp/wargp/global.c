#include "usr/argp/wargp/global.h"

#include "usr/argp/command.h"
#include "usr/argp/log.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"
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

static struct jool_result handle_display_response(
		struct joolnl_global_meta const *metadata,
		void *value, void *args)
{
	struct display_args *dargs = args;

	if (!dargs->csv.value)
		printf("  ");
	printf("%s%s", joolnl_global_meta_name(metadata),
			dargs->csv.value ? "," : ": ");
	joolnl_global_print(metadata, value, dargs->csv.value);
	printf("\n");

	return result_success();
}

int handle_global_display(char *iname, int argc, char **argv, void const *arg)
{
	struct display_args dargs = { 0 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(display_opts, argc, argv, &dargs);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	if (show_csv_header(dargs.no_headers.value, dargs.csv.value))
		printf("Field,Value\n");

	result = joolnl_global_foreach(&sk, iname, handle_display_response,
			&dargs);

	joolnl_teardown(&sk);

	return pr_result(&result);
}

void autocomplete_global_display(void const *args)
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

static int handle_global_update(char *iname, int argc, char **argv,
		void const *field)
{
	struct update_args uargs = { 0 };
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
	result = joolnl_global_update(&sk, iname, field, uargs.global_str.value,
			uargs.force.value);
	joolnl_teardown(&sk);

	return pr_result(&result);
}

void autocomplete_global_update(void const *meta)
{
	printf("%s ", joolnl_global_meta_values(meta));
	print_wargp_opts(update_opts);
}

struct mapt_update_args {
	struct wargp_prefix6 eui6p;
	struct wargp_u64 ea_bits;
	struct wargp_prefix6 bmr_p6;
	struct wargp_prefix4 bmr_p4;
	struct wargp_u8 bmr_ebl;
	struct wargp_u8 a;
	struct wargp_u8 k;
	struct wargp_u8 m;
};

/* TODO (mapt) docs */
static struct wargp_option mapt_update_opts[] = {
	{
		.xt = XT_MAPT,
		.name = "end-user-ipv6-prefix",
		.key = 1002,
		.doc = "",
		.offset = offsetof(struct mapt_update_args, eui6p),
		.type = &wt_prefix6,
	}, {
		.xt = XT_MAPT,
		.name = "ea-bits",
		.key = 1001,
		.doc = "",
		.offset = offsetof(struct mapt_update_args, ea_bits),
		.type = &wt_u64,
	}, {
		.xt = XT_MAPT,
		.name = "bmr.ipv6-prefix",
		.key = 1003,
		.doc = "",
		.offset = offsetof(struct mapt_update_args, bmr_p6),
		.type = &wt_prefix6,
	}, {
		.xt = XT_MAPT,
		.name = "bmr.ipv4-prefix",
		.key = 1004,
		.doc = "",
		.offset = offsetof(struct mapt_update_args, bmr_p4),
		.type = &wt_prefix4,
	}, {
		.xt = XT_MAPT,
		.name = "bmr.ea-bits-length",
		.key = 1005,
		.doc = "",
		.offset = offsetof(struct mapt_update_args, bmr_ebl),
		.type = &wt_u8,
	}, {
		.xt = XT_MAPT,
		.name = "a",
		.key = 'a',
		.doc = "",
		.offset = offsetof(struct mapt_update_args, a),
		.type = &wt_u8,
	}, {
		.xt = XT_MAPT,
		.name = "k",
		.key = 'k',
		.doc = "",
		.offset = offsetof(struct mapt_update_args, k),
		.type = &wt_u8,
	}, {
		.xt = XT_MAPT,
		.name = "m",
		.key = 'm',
		.doc = "",
		.offset = offsetof(struct mapt_update_args, m),
		.type = &wt_u8,
	},
	{ 0 },
};

static struct jool_result __joolnl_global_mapt_update(struct joolnl_socket *sk,
		char const *iname, struct mapt_update_args *uargs)
{
	struct nl_msg *msg;
	struct nlattr *root, *mapt;
	struct jool_result result;
	int error;

	result = joolnl_alloc_msg(sk, iname, JNLOP_GLOBAL_UPDATE, 0, &msg);
	if (result.error)
		return result;

	root = jnla_nest_start(msg, JNLAR_GLOBALS);
	if (!root)
		return joolnl_err_msgsize();
	mapt = jnla_nest_start(msg, JNLAG_MAPT);
	if (!mapt)
		return joolnl_err_msgsize();

	error = 0;
	if (uargs->eui6p.set)
		error = nla_put_prefix6(msg, JNLAMT_EUI6P, &uargs->eui6p.prefix);
	if (!error && uargs->ea_bits.set)
		error = nla_put_u64(msg, JNLAMT_EABITS, uargs->ea_bits.value);
	if (!error && uargs->bmr_p6.set)
		error = nla_put_prefix6(msg, JNLAMT_BMR_P6, &uargs->bmr_p6.prefix);
	if (!error && uargs->bmr_p4.set)
		error = nla_put_prefix4(msg, JNLAMT_BMR_P4, &uargs->bmr_p4.prefix);
	if (!error && uargs->bmr_ebl.set)
		error = nla_put_u8(msg, JNLAMT_BMR_EBL, uargs->bmr_ebl.value);
	if (!error && uargs->a.set)
		error = nla_put_u8(msg, JNLAMT_a, uargs->a.value);
	if (!error && uargs->k.set)
		error = nla_put_u8(msg, JNLAMT_k, uargs->k.value);
	if (!error && uargs->m.set)
		error = nla_put_u8(msg, JNLAMT_m, uargs->m.value);

	if (error) {
		nlmsg_free(msg);
		return result_from_error(error, iname);
	}

	nla_nest_end(msg, mapt);
	nla_nest_end(msg, root);
	return joolnl_request(sk, msg, NULL, NULL);
}

static int handle_global_update_mapt(char *iname, int argc, char **argv,
		void const *field)
{
	struct mapt_update_args uargs = { 0 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(mapt_update_opts, argc, argv, &uargs);
	if (result.error)
		return result.error;

	if (!uargs.eui6p.set && !uargs.bmr_p6.set
			&& !uargs.bmr_p4.set && !uargs.bmr_ebl.set &&
			!uargs.a.set && !uargs.k.set && !uargs.m.set) {
		pr_err("At least one argument expected.");
		return -EINVAL;
	}

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);
	result = __joolnl_global_mapt_update(&sk, iname, &uargs);
	joolnl_teardown(&sk);

	return pr_result(&result);
}

struct cmd_option *build_global_update_children(void)
{
	struct joolnl_global_meta const *meta;
	struct cmd_option *opts;
	struct cmd_option *opt;

	opts = calloc(joolnl_global_meta_count() + 1, sizeof(struct cmd_option));
	if (!opts)
		return NULL;

	opt = opts;
	joolnl_global_foreach_meta(meta) {
		opt->label = joolnl_global_meta_name(meta);
		opt->xt = joolnl_global_meta_xt(meta);
		/* Derp */
		opt->handler = (strcasecmp(opt->label, "mapt") == 0)
				? handle_global_update_mapt
				: handle_global_update;
		opt->handle_autocomplete = autocomplete_global_update;
		opt->args = meta;
		opt++;
	}

	return opts;
}
