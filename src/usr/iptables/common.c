#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <xtables.h>

#include "usr/common/global.h"

static const struct option jool_tg_opts[] = {
	{ .name = OPTNAME_INAME, .has_arg = true, .val = 'i'},
	{ NULL },
};

/**
 * Called when user execs "iptables -m jool -h"
 */
static void jool_tg_help(void)
{
	printf("jool target options:\n");
	printf("[!] --" OPTNAME_INAME "    Name of the Jool instance that should handle this rule's packets.\n");
}

static void jool_tg_init(struct xt_entry_target *target)
{
	struct target_info *info = (struct target_info *)target->data;
	strcpy(info->iname, INAME_DEFAULT);
}

/* TODO (duplicate code) See config.h */
int iname_validate(const char *iname, bool allow_null)
{
	unsigned int i;

	if (!iname) {
		if (allow_null)
			return 0;
		goto fail;
	}

	for (i = 0; i < INAME_MAX_LEN; i++) {
		if (iname[i] == '\0')
			return 0;
		if (iname[i] < 32) /* "if not printable" */
			break;
	}
	/* Fall through. */

fail:
	log_err("The instance name must be a null-terminated ascii string, %u characters max.",
			INAME_MAX_LEN - 1);
	return -EINVAL;
}

/*
 * Called once for every argument the user sends the rule upon creation.
 */
static int jool_tg_parse(int c, char **argv, int invert, unsigned int *flags,
		const void *entry, struct xt_entry_target **target)
{
	struct target_info *info = (struct target_info *)(*target)->data;
	int error;

	if (c != 'i')
		return false;

	error = iname_validate(optarg, false);
	if (error)
		return error;
	strcpy(info->iname, optarg);
	return true;
}

/**
 * Called when user execs "iptables -L"
 */
static void jool_tg_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	struct target_info *info = (struct target_info *)target->data;
	printf("instance: %s ", info->iname);
}

/**
 * Called when user execs "iptables-save"
 */
static void jool_tg_save(const void *ip, const struct xt_entry_target *target)
{
	struct target_info *info = (struct target_info *)target->data;
	printf("--" OPTNAME_INAME " %s ", info->iname);
}

static struct xtables_target targets[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = IPTABLES_MODULE_NAME,
		.revision      = 0,
		.family        = PF_INET6,
		.size          = XT_ALIGN(sizeof(struct target_info)),
		.userspacesize = XT_ALIGN(sizeof(struct target_info)),
		.help          = jool_tg_help,
		.init          = jool_tg_init,
		.parse         = jool_tg_parse,
		.print         = jool_tg_print,
		.save          = jool_tg_save,
		.extra_opts    = jool_tg_opts,
	}, {
		.version       = XTABLES_VERSION,
		.name          = IPTABLES_MODULE_NAME,
		.revision      = 0,
		.family        = PF_INET,
		.size          = XT_ALIGN(sizeof(struct target_info)),
		.userspacesize = XT_ALIGN(sizeof(struct target_info)),
		.help          = jool_tg_help,
		.init          = jool_tg_init,
		.parse         = jool_tg_parse,
		.print         = jool_tg_print,
		.save          = jool_tg_save,
		.extra_opts    = jool_tg_opts,
	}
};

static void _init(void)
{
	xtables_register_targets(targets, sizeof(targets) / sizeof(targets[0]));
}
