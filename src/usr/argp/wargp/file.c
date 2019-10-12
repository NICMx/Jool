#include "file.h"

#include <errno.h>

#include "log.h"
#include "requirements.h"
#include "wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/nl/jool_socket.h"
#include "usr/nl/json.h"

struct update_args {
	struct wargp_string file_name;
	struct wargp_bool force;
};

static struct wargp_option update_opts[] = {
	WARGP_FORCE(struct update_args, force),
	{
		.name = "File name",
		.key = ARGP_KEY_ARG,
		.doc = "Path to a JSON file containing Jool's configuration.",
		.offset = offsetof(struct update_args, file_name),
		.type = &wt_string,
	},
	{ 0 },
};

int handle_file_update(char *iname, int argc, char **argv, void *arg)
{
	struct update_args uargs = { 0 };
	struct jool_socket sk;
	struct jool_result result;

	result.error = wargp_parse(update_opts, argc, argv, &uargs);
	if (result.error)
		return result.error;

	if (!uargs.file_name.value) {
		struct requirement reqs[] = {
				{ false, "a file name" },
				{ 0 }
		};
		return requirement_print(reqs);
	}

	result = netlink_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = json_parse(&sk, xt_get(), iname, uargs.file_name.value,
			uargs.force.value);

	netlink_teardown(&sk);
	return pr_result(&result);
}

void autocomplete_file_update(void *args)
{
	/* Do nothing; default to autocomplete directory path */
}
