#include "file.h"

#include <errno.h>
#include "usr/common/log.h"
#include "usr/common/netlink.h"
#include "usr/common/requirements.h"
#include "usr/common/wargp.h"
#include "usr/common/nl/json.h"

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
	int error;

	error = wargp_parse(update_opts, argc, argv, &uargs);
	if (error)
		return error;

	if (!uargs.file_name.value) {
		struct requirement reqs[] = {
				{ false, "a file name" },
				{ 0 }
		};
		return requirement_print(reqs);
	}

	error = netlink_setup();
	if (error)
		return error;

	error = parse_file(uargs.file_name.value, uargs.force.value);

	netlink_teardown();
	return error;
}

void autocomplete_file_update(void *args)
{
	/* Do nothing; default to autocomplete directory path */
}
