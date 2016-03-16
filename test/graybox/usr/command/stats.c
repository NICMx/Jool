#include "stats.h"

#include <errno.h>
#include <netlink/attr.h>
#include "nat64/common/types.h"

int stats_init_request(int argc, char **argv, enum graybox_command *cmd)
{
	if (argc < 1) {
		log_err("stats needs an operation as first argument.");
		return -EINVAL;
	}

	if (strcasecmp(argv[0], "display") == 0) {
		*cmd = COMMAND_STATS_DISPLAY;
		return 0;
	} else if (strcasecmp(argv[0], "flush") == 0) {
		*cmd = COMMAND_STATS_FLUSH;
		return 0;
	}

	log_err("Unknown operation for stats: %s", argv[0]);
	return -EINVAL;
}

int stats_response_handle(struct nlattr **attrs, void *arg)
{
	struct graybox_stats *stats;

	if (!attrs[ATTR_STATS]) {
		log_err("The module's response lacks a stats structure.");
		return -EINVAL;
	}

	stats = nla_data(attrs[ATTR_STATS]);
	log_info("IPv6:");
	log_info("	Successes: %u", stats->ipv6.successes);
	log_info("	Failures:  %u", stats->ipv6.failures);
	log_info("	Queued:    %u", stats->ipv6.queued);
	log_info("IPv4:");
	log_info("	Successes: %u", stats->ipv4.successes);
	log_info("	Failures:  %u", stats->ipv4.failures);
	log_info("	Queued:    %u", stats->ipv4.queued);

	return 0;
}
