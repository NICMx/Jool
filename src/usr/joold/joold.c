#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "usr/joold/json.h"
#include "usr/argp/wargp/session.h"

static int modsocket_config(char const *filename, char **iname)
{
	cJSON *json;
	int error;

	error = read_json(filename, &json);
	if (error)
		return error;

	error = json2str(filename, json, "instance", iname);

	cJSON_Delete(json);
	return error;
}

static int netsocket_config(char const *file, struct netsocket_cfg *cfg)
{
	cJSON *json;
	int error;

	error = read_json(file, &json);
	if (error)
		return error;

	error = json2str(file, json, "multicast address", &cfg->mcast_addr);
	if (error)
		goto end;
	error = json2str(file, json, "multicast port", &cfg->mcast_port);
	if (error)
		goto end;
	error = json2str(file, json, "in interface", &cfg->in_interface);
	if (error)
		goto end;
	error = json2str(file, json, "out interface", &cfg->out_interface);
	if (error)
		goto end;
	error = json2int(file, json, "ttl", &cfg->ttl);

	if (cfg->ttl < 0 || 256 < cfg->ttl) {
		fprintf(stderr, "%s: ttl out of range: %d\n", file, cfg->ttl);
		return 1;
	}

end:	cJSON_Delete(json);
	return error;
}

static void statsocket_config(char *port, struct statsocket_cfg *cfg)
{
	cfg->enabled = true;
	cfg->port = port;
}

int main(int argc, char **argv)
{
	char *iname = "default";
	struct netsocket_cfg netcfg = {
		.mcast_port = "6400",
		.enabled = true,
		.ttl = 1,
	};
	struct statsocket_cfg statcfg = {
		.address = "::",
		.port = "6401",
	};
	int error;

	fprintf(stderr, "Warning: `joold` is deprecated. See `jool session proxy --help`.\n");

	if (argc < 3) {
		fprintf(stderr, "Not enough arguments.\n");
		return EINVAL;
	}

	error = modsocket_config(argv[2], &iname);
	if (error)
		return error;
	error = netsocket_config(argv[1], &netcfg);
	if (error)
		return error;
	if (argc >= 4)
		statsocket_config(argv[3], &statcfg);

	return joold_start(iname, &netcfg, &statcfg);
}
