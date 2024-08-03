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

	cfg->enabled = true;

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
	struct netsocket_cfg netcfg = { .enabled = true, .ttl = 1 };
	struct statsocket_cfg statcfg = { .address = "::" };
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

	if (!netcfg.mcast_port)
		netcfg.mcast_port = "6400";
	if (!statcfg.port)
		statcfg.port = "6401";

	printf("Config:\n");
	printf("  mod.instance: %s\n", iname);
	if (netcfg.enabled) {
		printf("  net.mcast.addr: %s\n", netcfg.mcast_addr);
		printf("  net.mcast.port: %s\n", netcfg.mcast_port);
		printf("  net.dev.in: %s\n", netcfg.in_interface);
		printf("  net.dev.out: %s\n", netcfg.out_interface);
		printf("  net.ttl: %d\n", netcfg.ttl);
	}
	if (statcfg.enabled) {
		printf("  stats.addr: %s\n", statcfg.address);
		printf("  stats.port: %s\n", statcfg.port);
	}

	printf("\n");
	printf("joold is intended as a daemon, so it outputs straight to syslog.\n");
	printf("The standard streams will mostly shut up from now on.\n");
	printf("---------------------------------------------\n");

	return joold_start(iname, &netcfg, &statcfg);
}
