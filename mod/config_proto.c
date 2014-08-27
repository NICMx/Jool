#include "nat64/comm/config_proto.h"
#include <linux/slab.h>
#include "nat64/mod/types.h"


int serialize_general_config(struct response_general *config, unsigned char **buffer_out,
		size_t *buffer_len_out)
{
	struct sessiondb_config *sconfig;
	struct fragmentation_config *fconfig;
	unsigned char *buffer;
	size_t mtus_len;

	mtus_len = config->translate.mtu_plateau_count * sizeof(*config->translate.mtu_plateaus);

	buffer = kmalloc(sizeof(*config) + mtus_len, GFP_KERNEL);
	if (!buffer) {
		log_debug("Could not allocate the configuration structure.");
		return -ENOMEM;
	}

	memcpy(buffer, config, sizeof(*config));
	memcpy(buffer + sizeof(*config), config->translate.mtu_plateaus, mtus_len);

	sconfig = &((struct response_general *) buffer)->sessiondb;
	sconfig->ttl.udp = jiffies_to_msecs(config->sessiondb.ttl.udp);
	sconfig->ttl.tcp_est = jiffies_to_msecs(config->sessiondb.ttl.tcp_est);
	sconfig->ttl.tcp_trans = jiffies_to_msecs(config->sessiondb.ttl.tcp_trans);
	sconfig->ttl.icmp = jiffies_to_msecs(config->sessiondb.ttl.icmp);

	fconfig = &((struct response_general *) buffer)->fragmentation;
	fconfig->fragment_timeout = jiffies_to_msecs(config->fragmentation.fragment_timeout);

	*buffer_out = buffer;
	*buffer_len_out = sizeof(*config) + mtus_len;
	return 0;
}

int deserialize_general_config(void *buffer, __u16 buffer_len, struct response_general *target_out)
{
	struct sessiondb_config *sconfig;
	struct translate_config *tconfig;
	struct fragmentation_config *fconfig;
	size_t mtus_len;

	memcpy(target_out, buffer, sizeof(*target_out));

	sconfig = &target_out->sessiondb;
	sconfig->ttl.udp = msecs_to_jiffies(sconfig->ttl.udp);
	sconfig->ttl.tcp_est = msecs_to_jiffies(sconfig->ttl.tcp_est);
	sconfig->ttl.tcp_trans = msecs_to_jiffies(sconfig->ttl.tcp_trans);
	sconfig->ttl.icmp = msecs_to_jiffies(sconfig->ttl.icmp);

	tconfig = &target_out->translate;
	tconfig->mtu_plateaus = NULL;
	if (tconfig->mtu_plateau_count) {
		mtus_len = tconfig->mtu_plateau_count * sizeof(*tconfig->mtu_plateaus);
		tconfig->mtu_plateaus = kmalloc(mtus_len, GFP_ATOMIC);
		if (!tconfig->mtu_plateaus) {
			log_debug("Could not allocate the config's plateaus.");
			return -ENOMEM;
		}
		memcpy(tconfig->mtu_plateaus, buffer + sizeof(*target_out), mtus_len);
	}

	fconfig = &target_out->fragmentation;
	fconfig->fragment_timeout = msecs_to_jiffies(fconfig->fragment_timeout);

	return 0;
}
