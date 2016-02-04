#include "nat64/mod/common/nl/global.h"

#include <linux/sort.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateless/eam.h"


static enum config_mode command = MODE_GLOBAL;

static int ensure_siit(void)
{
	if (!xlat_is_siit()) {
		log_err("Requested field is SIIT-only.");
		return -EINVAL;
	}

	return 0;
}

static int ensure_nat64(void)
{
	if (!xlat_is_nat64()) {
		log_err("Requested field is NAT64-only.");
		return -EINVAL;
	}

	return 0;
}

static bool ensure_bytes(size_t actual, size_t expected)
{
	if (actual < expected) {
		log_err("Expected a %zu-byte value, got %zu bytes.",
				expected, actual);
		return false;
	}
	return true;
}

static int parse_u8(__u8 *field, void *value, size_t size)
{
	if (!ensure_bytes(size, 1))
		return -EINVAL;
	*field = *((__u8 *)value);
	return 1;
}

static int parse_u32(__u32 *field, void *value, size_t size)
{
	if (!ensure_bytes(size, 4))
		return -EINVAL;
	*field = *((__u32 *)value);
	return 4;
}

static int parse_timeout(__u64 *field, void *value, size_t size,
		unsigned int min)
{
	/*
	 * TODO (fine) this max is somewhat arbitrary. We do have a maximum,
	 * but I don't recall what or why it was. I do remember it's bigger than
	 * this.
	 */
	const __u32 MAX_U32 = 0xFFFFFFFFU;
	__u64 value64;

	if (!ensure_bytes(size, 8))
		return -EINVAL;

	value64 = *((__u64 *)value);

	if (value64 < 1000 * min) {
		log_err("The timeout must be at least %u seconds.", min);
		return -EINVAL;
	}
	if (value64 > MAX_U32) {
		log_err("Expected a timeout less than %u seconds",
				MAX_U32 / 1000);
		return -EINVAL;
	}

	*field = msecs_to_jiffies(value64);
	return 8;
}

static int be16_compare(const void *a, const void *b)
{
	return *(__u16 *)b - *(__u16 *)a;
}

static void be16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

static int update_plateaus(struct global_config *config, void *payload,
		size_t payload_max_size)
{
	__u16 *list;
	size_t list_max_size;
	__u16 list_length;
	unsigned int i, j;

	if (payload_max_size == 0) {
		log_err("There is no data in the request.");
		return -EINVAL;
	}

	list_length = *((__u16 *)payload);
	if (list_length == 0) {
		log_err("The MTU list received from userspace is empty.");
		return -EINVAL;
	}
	if (list_length > ARRAY_SIZE(config->mtu_plateaus)) {
		log_err("Too many plateau values; there's only room for %zu.",
				ARRAY_SIZE(config->mtu_plateaus));
		return -EINVAL;
	}

	list = payload + sizeof(list_length);
	list_max_size = payload_max_size - sizeof(list_length);

	if (list_length * sizeof(*list) > list_max_size) {
		log_err("The request seems truncated.");
		return -EINVAL;
	}

	/* Sort descending. */
	sort(list, list_length, sizeof(*list), be16_compare, be16_swap);

	/* Remove zeroes and duplicates. */
	for (i = 0, j = 1; j < list_length; j++) {
		if (list[j] == 0)
			break;
		if (list[i] != list[j]) {
			i++;
			list[i] = list[j];
		}
	}

	if (list[0] == 0) {
		log_err("The MTU list contains nothing but zeroes.");
		return -EINVAL;
	}

	/* Update. */
	memcpy(config->mtu_plateaus, list, (i + 1) * sizeof(*list));
	config->mtu_plateau_count = i + 1;

	return sizeof(list_length) + list_length * sizeof(*list);
}

static int handle_global_display(struct xlator *jool, struct genl_info *info)
{
	struct full_config config;
	bool enabled;

	log_debug("Returning 'Global' options.");

	xlator_copy_config(jool, &config);

	enabled = !pool6_is_empty(jool->pool6);
	if (xlat_is_nat64())
		enabled |= !eamt_is_empty(jool->siit.eamt);
	prepare_config_for_userspace(&config, enabled);

	return nlcore_respond_struct(info, command, &config, sizeof(config));
}

/**
 * On success, returns the number of bytes consumed from @payload.
 * On error, returns a negative error code.
 */
static int massive_switch(struct full_config *cfg, enum global_type type,
		void *value, size_t size)
{
	__u8 tmp8;
	int error;

	switch (type) {
	case MAX_PKTS:
		error = ensure_nat64();
		return error ? : parse_u32(&cfg->session.pktqueue.max_stored_pkts, value, size);
	case SRC_ICMP6ERRS_BETTER:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->global.nat64.src_icmp6errs_better, value, size);
	case BIB_LOGGING:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->bib.log_changes, value, size);
	case SESSION_LOGGING:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->session.log_changes, value, size);
	case UDP_TIMEOUT:
		error = ensure_nat64();
		return error ? : parse_timeout(&cfg->session.ttl.udp, value, size, UDP_MIN);
	case ICMP_TIMEOUT:
		error = ensure_nat64();
		return error ? : parse_timeout(&cfg->session.ttl.icmp, value, size, 0);
	case TCP_EST_TIMEOUT:
		error = ensure_nat64();
		return error ? : parse_timeout(&cfg->session.ttl.tcp_est, value, size, TCP_EST);
	case TCP_TRANS_TIMEOUT:
		error = ensure_nat64();
		return error ? : parse_timeout(&cfg->session.ttl.tcp_trans, value, size, TCP_TRANS);
	case FRAGMENT_TIMEOUT:
		error = ensure_nat64();
		return error ? : parse_timeout(&cfg->global.nat64.ttl.frag, value, size, FRAGMENT_MIN);
	case DROP_BY_ADDR:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->global.nat64.drop_by_addr, value, size);
	case DROP_ICMP6_INFO:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->global.nat64.drop_icmp6_info, value, size);
	case DROP_EXTERNAL_TCP:
		error = ensure_nat64();
		return error ? : parse_u8(&cfg->global.nat64.drop_external_tcp, value, size);
	case COMPUTE_UDP_CSUM_ZERO:
		error = ensure_siit();
		return error ? : parse_u8(&cfg->global.siit.compute_udp_csum_zero, value, size);
	case EAM_HAIRPINNING_MODE:
		error = ensure_siit();
		return error ? : parse_u8(&cfg->global.siit.eam_hairpin_mode, value, size);
	case RANDOMIZE_RFC6791:
		error = ensure_siit();
		return error ? : parse_u8(&cfg->global.siit.randomize_error_addresses, value, size);
	case RESET_TCLASS:
		return parse_u8(&cfg->global.reset_traffic_class, value, size);
	case RESET_TOS:
		return parse_u8(&cfg->global.reset_tos, value, size);
	case NEW_TOS:
		return parse_u8(&cfg->global.new_tos, value, size);
	case DF_ALWAYS_ON:
		return parse_u8(&cfg->global.atomic_frags.df_always_on, value, size);
	case BUILD_IPV6_FH:
		return parse_u8(&cfg->global.atomic_frags.build_ipv6_fh, value, size);
	case BUILD_IPV4_ID:
		return parse_u8(&cfg->global.atomic_frags.build_ipv4_id, value, size);
	case LOWER_MTU_FAIL:
		return parse_u8(&cfg->global.atomic_frags.lower_mtu_fail, value, size);
	case MTU_PLATEAUS:
		return update_plateaus(&cfg->global, value, size);
	case ENABLE:
		cfg->global.enabled = true;
		return 0;
	case DISABLE:
		cfg->global.enabled = false;
		return 0;
	case ATOMIC_FRAGMENTS:
		error = parse_u8(&tmp8, value, size);
		if (error < 0)
			return error;
		cfg->global.atomic_frags.df_always_on = tmp8;
		cfg->global.atomic_frags.build_ipv6_fh = tmp8;
		cfg->global.atomic_frags.build_ipv4_id = !tmp8;
		cfg->global.atomic_frags.lower_mtu_fail = !tmp8;
		return error;
	case SYNCH_ELEMENTS_LIMIT:
		error = ensure_nat64();
		return error ? : parse_u32(&cfg->session.joold.queue_capacity, value, size);
	case SYNCH_PERIOD:
		error = ensure_nat64();
		return error ? : parse_u32(&cfg->session.joold.timer_period, value, size);
	case SYNCH_ENABLE:
		error = ensure_nat64();
		if (!error)
			cfg->session.joold.enabled = true;
		return error;
	case SYNCH_DISABLE:
		error = ensure_nat64();
		if (!error)
			cfg->session.joold.enabled = false;
		return error;
	}

	log_err("Unknown config type: %u", type);
	return -EINVAL;
}

int config_parse(struct full_config *config, void *payload, size_t payload_len)
{
	__u8 type;
	int result;

	while (payload_len > 0) {
		type = *((__u8 *)payload);
		payload += sizeof(type);
		payload_len -= sizeof(type);

		result = massive_switch(config, type, payload, payload_len);
		if (result < 0)
			return result;

		payload += result;
		payload_len -= result;
	}

	return 0;
}

static int commit_config(struct xlator *jool, struct full_config *config)
{
	int error;

	config_put(jool->global);
	error = config_init(&jool->global, false);
	if (error)
		return error;

	config_copy(&config->global, &jool->global->cfg);
	bibdb_config_set(jool->nat64.bib, &config->bib);
	sessiondb_config_set(jool->nat64.session, &config->session);

	return xlator_replace(jool);
}

static int handle_global_update(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	struct full_config config;
	int error;

	if (verify_superpriv())
		return nlcore_respond_error(info, command, -EPERM);

	log_debug("Updating 'Global' options.");

	xlator_copy_config(jool, &config);

	error = config_parse(&config, hdr + 1, hdr->length - sizeof(*hdr));
	if (error)
		return nlcore_respond_error(info, command, error);

	error = commit_config(jool, &config);
	return nlcore_respond(info, command, error);
}

int handle_global_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_global_display(jool, info);
	case OP_UPDATE:
		return handle_global_update(jool, info);
	}

	log_err("Unknown operation: %d", jool_hdr->operation);
	return nlcore_respond_error(info, command, -EINVAL);
}
