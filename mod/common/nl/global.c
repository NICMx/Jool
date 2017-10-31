#include "nat64/mod/common/nl/global.h"

#include <linux/sort.h>
#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/usr/global.h"


static int ensure_siit(char *field)
{
	if (!xlat_is_siit()) {
		log_err("Field '%s' is SIIT-only.", field);
		return -EINVAL;
	}

	return 0;
}

static int ensure_nat64(char *field)
{
	if (!xlat_is_nat64()) {
		log_err("Field '%s' is NAT64-only.", field);
		return -EINVAL;
	}

	return 0;
}

static bool ensure_bytes(size_t actual, size_t expected)
{
	if (actual < expected) {
		log_err("Expected a %zu-byte, got %zu bytes.",
				expected, actual);
		return false;
	}
	return true;
}


static bool ensure_bytes_ipv6_prefix(size_t actual, size_t expected)
{
	if (actual < expected && actual != 0) {
		log_err("Expected a %zu-byte or 0-byte value, got %zu bytes.",
				expected, actual);
		return false;
	}
	return true;
}

static int parse_ipv6_prefix(struct global_config_usr *config,
		struct global_value *chunk, size_t size)
{
	if (!ensure_bytes_ipv6_prefix(size - sizeof(struct global_value), sizeof(struct ipv6_prefix)))
		return -EINVAL;

	if (size - sizeof(struct global_value) != 0) {

		memcpy(&config->siit.rfc6791_v6_prefix, (struct ipv6_prefix*)(chunk+1), sizeof(struct ipv6_prefix));
		config->siit.use_rfc6791_v6 = 1;

	} else {
		config->siit.use_rfc6791_v6 = 0;
	}

	return 0;
}

static int parse_u32(__u32 *field, struct global_value *chunk, size_t size)
{
	if (!ensure_bytes(size, 4))
		return -EINVAL;
	*field = *((__u32 *)(chunk + 1));
	return 0;
}

static int parse_u16(__u16 *field, struct global_value *chunk, size_t size,
		__u16 max)
{
	__u16 value;

	if (!ensure_bytes(size, 2))
		return -EINVAL;

	value = *((__u16 *)(chunk + 1));
	if (value > max) {
		log_err("Expected a number <= %u.", max);
		return -EINVAL;
	}

	*field = value;
	return 0;
}

static int parse_u8(__u8 *field, struct global_value *chunk, size_t size)
{
	if (!ensure_bytes(size, 1))
		return -EINVAL;
	*field = *((__u8 *)(chunk + 1));
	return 0;
}

static int parse_bool(__u8 *field, struct global_value *chunk, size_t size)
{
	return parse_u8(field, chunk, size);
}

static int parse_timeout(__u32 *field, struct global_value *chunk, size_t size,
		unsigned int min)
{
	__u32 value;

	if (!ensure_bytes(size, 4))
		return -EINVAL;

	value = *((__u32 *)(chunk + 1));

	if (value < 1000 * min) {
		log_err("The timeout must be at least %u milliseconds (Got %u)",
				1000 * min, value);
		return -EINVAL;
	}

	*field = msecs_to_jiffies(value);
	return 0;
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

static int update_plateaus(struct global_config_usr *config,
		struct global_value *hdr,
		size_t max_size)
{
	__u16 *list;
	int list_length;
	unsigned int i, j;

	list_length = (hdr->len - sizeof(*hdr)) / sizeof(__u16);
	if (list_length < 1) {
		log_err("The MTU list received from userspace is empty.");
		return -EINVAL;
	}
	if (list_length > ARRAY_SIZE(config->mtu_plateaus)) {
		log_err("Too many plateau values; there's only room for %zu.",
				ARRAY_SIZE(config->mtu_plateaus));
		return -EINVAL;
	}

	list = (__u16 *)(hdr + 1);

	if (list_length * sizeof(*list) > max_size - sizeof(*hdr)) {
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

	return 0;
}

static int handle_global_display(struct xlator *jool, struct genl_info *info)
{
	struct full_config config;
	bool pools_empty;

	log_debug("Returning 'Global' options.");

	xlator_copy_config(jool, &config);

	pools_empty = pool6_is_empty(jool->pool6);
	if (xlat_is_siit())
		pools_empty &= eamt_is_empty(jool->siit.eamt);
	prepare_config_for_userspace(&config, pools_empty);

	return nlcore_respond_struct(info, &config, sizeof(config));
}

static int massive_switch(struct full_config *cfg, struct global_value *chunk,
		size_t size)
{
	int error;

	if (!ensure_bytes(size, chunk->len))
		return -EINVAL;

	switch (chunk->type) {
	case ENABLE:
		cfg->global.enabled = true;
		return 0;
	case DISABLE:
		cfg->global.enabled = false;
		return 0;
	case ENABLE_BOOL:
		return parse_bool(&cfg->global.enabled, chunk, size);
	case RESET_TCLASS:
		return parse_bool(&cfg->global.reset_traffic_class, chunk, size);
	case RESET_TOS:
		return parse_bool(&cfg->global.reset_tos, chunk, size);
	case NEW_TOS:
		return parse_u8(&cfg->global.new_tos, chunk, size);
	case MTU_PLATEAUS:
		return update_plateaus(&cfg->global, chunk, size);
	case COMPUTE_UDP_CSUM_ZERO:
		error = ensure_siit(OPTNAME_AMEND_UDP_CSUM);
		return error ? : parse_bool(&cfg->global.siit.compute_udp_csum_zero, chunk, size);
	case RANDOMIZE_RFC6791:
		error = ensure_siit(OPTNAME_RANDOMIZE_RFC6791);
		return error ? : parse_bool(&cfg->global.siit.randomize_error_addresses, chunk, size);
	case EAM_HAIRPINNING_MODE:
		error = ensure_siit(OPTNAME_EAM_HAIRPIN_MODE);
		return error ? : parse_bool(&cfg->global.siit.eam_hairpin_mode, chunk, size);
	case RFC6791V6_PREFIX:
		error = ensure_siit(OPTNAME_RFC6791V6_PREFIX);
		return error ? : parse_ipv6_prefix(&cfg->global, chunk, size);
	case DROP_BY_ADDR:
		error = ensure_nat64(OPTNAME_DROP_BY_ADDR);
		return error ? : parse_bool(&cfg->bib.drop_by_addr, chunk, size);
	case DROP_ICMP6_INFO:
		error = ensure_nat64(OPTNAME_DROP_ICMP6_INFO);
		return error ? : parse_bool(&cfg->global.nat64.drop_icmp6_info, chunk, size);
	case DROP_EXTERNAL_TCP:
		error = ensure_nat64(OPTNAME_DROP_EXTERNAL_TCP);
		return error ? : parse_bool(&cfg->bib.drop_external_tcp, chunk, size);
	case SRC_ICMP6ERRS_BETTER:
		error = ensure_nat64(OPTNAME_SRC_ICMP6E_BETTER);
		return error ? : parse_bool(&cfg->global.nat64.src_icmp6errs_better, chunk, size);
	case F_ARGS:
		error = ensure_nat64(OPTNAME_F_ARGS);
		return error ? : parse_u8(&cfg->global.nat64.f_args, chunk, size);
	case HANDLE_RST_DURING_FIN_RCV:
		error = ensure_nat64(OPTNAME_F_ARGS);
		return error ? : parse_bool(&cfg->global.nat64.handle_rst_during_fin_rcv, chunk, size);
	case UDP_TIMEOUT:
		error = ensure_nat64(OPTNAME_UDP_TIMEOUT);
		return error ? : parse_timeout(&cfg->bib.ttl.udp, chunk, size, UDP_MIN);
	case ICMP_TIMEOUT:
		error = ensure_nat64(OPTNAME_ICMP_TIMEOUT);
		return error ? : parse_timeout(&cfg->bib.ttl.icmp, chunk, size, 0);
	case TCP_EST_TIMEOUT:
		error = ensure_nat64(OPTNAME_TCPEST_TIMEOUT);
		return error ? : parse_timeout(&cfg->bib.ttl.tcp_est, chunk, size, TCP_EST);
	case TCP_TRANS_TIMEOUT:
		error = ensure_nat64(OPTNAME_TCPTRANS_TIMEOUT);
		return error ? : parse_timeout(&cfg->bib.ttl.tcp_trans, chunk, size, TCP_TRANS);
	case FRAGMENT_TIMEOUT:
		error = ensure_nat64(OPTNAME_FRAG_TIMEOUT);
		return error ? : parse_timeout(&cfg->frag.ttl, chunk, size, FRAGMENT_MIN);
	case BIB_LOGGING:
		error = ensure_nat64(OPTNAME_BIB_LOGGING);
		return error ? : parse_bool(&cfg->bib.bib_logging, chunk, size);
	case SESSION_LOGGING:
		error = ensure_nat64(OPTNAME_SESSION_LOGGING);
		return error ? : parse_bool(&cfg->bib.session_logging, chunk, size);
	case MAX_PKTS:
		error = ensure_nat64(OPTNAME_MAX_SO);
		return error ? : parse_u32(&cfg->bib.max_stored_pkts, chunk, size);
	case SS_ENABLED:
		error = ensure_nat64(OPTNAME_SS_ENABLED);
		return error ? : parse_bool(&cfg->joold.enabled, chunk, size);
	case SS_FLUSH_ASAP:
		error = ensure_nat64(OPTNAME_SS_FLUSH_ASAP);
		return error ? : parse_bool(&cfg->joold.flush_asap, chunk, size);
	case SS_FLUSH_DEADLINE:
		error = ensure_nat64(OPTNAME_SS_FLUSH_DEADLINE);
		return error ? : parse_timeout(&cfg->joold.flush_deadline, chunk, size, 0);
	case SS_CAPACITY:
		error = ensure_nat64(OPTNAME_SS_CAPACITY);
		return error ? : parse_u32(&cfg->joold.capacity, chunk, size);
	case SS_MAX_PAYLOAD:
		error = ensure_nat64(OPTNAME_SS_MAX_PAYLOAD);
		return error ? : parse_u16(&cfg->joold.max_payload, chunk, size, JOOLD_MAX_PAYLOAD);
	}

	log_err("Unknown config type: %u", chunk->type);
	return -EINVAL;
}

/**
 * On success, returns the number of bytes consumed from @payload.
 * On error, returns a negative error code.
 */
int config_parse(struct full_config *config, void *payload, size_t payload_len)
{
	struct global_value *chunk;
	size_t bytes_read = 0;
	int error;

	while (payload_len > 0) {
		if (!ensure_bytes(payload_len, sizeof(struct global_value)))
			return -EINVAL;

		chunk = payload;
		error = massive_switch(config, chunk, payload_len);
		if (error)
			return error;

		payload += chunk->len;
		payload_len -= chunk->len;
		bytes_read += chunk->len;
	}

	return bytes_read;
}

static int commit_config(struct xlator *jool, struct full_config *config)
{
	int error;

	config_put(jool->global);
	error = config_init(&jool->global);
	if (error)
		return error;

	config_copy(&config->global, &jool->global->cfg);
	bib_config_set(jool->nat64.bib, &config->bib);
	joold_config_set(jool->nat64.joold, &config->joold);
	fragdb_config_set(jool->nat64.frag, &config->frag);

	return xlator_replace(jool);
}

static int handle_global_update(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	size_t total_len;
	struct full_config config;
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Updating 'Global' options.");

	xlator_copy_config(jool, &config);

	hdr = nla_data(info->attrs[ATTR_DATA]);
	total_len = nla_len(info->attrs[ATTR_DATA]);


	error = config_parse(&config, hdr + 1, total_len - sizeof(*hdr));
	if (error < 0)
		return nlcore_respond(info, error);

	error = commit_config(jool, &config);
	return nlcore_respond(info, error);
}

int handle_global_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_global_display(jool, info);
	case OP_UPDATE:
		return handle_global_update(jool, info);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
