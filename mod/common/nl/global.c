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

static bool ensure_bytes(size_t actual, size_t expected)
{
	if (actual != expected) {
		log_err("Expected a %zu-byte integer, got %zu bytes.", expected, actual);
		return false;
	}
	return true;
}

static bool assign_timeout(void *value, unsigned int min, __u64 *field)
{
	/*
	 * TODO (fine) this max is somewhat arbitrary. We do have a maximum,
	 * but I don't recall what or why it was. I do remember it's bigger than this.
	 */
	const __u32 MAX_U32 = 0xFFFFFFFFU;
	__u64 value64 = *((__u64 *) value);

	if (value64 < 1000 * min) {
		log_err("The timeout must be at least %u seconds.", min);
		return false;
	}
	if (value64 > MAX_U32) {
		log_err("Expected a timeout less than %u seconds", MAX_U32 / 1000);
		return false;
	}

	*field = msecs_to_jiffies(value64);
	return true;
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

static int update_plateaus(struct global_config *config, size_t size, void *value)
{
	__u16 *list = value;
	unsigned int count = size / 2;
	unsigned int i, j;

	if (count == 0) {
		log_err("The MTU list received from userspace is empty.");
		return -EINVAL;
	}
	if (size % 2 == 1) {
		log_err("Expected an array of 16-bit integers; got an uneven number of bytes.");
		return -EINVAL;
	}

	/* Sort descending. */
	sort(list, count, sizeof(*list), be16_compare, be16_swap);

	/* Remove zeroes and duplicates. */
	for (i = 0, j = 1; j < count; j++) {
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

	count = i + 1;
	size = count * sizeof(*list);

	/* Update. */
	config->mtu_plateaus = kmalloc(size, GFP_KERNEL);
	if (!config->mtu_plateaus) {
		log_err("Could not allocate the kernel's MTU plateaus list.");
		return -ENOMEM;
	}
	memcpy(config->mtu_plateaus, list, size);
	config->mtu_plateau_count = count;

	return 0;
}

static int handle_global_update(enum global_type type, size_t size, unsigned char *value)
{
	struct global_config *config;
	int synch_elements_limit;
	unsigned long synch_period;

	bool joold_needs_update = false;
	int error;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;
	config->mtu_plateaus = NULL;

	error = config_clone(config);
	if (error)
		goto fail;

	switch (type) {
	case MAX_PKTS:
		if (!ensure_bytes(size, 8))
			goto einval;
		config->nat64.max_stored_pkts = *((__u64 *) value);
		break;
	case SRC_ICMP6ERRS_BETTER:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.src_icmp6errs_better = *((__u8 *) value);
		break;
	case BIB_LOGGING:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.bib_logging = *((__u8 *) value);
		break;
	case SESSION_LOGGING:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.session_logging = *((__u8 *) value);
		break;

	case UDP_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto einval;
		if (!assign_timeout(value, UDP_MIN, &config->nat64.ttl.udp))
			goto einval;
		break;
	case ICMP_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto einval;
		if (!assign_timeout(value, 0, &config->nat64.ttl.icmp))
			goto einval;
		break;
	case TCP_EST_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto einval;
		if (!assign_timeout(value, TCP_EST, &config->nat64.ttl.tcp_est))
			goto einval;
		break;
	case TCP_TRANS_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto einval;
		if (!assign_timeout(value, TCP_TRANS, &config->nat64.ttl.tcp_trans))
			goto einval;
		break;
	case FRAGMENT_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto einval;
		if (!assign_timeout(value, FRAGMENT_MIN, &config->nat64.ttl.frag))
			goto einval;
		break;
	case DROP_BY_ADDR:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.drop_by_addr = *((__u8 *) value);
		break;
	case DROP_ICMP6_INFO:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.drop_icmp6_info = *((__u8 *) value);
		break;
	case DROP_EXTERNAL_TCP:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->nat64.drop_external_tcp = *((__u8 *) value);
		break;

	case COMPUTE_UDP_CSUM_ZERO:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->siit.compute_udp_csum_zero = *((__u8 *) value);
		break;
	case EAM_HAIRPINNING_MODE:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->siit.eam_hairpin_mode = *((__u8 *) value);
		break;
	case RANDOMIZE_RFC6791:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->siit.randomize_error_addresses = *((__u8 *) value);
		break;

	case RESET_TCLASS:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->reset_traffic_class = *((__u8 *) value);
		break;
	case RESET_TOS:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->reset_tos = *((__u8 *) value);
		break;
	case NEW_TOS:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->new_tos = *((__u8 *) value);
		break;
	case DF_ALWAYS_ON:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->atomic_frags.df_always_on = *((__u8 *) value);
		break;
	case BUILD_IPV6_FH:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->atomic_frags.build_ipv6_fh = *((__u8 *) value);
		break;
	case BUILD_IPV4_ID:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->atomic_frags.build_ipv4_id = *((__u8 *) value);
		break;
	case LOWER_MTU_FAIL:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->atomic_frags.lower_mtu_fail = *((__u8 *) value);
		break;
	case MTU_PLATEAUS:
		if (is_error(update_plateaus(config, size, value)))
			goto einval;
		break;
	case DISABLE:
		config->is_disable = (__u8) true;
		break;
	case ENABLE:
		config->is_disable = (__u8) false;
		break;
	case ATOMIC_FRAGMENTS:
		if (!ensure_bytes(size, 1))
			goto einval;
		config->atomic_frags.df_always_on = *((__u8 *) value);
		config->atomic_frags.build_ipv6_fh = *((__u8 *) value);
		config->atomic_frags.build_ipv4_id = !(*((__u8 *) value));
		config->atomic_frags.lower_mtu_fail = !(*((__u8 *) value));
		break;

	case SYNCH_ELEMENTS_LIMIT:

		synch_elements_limit = *((__u8*)value);

		if (synch_elements_limit <  DEFAULT_SYNCH_ELEMENTS_LIMIT) {
			log_err("The limit of synchronization elements can't be lower than %d", DEFAULT_SYNCH_ELEMENTS_LIMIT);
			goto einval;
		}

		joold_needs_update = true;
		config->synch_elements_limit = synch_elements_limit;

		break;
	case SYNCH_PERIOD:

		synch_period = *((__u64*)value);

		if (synch_period < DEFAULT_SYNCH_ELEMENTS_PERIOD) {
			log_err("The period of synchronization can't be less than %d", DEFAULT_SYNCH_ELEMENTS_PERIOD);
			goto einval;
		}

		joold_needs_update = true;
		config->synch_elements_period = synch_period;

		break;

	case SYNCH_THRESHOLD:

		config->synch_elements_threshold = *((__u64*)value);

		break;

	case SYNCH_ENABLE:

		joold_start();

		config->synch_enabled = 1;
		joold_needs_update = true;

		return error;
		break;

	case SYNCH_DISABLE:

		joold_stop();

		config->synch_enabled = 0;
		joold_needs_update = true;

		break;

	default:
		log_err("Unknown config type: %u", type);
		goto einval;
	}

	config_replace(config);

	if (joold_needs_update)
		joold_update_config();

	return 0;

einval:
	error = -EINVAL;
	/* Fall through. */

fail:
	kfree(config->mtu_plateaus);
	kfree(config);
	return error;
}



static int handle_global_display(struct genl_info *info)
{
	int error = 0;
	struct nl_core_buffer *response_buffer;
	struct global_config response = { .mtu_plateaus = NULL };
	unsigned char *buffer;
	bool disabled;
	size_t buffer_len;

	error = config_clone(&response);
		if (error)
			return error;

		disabled = xlat_is_nat64()
				? pool6_is_empty()
				: (pool6_is_empty() && eamt_is_empty());
		error = serialize_global_config(&response, disabled, &buffer, &buffer_len);
		if (error)
			return nl_core_respond_error(info, command, error);

		error = nl_core_new_core_buffer(&response_buffer, buffer_len);

		if (error)
			return nl_core_respond_error(info, command, error);

		error = nl_core_write_to_buffer(response_buffer, (__u8*)buffer,buffer_len);
		error = (error >= 0) ? nl_core_send_buffer(info, command, response_buffer) :  nl_core_respond_error(info, command, error);

		nl_core_free_buffer(response_buffer);

		return error;
}


int handle_global_config(struct genl_info *info)
{
	struct request_hdr *jool_hdr = info->userhdr;
	union request_global *request = (union request_global *)(jool_hdr + 1);

	unsigned char *buffer;
	size_t buffer_len;

	int error;


	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Returning 'Global' options.");

		error = handle_global_display(info);

		if (error)
			goto end;

		return 0;
	case OP_UPDATE:
		if (verify_superpriv()) {
			error = -EPERM;
			goto end;
		}

		log_debug("Updating 'Global' options.");

		buffer = (unsigned char *) (request + 1);
		buffer_len = jool_hdr->length - sizeof(*jool_hdr) - sizeof(*request);

		error = handle_global_update(request->update.type, buffer_len, buffer);

		if (error)
			goto end;

		return 0;

		break;

	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
	}

end:
	return nl_core_respond_error(info, command, error);
}
