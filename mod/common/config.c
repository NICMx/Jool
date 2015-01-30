#include "nat64/mod/common/config.h"
#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include <linux/sort.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"

static struct global_config *config;

int config_init(bool is_disable)
{
	__u16 default_plateaus[] = TRAN_DEF_MTU_PLATEAUS;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;

#ifdef STATEFUL
	config->sessiondb.ttl.udp = msecs_to_jiffies(1000 * UDP_DEFAULT);
	config->sessiondb.ttl.icmp = msecs_to_jiffies(1000 * ICMP_DEFAULT);
	config->sessiondb.ttl.tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	config->sessiondb.ttl.tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);
	config->pktqueue.max_pkts = PKTQ_DEF_MAX_STORED_PKTS;
	config->filtering.drop_by_addr = FILT_DEF_ADDR_DEPENDENT_FILTERING;
	config->filtering.drop_external_tcp = FILT_DEF_DROP_EXTERNAL_CONNECTIONS;
	config->filtering.drop_icmp6_info = FILT_DEF_FILTER_ICMPV6_INFO;
	config->fragmentation.fragment_timeout = msecs_to_jiffies(1000 * FRAGMENT_MIN);
#endif

	config->translate.reset_traffic_class = TRAN_DEF_RESET_TRAFFIC_CLASS;
	config->translate.reset_tos = TRAN_DEF_RESET_TOS;
	config->translate.new_tos = TRAN_DEF_NEW_TOS;
	config->translate.df_always_on = TRAN_DEF_DF_ALWAYS_ON;
	config->translate.build_ipv4_id = TRAN_DEF_BUILD_IPV4_ID;
	config->translate.lower_mtu_fail = TRAN_DEF_LOWER_MTU_FAIL;
	config->translate.mtu_plateau_count = ARRAY_SIZE(default_plateaus);
	config->translate.is_disable = (__u8) is_disable;
	config->translate.mtu_plateaus = kmalloc(sizeof(default_plateaus), GFP_ATOMIC);
	if (!config->translate.mtu_plateaus) {
		log_err("Could not allocate memory to store the MTU plateaus.");
		kfree(config);
		return -ENOMEM;
	}
	memcpy(config->translate.mtu_plateaus, &default_plateaus, sizeof(default_plateaus));

	return 0;
}

void config_destroy(void)
{
	kfree(config->translate.mtu_plateaus);
	kfree(config);
}

int config_clone(struct global_config *clone)
{
	__u16 *buffer;
	size_t mtus_len;

	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	/* Eh. Because of the configuration mutex, we don't really need to clone the plateaus list. */
	/* TODO: dhernandez: is the comment above correct?, I saw a possible segmentation fault (well
	 * the kernel log said so :P) and when requesting the global config the mtu_plateus change
	 * without updating it, and finally my virtual machine crash, the code below apparently fix it.*/
	mtus_len = clone->translate.mtu_plateau_count * sizeof(*clone->translate.mtu_plateaus);
	buffer = kmalloc(mtus_len, GFP_KERNEL);
	if (!buffer) {
		log_debug("Could not allocate the mtu plateus.");
		return -ENOMEM;
	}

	memcpy(buffer, config->translate.mtu_plateaus, mtus_len);
	config->translate.mtu_plateaus = buffer;

	rcu_read_unlock_bh();
	return 0;
}

static bool ensure_bytes(size_t actual, size_t expected)
{
	if (actual != expected) {
		log_err("Expected a %zu-byte integer, got %zu bytes.", expected, actual);
		return false;
	}
	return true;
}

#ifdef STATEFUL

static bool assign_timeout(void *value, unsigned int min, __u64 *field)
{
	/*
	 * TODO (fine) this max is somewhat arbitrary. We do have a maximum,
	 * but I don't recall what or why it was. I do remember it's bigger than this.
	 */
	const __u32 MAX_U32 = 0xFFFFFFFFL;
	__u64 value64 = *((__u64 *) value);

	if (value64 < 1000 * min) {
		log_err("The UDP timeout must be at least %u seconds.", min);
		return false;
	}
	if (value64 > MAX_U32) {
		log_err("Expected a timeout less than %u seconds", MAX_U32 / 1000);
		return false;
	}

	*field = msecs_to_jiffies(value64);
	return true;
}

#endif

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

static int update_plateaus(struct translate_config *config, size_t size, void *value)
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

int config_set(__u8 type, size_t size, void *value)
{
	struct global_config *tmp_config;
	struct global_config *old_config;

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	switch (type) {
#ifdef STATEFUL
	case MAX_PKTS:
		if (!ensure_bytes(size, 8))
			goto fail;
		tmp_config->pktqueue.max_pkts = *((__u64 *) value);
		break;
	case UDP_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto fail;
		if (!assign_timeout(value, UDP_MIN, &tmp_config->sessiondb.ttl.udp))
			goto fail;
		break;
	case ICMP_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto fail;
		if (!assign_timeout(value, 0, &tmp_config->sessiondb.ttl.icmp))
			goto fail;
		break;
	case TCP_EST_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto fail;
		if (!assign_timeout(value, TCP_EST, &tmp_config->sessiondb.ttl.tcp_est))
			goto fail;
		break;
	case TCP_TRANS_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto fail;
		if (!assign_timeout(value, TCP_TRANS, &tmp_config->sessiondb.ttl.tcp_trans))
			goto fail;
		break;
	case FRAGMENT_TIMEOUT:
		if (!ensure_bytes(size, 8))
			goto fail;
		if (!assign_timeout(value, FRAGMENT_MIN, &tmp_config->fragmentation.fragment_timeout))
			goto fail;
		break;
	case DROP_BY_ADDR:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->filtering.drop_by_addr = *((__u8 *) value);
		break;
	case DROP_ICMP6_INFO:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->filtering.drop_icmp6_info = *((__u8 *) value);
		break;
	case DROP_EXTERNAL_TCP:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->filtering.drop_external_tcp = *((__u8 *) value);
		break;
#endif
	case RESET_TCLASS:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.reset_traffic_class = *((__u8 *) value);
		break;
	case RESET_TOS:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.reset_tos = *((__u8 *) value);
		break;
	case NEW_TOS:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.new_tos = *((__u8 *) value);
		break;
	case DF_ALWAYS_ON:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.df_always_on = *((__u8 *) value);
		break;
	case BUILD_IPV4_ID:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.build_ipv4_id = *((__u8 *) value);
		break;
	case LOWER_MTU_FAIL:
		if (!ensure_bytes(size, 1))
			goto fail;
		tmp_config->translate.lower_mtu_fail = *((__u8 *) value);
		break;
	case MTU_PLATEAUS:
		if (is_error(update_plateaus(&tmp_config->translate, size, value)))
			goto fail;
		break;
	case DISABLE:
		tmp_config->translate.is_disable = (__u8) true;
		break;
	case ENABLE:
		tmp_config->translate.is_disable = (__u8) false;
		break;
	default:
		log_err("Unknown config type: %u", type);
		goto fail;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();

	if (old_config->translate.mtu_plateaus != tmp_config->translate.mtu_plateaus)
		kfree(old_config->translate.mtu_plateaus);
	kfree(old_config);

	return 0;

fail:
	kfree(tmp_config);
	return -EINVAL;
}

#define RCU_THINGY(type, field) \
	({ \
		type result; \
		rcu_read_lock_bh(); \
		result = rcu_dereference_bh(config)->field; \
		rcu_read_unlock_bh(); \
		result; \
	})

#ifdef STATEFUL

unsigned long config_get_ttl_udp(void)
{
	return RCU_THINGY(unsigned long, sessiondb.ttl.udp);
}

unsigned long config_get_ttl_tcpest(void)
{
	return RCU_THINGY(unsigned long, sessiondb.ttl.tcp_est);
}

unsigned long config_get_ttl_tcptrans(void)
{
	return RCU_THINGY(unsigned long, sessiondb.ttl.tcp_trans);
}

unsigned long config_get_ttl_icmp(void)
{
	return RCU_THINGY(unsigned long, sessiondb.ttl.icmp);
}

unsigned int config_get_max_pkts(void)
{
	return RCU_THINGY(unsigned int, pktqueue.max_pkts);
}

bool config_get_filter_icmpv6_info(void)
{
	return RCU_THINGY(bool, filtering.drop_icmp6_info);
}

bool config_get_addr_dependent_filtering(void)
{
	return RCU_THINGY(bool, filtering.drop_by_addr);
}

bool config_get_drop_external_connections(void)
{
	return RCU_THINGY(bool, filtering.drop_external_tcp);
}

unsigned long config_get_ttl_frag(void)
{
	return RCU_THINGY(unsigned long, fragmentation.fragment_timeout);
}

#endif

bool config_get_reset_traffic_class(void)
{
	return RCU_THINGY(bool, translate.reset_traffic_class);
}

void config_get_hdr4_config(bool *reset_tos, __u8 *new_tos, bool *build_ipv4_id,
		bool *df_always_on)
{
	struct global_config *tmp;

	rcu_read_lock_bh();
	tmp = rcu_dereference_bh(config);
	*reset_tos = tmp->translate.reset_tos;
	*new_tos = tmp->translate.new_tos;
	*build_ipv4_id = tmp->translate.build_ipv4_id;
	*df_always_on = tmp->translate.df_always_on;
	rcu_read_unlock_bh();
}

bool config_get_lower_mtu_fail(void)
{
	return RCU_THINGY(bool, translate.lower_mtu_fail);
}

/**
 * You need to call rcu_read_lock_bh() before calling this function, and then rcu_read_unlock_bh()
 * when you don't need plateaus & count anymore.
 */
void config_get_mtu_plateaus(__u16 **plateaus, __u16 *count)
{
	struct global_config *tmp;

	tmp = rcu_dereference_bh(config);
	*plateaus = tmp->translate.mtu_plateaus;
	*count = tmp->translate.mtu_plateau_count;
}

bool config_get_is_disable(void)
{
	return RCU_THINGY(bool, translate.is_disable);
}
