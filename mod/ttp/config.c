#include "nat64/mod/ttp/config.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ipv6.h>
#include <linux/sort.h>

#include "nat64/comm/constants.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/types.h"
#include "nat64/mod/ttp/6to4.h"
#include "nat64/mod/ttp/4to6.h"

static struct translate_config *config;

int ttpconfig_init(void)
{
	__u16 default_plateaus[] = TRAN_DEF_MTU_PLATEAUS;

	config = kmalloc(sizeof(*config), GFP_ATOMIC);
	if (!config)
		return -ENOMEM;

	config->reset_traffic_class = TRAN_DEF_RESET_TRAFFIC_CLASS;
	config->reset_tos = TRAN_DEF_RESET_TOS;
	config->new_tos = TRAN_DEF_NEW_TOS;
	config->df_always_on = TRAN_DEF_DF_ALWAYS_ON;
	config->build_ipv4_id = TRAN_DEF_BUILD_IPV4_ID;
	config->lower_mtu_fail = TRAN_DEF_LOWER_MTU_FAIL;
	config->mtu_plateau_count = ARRAY_SIZE(default_plateaus);
	config->mtu_plateaus = kmalloc(sizeof(default_plateaus), GFP_ATOMIC);
	if (!config->mtu_plateaus) {
		log_err("Could not allocate memory to store the MTU plateaus.");
		kfree(config);
		return -ENOMEM;
	}
	config->min_ipv6_mtu = TRAN_DEF_MIN_IPV6_MTU;
	memcpy(config->mtu_plateaus, &default_plateaus, sizeof(default_plateaus));

	return 0;
}

void ttpconfig_destroy(void)
{
	kfree(config->mtu_plateaus);
	kfree(config);
}

int ttpconfig_clone(struct translate_config *clone)
{
	struct translate_config *config_ref;
	__u16 plateaus_len;

	rcu_read_lock_bh();
	config_ref = rcu_dereference_bh(config);

	*clone = *config_ref;

	plateaus_len = clone->mtu_plateau_count * sizeof(*clone->mtu_plateaus);
	clone->mtu_plateaus = kmalloc(plateaus_len, GFP_ATOMIC);
	if (!clone->mtu_plateaus) {
		rcu_read_unlock_bh();
		log_err("Could not allocate a clone of the config's plateaus list.");
		return -ENOMEM;
	}
	memcpy(clone->mtu_plateaus, config_ref->mtu_plateaus, plateaus_len);

	rcu_read_unlock_bh();
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

static bool validate_size(size_t expected, size_t actual)
{
	if (expected != actual) {
		log_err("Expected a %zu-byte integer, got %zu bytes.", expected, actual);
		return false;
	}
	return true;
}

static bool expect_u16(size_t actual)
{
	return validate_size(sizeof(__u16), actual);
}

static bool expect_u8(size_t actual)
{
	return validate_size(sizeof(__u8), actual);
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

int ttpconfig_update(enum translate_type type, size_t size, void *value)
{
	struct translate_config *tmp_config;
	struct translate_config *old_config;
	int error = -EINVAL;

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	switch (type) {
	case RESET_TCLASS:
		if (!expect_u8(size))
			goto fail;
		tmp_config->reset_traffic_class = *((__u8 *) value);
		break;
	case RESET_TOS:
		if (!expect_u8(size))
			goto fail;
		tmp_config->reset_tos = *((__u8 *) value);
		break;
	case NEW_TOS:
		if (!expect_u8(size))
			goto fail;
		tmp_config->new_tos = *((__u8 *) value);
		break;
	case DF_ALWAYS_ON:
		if (!expect_u8(size))
			goto fail;
		tmp_config->df_always_on = *((__u8 *) value);
		break;
	case BUILD_IPV4_ID:
		if (!expect_u8(size))
			goto fail;
		tmp_config->build_ipv4_id = *((__u8 *) value);
		break;
	case LOWER_MTU_FAIL:
		if (!expect_u8(size))
			goto fail;
		tmp_config->lower_mtu_fail = *((__u8 *) value);
		break;
	case MTU_PLATEAUS:
		error = update_plateaus(tmp_config, size, value);
		if (error)
			goto fail;
		break;
	case MIN_IPV6_MTU:
		if (!expect_u16(size))
			goto fail;
		tmp_config->min_ipv6_mtu = *((__u16 *) value);
		break;
	default:
		log_err("Unknown config type for the 'translating the packet' module: %u", type);
		goto fail;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();

	if (old_config->mtu_plateaus != tmp_config->mtu_plateaus)
		kfree(old_config->mtu_plateaus);
	kfree(old_config);

	return 0;

fail:
	kfree(tmp_config);
	return error;
}

struct translate_config *ttpconfig_get(void)
{
	return rcu_dereference_bh(config);
}
