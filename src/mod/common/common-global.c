#include "common/common-global.h"

#include <linux/sort.h>
#include "mod/common/address.h"
#include "usr/common/str_utils.h"

static int validate_uint(struct global_field *field, unsigned int value)
{
	if (value < field->min) {
		log_err("%u is too small for the range of %s [%llu-%llu].",
				value, field->name, field->min, field->max);
		return -EINVAL;
	}
	if (value > field->max) {
		log_err("%u is too big for the range of %s [%llu-%llu].",
				value, field->name, field->min, field->max);
		return -EINVAL;
	}

	return 0;
}

int validate_u8(struct global_field *field, void *value, bool force)
{
	__u8 value8 = *((__u8 *)value);
	return validate_uint(field, value8);
}

int validate_u32(struct global_field *field, void *value, bool force)
{
	__u32 value32 = *((__u32 *)value);
	return validate_uint(field, value32);
}

static int validate_pool6_len(__u8 len)
{
	if (len == 32 || len == 40 || len == 48)
		return 0;
	if (len == 56 || len == 64 || len == 96)
		return 0;

	log_err("%u is not a valid prefix length (32, 40, 48, 56, 64, 96).", len);
	return -EINVAL;
}

static int validate_ubit(struct ipv6_prefix *prefix, config_bool force)
{
	if (force || !prefix->addr.s6_addr[8])
		return 0;

	log_err("The u-bit is nonzero; see https://github.com/NICMx/Jool/issues/174.\n"
			"Will cancel the operation. Use --force to override this.");
	return -EINVAL;
}

int validate_pool6(struct global_field *field, void *value, bool force)
{
	struct config_prefix6 *prefix = value;
	int error;

	if (!prefix->set)
		return 0;

	error = validate_pool6_len(prefix->prefix.len);
	if (error)
		return error;

	error = prefix6_validate(&prefix->prefix);
	if (error)
		return error;

	return validate_ubit(&prefix->prefix, force);
}

static int u16_compare(const void *a, const void *b)
{
	return *(__u16 *)b - *(__u16 *)a;
}

static void u16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

int validate_plateaus(struct global_field *field, void *value, bool force)
{
	struct mtu_plateaus *plateaus = value;
	__u16 *values = plateaus->values;
	unsigned int i, j;

	/* Sort descending. */
	sort(values, plateaus->count, sizeof(*values), u16_compare, u16_swap);

	/* Remove zeroes and duplicates. */
	for (i = 0, j = 1; j < plateaus->count; j++) {
		if (values[j] == 0)
			break;
		if (values[i] != values[j]) {
			i++;
			values[i] = values[j];
		}
	}

	if (values[0] == 0) {
		log_err("The MTU list contains nothing but zeroes.");
		return -EINVAL;
	}

	/* Update. */
	plateaus->count = i + 1;
	return 0;
}

int validate_prefix6(struct global_field *field, void *value, bool force)
{
	struct config_prefix6 *prefix = value;
	return prefix->set ? prefix6_validate(&prefix->prefix) : 0;
}

int validate_prefix4(struct global_field *field, void *value, bool force)
{
	struct config_prefix4 *prefix = value;
	return prefix->set ? prefix4_validate(&prefix->prefix) : 0;
}

int validate_prefix6791v4(struct global_field *field, void *value, bool force)
{
	struct config_prefix4 *prefix = value;
	int error;

	if (!prefix->set)
		return 0;

	error = prefix4_validate(&prefix->prefix);
	if (error)
		return error;

	return prefix4_validate_scope(&prefix->prefix, force);
}

int validate_hairpin_mode(struct global_field *field, void *_value, bool force)
{
	__u8 value = *((__u8 *)_value);

	if (value == EHM_OFF || value == EHM_SIMPLE || value == EHM_INTRINSIC)
		return 0;

	log_err("Unknown hairpinning mode: %u", value);
	return -EINVAL;
}
