#include "mod/common/address_xlat.h"

#include "mod/common/address.h"
#include "mod/common/rfc6052.h"
#include "mod/siit/blacklist4.h"
#include "mod/siit/eam.h"

static bool must_not_translate(struct in_addr *addr, struct net *ns)
{
	return addr4_is_scope_subnet(addr->s_addr)
			|| interface_contains(ns, addr);
}

static struct addrxlat_result programming_error(void)
{
	struct addrxlat_result result;
	result.verdict = ADDRXLAT_DROP;
	result.reason = "Programming error";
	return result;
}

struct addrxlat_result addrxlat_siit64(struct xlator *instance,
		struct in6_addr *in, struct result_addrxlat64 *out)
{
	struct addrxlat_result result;
	int error;

	error = eamt_xlat_6to4(instance->siit.eamt, in, out);
	if (!error)
		goto success;
	if (unlikely(error != -ESRCH))
		return programming_error();

	if (!instance->global->cfg.pool6.set || rfc6052_6to4(&instance->global->cfg.pool6.prefix, in, out)) {
		result.verdict = ADDRXLAT_TRY_SOMETHING_ELSE;
		result.reason = "The input address lacks both pool6 prefix and EAM";
		return result;
	}

	if (blacklist4_contains(instance->siit.blacklist4, &out->addr)) {
		result.verdict = ADDRXLAT_ACCEPT;
		/* No, that's not a typo. */
		result.reason = "The resulting address (%pI4) is blacklist4ed";
		return result;
	}

success:
	if (must_not_translate(&out->addr, instance->ns)) {
		result.verdict = ADDRXLAT_ACCEPT;
		result.reason = "The resulting address is subnet-scoped or belongs to a local interface";
		return result;
	}

	result.verdict = ADDRXLAT_CONTINUE;
	result.reason = NULL;
	return result;
}

struct addrxlat_result addrxlat_siit46(struct xlator *instance,
		bool enable_eam, __be32 in, struct result_addrxlat46 *out)
{
	struct in_addr tmp = { .s_addr = in };
	struct addrxlat_result result;
	int error;

	if (must_not_translate(&tmp, instance->ns)) {
		result.verdict = ADDRXLAT_ACCEPT;
		result.reason = "The address is subnet-scoped or belongs to a local interface";
		return result;
	}

	if (enable_eam) {
		error = eamt_xlat_4to6(instance->siit.eamt, &tmp, out);
		if (!error)
			goto success;
		if (error != -ESRCH)
			return programming_error();
	}

	if (blacklist4_contains(instance->siit.blacklist4, &tmp)) {
		result.verdict = ADDRXLAT_ACCEPT;
		result.reason = "The address lacks EAMT entry and is blacklist4ed";
		return result;
	}

	if (!instance->global->cfg.pool6.set) {
		result.verdict = ADDRXLAT_TRY_SOMETHING_ELSE;
		result.reason = "The address lacks EAMT entry and there's no pool6 prefix";
		return result;
	}

	error = rfc6052_4to6(&instance->global->cfg.pool6.prefix, &tmp, out);
	if (error)
		return programming_error();

success:
	result.verdict = ADDRXLAT_CONTINUE;
	result.reason = NULL;
	return result;
}
