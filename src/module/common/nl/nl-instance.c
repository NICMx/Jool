#include "nl/nl-instance.h"

#include "xlator.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"

int handle_instance_add(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attr;
	char *name;
	xlator_type type;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Adding Jool instance.");

	if (!jnla_get_instance_name(info, &name)) {
		log_err("The instance name argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	attr = info->attrs[JNLA_INSTANCE_TYPE];
	type = attr ? nla_get_u8(attr) : XLATOR_SIIT;

	return jnl_respond_error(info, xlator_add(NULL, type, name));
}

int handle_instance_rm(struct sk_buff *skb, struct genl_info *info)
{
	char *name;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Removing Jool instance.");

	if (!jnla_get_instance_name(info, &name)) {
		log_err("The instance name argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	return jnl_respond_error(info, xlator_rm(name));
}
