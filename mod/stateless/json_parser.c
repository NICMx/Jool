#include "nat64/mod/common/json_parser.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateless/pool.h"

/*
 * TODO this module is missing a timer.
 * If the new configuration hasn't been committed after n milliseconds, config
 * should be purged.
 */

static DEFINE_MUTEX(lock);

static int handle_global(struct xlator *jool, void *payload, __u32 payload_len);
static int handle_pool6(struct xlator *jool, void *payload, __u32 payload_len);
static int handle_eamt(struct xlator *jool, void *payload, __u32 payload_len);
static int handle_blacklist(struct xlator *jool, void *payload,
		__u32 payload_len);
static int handle_pool6791(struct xlator *jool, void *payload,
		__u32 payload_len);
static int commit(struct xlator *usr);

int jparser_init(struct xlator **jool)
{
	struct xlator *result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;
	memset(result, 0, sizeof(*result));

	*jool = result;
	return 0;
}

void jparser_destroy(struct xlator *jool)
{
	joolns_put(jool);
}

static void rollback(struct xlator *jool)
{
	joolns_put(jool);
	memset(jool, 0, sizeof(*jool));
}

int jparser_handle(struct xlator *jool, struct request_hdr *jool_hdr,
		__u8 *request)
{
	__u16 type =  *((__u16 *)request);
	__u32 length = jool_hdr->length - sizeof(*jool_hdr) - sizeof(type);
	int error;

	request = request + sizeof(type);

	mutex_lock(&lock);

	switch (type) {
	case SEC_INIT:
		rollback(jool);
		error = 0;
		break;
	case SEC_GLOBAL:
		error = handle_global(jool, request, length);
		break;
	case SEC_POOL6:
		error = handle_pool6(jool, request, length);
		break;
	case SEC_EAMT:
		error = handle_eamt(jool, request, length);
		break;
	case SEC_BLACKLIST:
		error = handle_blacklist(jool, request, length);
		break;
	case SEC_POOL6791:
		error = handle_pool6791(jool, request, length);
		break;
	case SEC_COMMIT:
		error = commit(jool);
		break;
	default:
		log_err("Unknown configuration mode.") ;
		error = -EINVAL;
		break;
	}

	if (error)
		rollback(jool);

	mutex_unlock(&lock);

	return error;
}

/* TODO document the name of usr above. */
static int handle_global(struct xlator *usr, void *payload, __u32 payload_len)
{
	struct xlator jool;
	void *end = payload + payload_len;
//	unsigned int len = 0;
	int error;

	if (!usr->global) {
		error = joolns_get(usr->ns, &jool);
		if (error)
			return error;

		error = config_clone(jool.global, &usr->global);
		joolns_put(&jool);
		if (error)
			return error;
	}

	while (payload < end) {
		/* TODO implement. */
		/* TODO and catch error and send the config in, yadda yadda. */
//		len = parse_global_arg(payload, payload_len);
//		payload += len;
//		payload_len -= len;
	}

	return 0;
}

static int handle_pool6(struct xlator *jool, void *payload, __u32 payload_len)
{
	struct ipv6_prefix *prefixes = payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (!jool->pool6) {
		error = pool6_init(&jool->pool6, NULL, 0);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		error = pool6_add(jool->pool6, &prefixes[i]);
		if (error)
			return error;
	}

	return 0;
}

static int handle_eamt(struct xlator *jool, void *payload, __u32 payload_len)
{
	struct eamt_entry *eams = payload;
	unsigned int eam_count = payload_len / sizeof(*eams);
	unsigned int i;
	int error;

	if (!jool->siit.eamt) {
		error = eamt_init(&jool->siit.eamt);
		if (error)
			return error;
	}

	for (i = 0; i < eam_count; i++) {
		/* TODO force should be variable. */
		error = eamt_add(jool->siit.eamt, &eams[i].prefix6,
				&eams->prefix4, true);
		if (error)
			return error;
	}

	return 0;
}

static int handle_addr4_pool(struct addr4_pool **pool, void *payload,
		__u32 payload_len)
{
	struct ipv4_prefix *prefixes = payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (!(*pool)) {
		error = pool_init(pool, NULL, 0);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		error = pool_add(*pool, &prefixes[i]);
		if (error)
			return error;
	}

	return 0;
}

static int handle_blacklist(struct xlator *jool, void *payload,
		__u32 payload_len)
{
	return handle_addr4_pool(&jool->siit.blacklist, payload, payload_len);
}

static int handle_pool6791(struct xlator *jool, void *payload,
		__u32 payload_len)
{
	return handle_addr4_pool(&jool->siit.pool6791, payload, payload_len);
}

static int commit(struct xlator *usr)
{
	/*
	 * @copy is a clone of the current running configuration.
	 * @usr is the configuration we just finished received from userspace.
	 */
	struct xlator copy;
	int error;

	/*
	 * kref analysis:
	 *
	 * ns:		(2+)+1=(3+) (1 joolns, 1 @usr, 0+ joolns users, 1 @copy)
	 * old pool6:	(1+)+1=(2+) (1 joolns, 0+ joolns users, 1 @copy)
	 * new pool6:	1+0=1 (1 @usr)
	 *
	 * on success only; otherwise +0 to everything.
	 */
	error = joolns_get_current(&copy);
	if (error) {
		log_err("joolns_get() failed. Errcode %d", error);
		return error;
	}

	if (usr->global) {
		config_put(copy.global);
		copy.global = usr->global;
		usr->global = NULL;
	}
	/*
	 * ns:		(3+)+0=(3+) (1 joolns, 1 @usr, 0+ joolns users, 1 @copy)
	 * old pool6:	(2+)-1=(1+) (1 joolns, 0+ joolns users)
	 * new pool6:	1+0=1 (1 @copy)
	 *     (kref transferred from @usr to @copy.)
	 */
	if (usr->pool6) {
		pool6_put(copy.pool6);
		copy.pool6 = usr->pool6;
		usr->pool6 = NULL;
	}
	if (usr->siit.eamt) {
		eamt_put(copy.siit.eamt);
		copy.siit.eamt = usr->siit.eamt;
		usr->siit.eamt = NULL;
	}
	if (usr->siit.blacklist) {
		pool_put(copy.siit.blacklist);
		copy.siit.blacklist = usr->siit.blacklist;
		usr->siit.blacklist = NULL;
	}
	if (usr->siit.pool6791) {
		pool_put(copy.siit.pool6791);
		copy.siit.pool6791 = usr->siit.pool6791;
		usr->siit.pool6791 = NULL;
	}

	/*
	 * ns:		(3+)-1=(2+) (1 joolns, 1 @usr, 0+ joolns users)
	 * old pool6:	(1+)-1=(0+) (0+ joolns users)
	 * new pool6:	1+0=1 (1 joolns)
	 *     (kref transferred from @copy to joolns.)
	 *
	 * Unless failure.
	 */
	error = joolns_replace(&copy);
	if (error) {
		log_err("joolns_replace() failed. Errcode %d", error);
		/*
		 * ns:		(3+)-1=(2+) (1 joolns, 1 @usr, 0+ joolns users)
		 * old pool6:	(1+)-0=(1+) (1 joolns, 0+ joolns users)
		 * new pool6:	1-1=0
		 */
		joolns_put(&copy);
		return error;
	}

	/*
	 * ns:		(2+)-1=(1+) (1 joolns, 0+ joolns users)
	 * old pool6:	(0+)+0=(0+) (0+ joolns users)
	 * new pool6:	1+0=1 (1 joolns)
	 *
	 * TODO does this really make sense?
	 * The next time usr is used, it will use the same namespace.
	 */
	rollback(usr);
	log_debug("Configuration replaced.");
	return 0;
}
