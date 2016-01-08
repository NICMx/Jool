#include "nat64/mod/common/json_parser.h"

#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateless/pool.h"

/*
 * TODO this module is missing a timer.
 * If the new configuration hasn't been committed after n milliseconds, @config
 * should be purged.
 */

/* TODO Might need a different one depending on namespace. */
static struct xlator config;
static DEFINE_MUTEX(lock);

//static int handle_global(void *payload, __u32 payload_len);
static int handle_pool6(void *payload, __u32 payload_len);
//static int handle_eamt(void *payload, __u32 payload_len);
//static int handle_addr4_pool(struct addr4_pool **pool, void *payload,
//		__u32 payload_len);
static int commit(void);

int jparser_init(void)
{
	memset(&config, 0, sizeof(config));
	return 0;
}

void jparser_destroy(void)
{
	joolns_put(&config);
}

static void reinitialize(void)
{
	joolns_put(&config);
	memset(&config, 0, sizeof(config));
}

int jparser_handle(struct nlmsghdr *nl_hdr, struct request_hdr *jool_hdr,
		__u8 *request)
{
	__u16 type =  *((__u16 *) request);
	__u32 length = jool_hdr->length - sizeof(*jool_hdr) - sizeof(type);
	int error;

	request = request + sizeof(type);

	mutex_lock(&lock);

	switch (type) {
	case SEC_INIT:
		reinitialize();
		error = 0;
		break;
//	case SEC_GLOBAL:
//		error = handle_global(request, length);
//		break;
	case SEC_POOL6:
		error = handle_pool6(request, length);
		break;
//	case SEC_EAMT:
//		error = handle_eamt(request, length);
//		break;
//	case SEC_BLACKLIST:
//		error = handle_addr4_pool(&config.siit.blacklist, request,
//				length);
//		break;
//	case SEC_POOL6791:
//		error = handle_addr4_pool(&config.siit.pool6791, request,
//				length);
//		break;
	case SEC_DONE:
		error = commit();
		break;
	default:
		log_err("Unknown configuration mode.") ;
		error = -EINVAL;
		break;
	}

	if (error)
		reinitialize();

	mutex_unlock(&lock);

	return error;
}

//static int handle_global(void *payload, __u32 payload_len)
//{
//	void *end = payload + payload_len;
//	unsigned int len;
//	int error;
//
//	if (!config.global) {
//		error = global_clone(config.global);
//		if (error)
//			return error;
//	}
//
//	while (payload < end) {
//		/* TODO and catch error and send the config in, yadda yadda. */
//		len = parse_global_arg(payload, payload_len);
//		payload += len;
//		payload_len -= len;
//	}
//
//	return 0;
//}

static int handle_pool6(void *payload, __u32 payload_len)
{
	struct ipv6_prefix *prefixes = (typeof(prefixes))payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (!config.pool6) {
		error = pool6_init(&config.pool6, NULL, 0);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		error = pool6_add(config.pool6, &prefixes[i]);
		if (error)
			return error;
	}

	return 0;
}

//static int handle_eamt(void *payload, __u32 payload_len)
//{
//	struct eamt_entry *eams = (typeof(eams))payload;
//	unsigned int eam_count = payload_len / sizeof(*eams);
//	unsigned int i;
//	int error;
//
//	if (!config.siit.eamt) {
//		error = eamt_init(config.siit.eamt);
//		if (error)
//			return error;
//	}
//
//	for (i = 0; i < eam_count; i++) {
//		error = eamt_add(config.siit.eamt, &eams[i]);
//		if (error)
//			return error;
//	}
//
//	return 0;
//}
//
//static int handle_addr4_pool(struct addr4_pool **pool, void *payload,
//		__u32 payload_len)
//{
//	struct in_addr *addrs = (typeof(addrs))payload;
//	unsigned int addr_count = payload_len / sizeof(*addrs);
//	unsigned int i;
//	int error;
//
//	if (!*pool) {
//		error = pool_init(*pool, NULL, 0);
//		if (error)
//			return error;
//	}
//
//	for (i = 0; i < addr_count; i++) {
//		error = pool_add(*pool, &addrs[i]);
//		if (error)
//			return error;
//	}
//
//	return 0;
//}

static int commit(void)
{
	struct xlator copy;
	int error;

	/*
	 * kref analysis:
	 *
	 * ns:		(2+)+1=(3+) (1 joolns, 1 @config, 0+ users, 1 @copy)
	 * old pool6:	(1+)+1=(2+) (1 joolns, 0+ users, 1 @copy)
	 * new pool6:	1+0=1 (1 @config)
	 *
	 * on success only; otherwise +0 to everything.
	 */
	error = joolns_get_current(&copy);
	if (error) {
		log_err("joolns_get() failed. Errcode %d", error);
		return error;
	}

//	if (config.global) {
//		global_put(copy.global);
//		copy.global = config.global;
//	}
	/*
	 * ns:		(3+)+0=(3+) (1 joolns, 1 @config, 0+ users, 1 @copy)
	 * old pool6:	(2+)-1=(1+) (1 joolns, 0+ users)
	 * new pool6:	1+0=1 (1 @copy)
	 *     (kref transferred from @config to @copy.)
	 */
	if (config.pool6) {
		pool6_put(copy.pool6);
		copy.pool6 = config.pool6;
		config.pool6 = NULL;
	}
//	if (config.siit.eamt) {
//		eamt_put(copy.siit.eamt);
//		copy.siit.eamt = config.siit.eamt;
//	}
//	if (config.siit.blacklist) {
//		pool_put(copy.siit.blacklist);
//		copy.siit.blacklist = config.siit.blacklist;
//	}
//	if (config.siit.pool6791) {
//		pool_put(copy.siit.pool6791);
//		copy.siit.pool6791 = config.siit.pool6791;
//	}

	/*
	 * ns:		(3+)-1=(2+) (1 joolns, 1 @config, 0+ users)
	 * old pool6:	(1+)-1=(0+) (0+ users)
	 * new pool6:	1+0=1 (1 joolns)
	 *     (kref transferred from @copy to joolns.)
	 *
	 * Unless failure.
	 */
	error = joolns_replace(&copy);
	if (error) {
		log_err("joolns_replace() failed. Errcode %d", error);
		/*
		 * ns:		(3+)-1=(2+) (1 joolns, 1 @config, 0+ users)
		 * old pool6:	(1+)-0=(1+) (1 joolns, 0+ users)
		 * new pool6:	1-1=0
		 */
		joolns_put(&copy);
		return error;
	}

	/*
	 * ns:		(2+)-1=(1+) (1 joolns, 0+ users)
	 * old pool6:	(0+)+0=(0+) (0+ users)
	 * new pool6:	1+0=1 (1 joolns)
	 */
	reinitialize();
	log_debug("Configuration replaced.");
	return 0;
}
