#include "mod/common/db/pool4/rfc6056.h"

#include <crypto/hash.h>
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"

/*
 * This is not actually an implementation of the RFC6056 algorithms anymore.
 * They are all at least somewhat problematic. Ondřej Caletka came up with a
 * clever alternative, which I'll quote later.
 *
 * First, these used to be my notes on RFC 6056's algorithms:
 *
 * Algorithms 1 and 2: Currently, the main drawback is that they would require
 * calls to `get_random_bytes()`, which is a big no-no according to issue #282.
 * But IIRC, the original reason why I chose not to use them was because they
 * break games. These algorithms are very anti-RFC6146.
 *
 * (When you see the word "gaming" or "games", assume "applications that open
 * lots of connections, and which the server probably expects them all to share
 * the same IP address.")
 *
 * Algorithm 3: I no longer like this algorithm as much as I used to, TBH. The
 * fact that `next_ephemeral` is shared between all connections means that high
 * traffic will increase the probability of games breaking.
 * However, it seems that `next_ephemeral` was removed from Jool during some
 * refactor. Whether this was on purpose or not, it is both good (because it
 * breaks games less) and bad (because it creates unnecesary collisions during
 * port selection for games). Because our pool4 has the max_iterations feature,
 * the bad might not be so troublesome after all.
 *
 * 3 was Jool's old implementation of RFC 6056, and I chose it because I found
 * it offered an interesting tradeoff between randomization (thanks to `F`) and
 * source preservation (by way of checking adjacent ports during the loop).
 *
 * Algorithm 4: I rejected this one for two reasons. The second one is probably
 * good:
 *
 * 1. I feel like computing two separate hashes is too much overhead for such a
 *    minor operation.
 *    (But I'm making assumptions here. MD5 is probably very fast actually, and
 *    if `shash_desc` can be cloned, most of the operation will be obviated away
 *    because the hashes differ in one field only.)
 * 2. Storing the `table` array sounds like a pain.
 *    (But not that much more of a pain than maintaining a global ephemeral. My
 *    main gripe is that the array size would have to be configurable, and I
 *    really don't want to bother users with more stupefyingly-specific global
 *    fields that nobody asked for.)
 *
 * Algorithm 5: This algorithm jumps a lot (particularly with a default `N` of
 * 500), so it's also 6146-unfriendly. It also has the drawback that `N` needs
 * to be configurable, so please no.
 *
 * Ondřej Caletka's algorithm:
 *
 * > What I would like to see instead would be to use F with f-args=8 only to
 * > select IPv4 address. Once it is selected, another F could be run, this
 * > time with f-args=15 (or 7) to select a port within that IPv4 address.
 * > This way it would be guaranteed that one IPv6 address is always masked
 * > behind one IPv4 address and at the same time there would be less
 * > collisions.
 *
 * For the price of two hashes, we apparently get all the benefits of the other
 * algorithms and none of the drawbacks.
 */

/*
 * TODO (issue175) RFC 6056 wants us to change this from time to time.
 *
 * For now they are only modified during module initialization and destruction,
 * which means they don't need synchronization.
 */
static unsigned char *secret_key;
static size_t secret_key_len;

/*
 * It looks like this does not require a spinlock either:
 *
 * "The shash interface (...)
 * improves over hash in two ways.  Firstly shash is reentrant,
 * meaning that the same tfm may be used by two threads simultaneously
 * as all hashing state is stored in a local descriptor."
 * (Linux commit 7b5a080b3c46f0cac71c0d0262634c6517d4ee4f)
 */
static struct crypto_shash *shash;

int rfc6056_setup(void)
{
	int error;

	/* Secret key stuff */
	secret_key_len = (PAGE_SIZE < 128) ? PAGE_SIZE : 128;
	secret_key = __wkmalloc("Secret key", secret_key_len, GFP_KERNEL);
	if (!secret_key)
		return -ENOMEM;
	get_random_bytes(secret_key, secret_key_len);

	/* TFC stuff */
	shash = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(shash)) {
		error = PTR_ERR(shash);
		log_warn_once("Failed to load transform for MD5; errcode %d",
				error);
		__wkfree("Secret key", secret_key);
		return error;
	}

	return 0;
}

void rfc6056_teardown(void)
{
	crypto_free_shash(shash);
	__wkfree("Secret key", secret_key);
}

static int init_shash_desc(struct xlation *state, struct shash_desc *desc)
{
	int error;

	desc->tfm = shash;
/* Linux commit: 877b5691f27a1aec0d9b53095a323e45c30069e2 */
#if LINUX_VERSION_LOWER_THAN(5, 2, 0, 9, 0)
	desc->flags = 0;
#endif

	error = crypto_shash_init(desc);
	if (error)
		log_debug(state, "crypto_hash_init() error: %d", error);

	return error;
}

static int hash_saddr(struct xlation *state, struct shash_desc *desc,
		const struct in6_addr *saddr)
{
	int error;

	error = crypto_shash_update(desc, (u8 *)saddr, sizeof(*saddr));
	if (error)
		log_debug(state, "crypto_hash_update() error: %d", error);

	return error;
}

static int hash_tuple(struct xlation *state, struct shash_desc *desc,
		const struct tuple *tuple6)
{
	int error;

	error = crypto_shash_update(desc, (u8 *)&tuple6->src.addr6.l3,
			sizeof(tuple6->src.addr6.l3));
	if (error)
		goto fail;
	error = crypto_shash_update(desc, (u8 *)&tuple6->src.addr6.l4,
			sizeof(tuple6->src.addr6.l4));
	if (error)
		goto fail;
	error = crypto_shash_update(desc, (u8 *)&tuple6->dst.addr6.l3,
			sizeof(tuple6->dst.addr6.l3));
	if (error)
		goto fail;
	error = crypto_shash_update(desc, (u8 *)&tuple6->dst.addr6.l4,
			sizeof(tuple6->dst.addr6.l4));
	if (error)
		goto fail;

	return 0;

fail:
	log_debug(state, "crypto_hash_update() error: %d", error);
	return error;
}

static int finish_hash(struct xlation *state, struct shash_desc *desc,
		__u32 *result)
{
	union {
		__u32 as32[4];
		__u8 as8[16];
	} md5_result;
	int error;

	error = crypto_shash_update(desc, secret_key, secret_key_len);
	if (error) {
		log_debug(state, "crypto_shash_update() error: %d", error);
		return error;
	}

	error = crypto_shash_final(desc, md5_result.as8);
	if (error) {
		log_debug(state, "crypto_shash_final() error: %d", error);
		return error;
	}

	*result = md5_result.as32[3];
	return 0;
}

/**
 * RFC 6056, Algorithm 3, tweaked for improved reliability. Returns two hashes
 * out of some of @tuple's fields. The firsh hash should decide the source
 * address of the new allocated connection, and the second hash should decide
 * the port.
 *
 * (Also, I removed ephemerals because they no longer seem to do anything with
 * the improved algorithm.)
 */
int rfc6056_f(struct xlation *state, __u32 *entry_offset, __u32 *port_offset)
{
	struct shash_desc *desc;
	int error;

	desc = __wkmalloc("shash desc", sizeof(struct shash_desc)
			+ crypto_shash_descsize(shash), GFP_ATOMIC);
	if (!desc)
		return -ENOMEM;

	if (entry_offset) {
		error = init_shash_desc(state, desc);
		if (error)
			goto end;
		error = hash_saddr(state, desc, &state->in.tuple.src.addr6.l3);
		if (error)
			goto end;
		error = finish_hash(state, desc, entry_offset);
		if (error)
			goto end;
	}

	error = init_shash_desc(state, desc);
	if (error)
		goto end;
	error = hash_tuple(state, desc, &state->in.tuple);
	if (error)
		goto end;
	error = finish_hash(state, desc, port_offset);
end:	__wkfree("shash desc", desc);
	return error;
}
