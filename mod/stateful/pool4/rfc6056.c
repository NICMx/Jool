#include "nat64/mod/stateful/pool4/rfc6056.h"

#include <crypto/hash.h>
#include "nat64/mod/common/wkmalloc.h"

/* TODO (issue175) RFC 6056 wants us to change this from time to time. */
static unsigned char *secret_key;
static size_t secret_key_len;
static atomic_t next_ephemeral;

static struct crypto_shash *shash;
static DEFINE_SPINLOCK(tfm_lock);

int rfc6056_init(void)
{
	unsigned int tmp;
	int error;

	/* Secret key stuff */
	secret_key_len = (PAGE_SIZE < 128) ? PAGE_SIZE : 128;
	secret_key = __wkmalloc("Secret key", secret_key_len, GFP_KERNEL);
	if (!secret_key)
		return -ENOMEM;
	get_random_bytes(secret_key, secret_key_len);

	/* Next ephemeral stuff */
	get_random_bytes(&tmp, sizeof(tmp));
	atomic_set(&next_ephemeral, tmp);

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

void rfc6056_destroy(void)
{
	crypto_free_shash(shash);
	__wkfree("Secret key", secret_key);
}

static int hash_tuple(struct shash_desc *desc, __u8 fields,
		const struct tuple *tuple6)
{
	int error;

	if (fields & F_ARGS_SRC_ADDR) {
		error = crypto_shash_update(desc, (u8 *)&tuple6->src.addr6.l3,
				sizeof(tuple6->src.addr6.l3));
		if (error)
			return error;
	}
	if (fields & F_ARGS_SRC_PORT) {
		error = crypto_shash_update(desc, (u8 *)&tuple6->src.addr6.l4,
				sizeof(tuple6->src.addr6.l4));
		if (error)
			return error;
	}
	if (fields & F_ARGS_DST_ADDR) {
		error = crypto_shash_update(desc, (u8 *)&tuple6->dst.addr6.l3,
				sizeof(tuple6->dst.addr6.l3));
		if (error)
			return error;
	}
	if (fields & F_ARGS_DST_PORT) {
		error = crypto_shash_update(desc, (u8 *)&tuple6->dst.addr6.l4,
				sizeof(tuple6->dst.addr6.l4));
		if (error)
			return error;
	}

	return crypto_shash_update(desc, secret_key, secret_key_len);
}

/**
 * RFC 6056, Algorithm 3.
 */
int rfc6056_f(const struct tuple *tuple6, __u8 fields, unsigned int *result)
{
	union {
		__be32 as32[4];
		__u8 as8[16];
	} md5_result;
	struct shash_desc *desc;
	int error = 0;

	desc = __wkmalloc("shash desc", sizeof(struct shash_desc)
			+ crypto_shash_descsize(shash), GFP_ATOMIC);
	if (!desc)
		return -ENOMEM;

	desc->tfm = shash;
	desc->flags = 0;

	/*
	 * TODO (performance) it would appear this is a good opportunity to use
	 * per-cpu variables instead of a spinlock.
	 */
	spin_lock_bh(&tfm_lock);

	error = crypto_shash_init(desc);
	if (error) {
		log_debug("crypto_hash_init() failed. Errcode: %d", error);
		goto end;
	}

	error = hash_tuple(desc, fields, tuple6);
	if (error) {
		log_debug("crypto_hash_update() failed. Errcode: %d", error);
		goto end;
	}

	error = crypto_shash_final(desc, md5_result.as8);
	if (error) {
		log_debug("crypto_hash_digest() failed. Errcode: %d", error);
		goto end;
	}

	*result = (__force __u32)md5_result.as32[3];
	/* Fall through. */

end:
	spin_unlock_bh(&tfm_lock);
	__wkfree("shash desc", desc);
	return error;
}
