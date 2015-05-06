#include "nat64/mod/stateful/bib/port_allocator.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/bib/host6_node.h"

#include <linux/crypto.h>
#include <crypto/md5.h>

/* TODO spinlocks */

struct addr4_ephemeral {
	struct in_addr addr;
	unsigned int min;
	unsigned int max;
	atomic_t next;
};

struct crypto_tfm *tfm;
unsigned char *secret_key;
size_t secret_key_len;

int palloc_init(void)
{
	int key_len;

	key_len = PAGE_SIZE - 2 * sizeof(struct in6_addr) - sizeof(__u16);
	if (key_len < 1) {
		log_err("PAGE_SIZE is too small");
		return -EINVAL;
	}

	secret_key_len = key_len;
	secret_key = kmalloc(secret_key_len, GFP_KERNEL);
	if (!secret_key)
		return -EINVAL;
	get_random_bytes(secret_key, key_len);

	return 0;
}

void palloc_destroy(void)
{
	kfree(secret_key);
}

union md5_result {
	__be32 as32[4];
	__u8 as8[16];
};

static int md5(unsigned char *input, size_t input_len, union md5_result *output)
{
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
	int error;

	/*
	 * TODO this doesn't need to be init'd and destroyed all the time.
	 * (though that requires another spinlock, which sucks.)
	 */
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC); /* TODO async? */
	if (IS_ERR(tfm)) {
		error = PTR_ERR(tfm);
		log_warn_once("Failed to load transform for MD5; errcode %d",
				error);
		return error;
	}

	desc.tfm = tfm;
	desc.flags = 0;
	/*
	 * TODO supposedly, something's supposed to be one page long at most.
	 * Review.
	 */
	sg_init_one(&sg, input, input_len);
	error = crypto_hash_init(&desc);
	if (error)
		goto end;

	error = crypto_hash_update(&desc, &sg, input_len);
	if (error)
		goto end;
	error = crypto_hash_final(&desc, output->as8);
	/* Fall through. */

end:
	crypto_free_hash(tfm);
	return error;
}

static int f(const struct in6_addr *local_ip, const struct in6_addr *remote_ip,
		__u16 remote_port, unsigned int *result)
{
	unsigned char *buffer;
	size_t buffer_len;
	unsigned int offset;
	union md5_result hash;
	int error;

	buffer_len = sizeof(*local_ip) + sizeof(*remote_ip) +
			sizeof(remote_port) + secret_key_len;
	buffer = kmalloc(buffer_len, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;
	offset = 0;
	memcpy(&buffer[offset], local_ip, sizeof(*local_ip));
	offset += sizeof(*local_ip);
	memcpy(&buffer[offset], remote_ip, sizeof(*remote_ip));
	offset += sizeof(*remote_ip);
	memcpy(&buffer[offset], &remote_port, sizeof(remote_port));
	offset += sizeof(remote_port);
	memcpy(&buffer[offset], secret_key, secret_key_len);

	error = md5(buffer, buffer_len, &hash);
	if (!error)
		*result = hash.as32[3];

	kfree(buffer);
	return error;
}

static bool check_suitable_port(struct in_addr *addr, unsigned int port,
		l4_protocol proto)
{
	struct ipv4_transport_addr tmp = { .l3 = *addr, .l4 = port };
	struct bib_entry *bib;
	int error;

	/* TODO check parity? */
	/* TODO allow bib to be NULL so we don't have to return? */
	error = bibdb_get4(&tmp, proto, &bib);
	bibdb_return(bib);

	return !error;
}

/**
 * Algorithm 3.
 */
static int rfc6056(const struct tuple *tuple6,
		struct addr4_ephemeral *ephemeral, __u16 *result)
{
	unsigned int num_ephemeral;
	unsigned int offset;
	unsigned int count;
	unsigned int port;
	int error;

	num_ephemeral = ephemeral->max - ephemeral->min + 1;
	error = f(&tuple6->src.addr6.l3, &tuple6->dst.addr6.l3,
			tuple6->dst.addr6.l4, &offset);
	if (error)
		return error;
	count = num_ephemeral;

	do {
		port = ephemeral->min +
				(atomic_inc_return(&ephemeral->next) + offset) %
				num_ephemeral;

		if (check_suitable_port(&ephemeral->addr, port, tuple6->l4_proto)) {
			*result = port;
			return 0;
		}

		count--;

	} while (count > 0);

	return -ESRCH;
}

static int choose_port(struct ipv4_transport_addr *addr, void *arg)
{

}

int palloc_allocate(const struct tuple *tuple6, __u32 mark,
		struct ipv4_transport_addr *result)
{
	struct in_addr addr4;
	struct in_addr *offset;
	int error;

	error = bibdb_get_addr4(&tuple6->src.addr6.l3, &addr4);
	if (error) {
		if (error != -ESRCH)
			return error;
		offset = NULL;
	} else {
		offset = &addr4;
	}

	error = pool4_foreach(mark, choose_port, NULL, offset);
	return (error >= 0) ? 0 : error;

//	if (client->session_count > config_session_limit())
//		return -E2BIG;
//
//	result->l3 = addr4->addr;
//	return rfc6056(tuple6, addr4, &result->l4);
}
