#include "nat64/common/config.h"
#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <errno.h>
#endif

void init_request_hdr(struct request_hdr *hdr, enum config_mode mode,
		enum config_operation operation)
{
	hdr->magic[0] = 'j';
	hdr->magic[1] = 'o';
	hdr->magic[2] = 'o';
	hdr->magic[3] = 'l';
	hdr->type = xlat_is_nat64() ? 'n' : 's'; /* 'n'at64 or 's'iit. */
	hdr->castness = 'u';
	hdr->slop = 0;
	hdr->version = htonl(xlat_version());
	hdr->mode = htons(mode);
	hdr->operation = htons(operation);
}

static int validate_magic(struct request_hdr *hdr, char *sender)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	/* Well, the sender does not understand the protocol. */
	log_err("The %s sent a message that lacks the Jool magic text.",
			sender);
	return -EINVAL;
}

static int validate_stateness(struct request_hdr *hdr,
		char *sender, char *receiver)
{
	switch (hdr->type) {
	case 's':
		if (xlat_is_siit())
			return 0;

		log_err("The %s is SIIT but the %s is NAT64. Please match us correctly.",
				sender, receiver);
		return -EINVAL;
	case 'n':
		if (xlat_is_nat64())
			return 0;

		log_err("The %s is NAT64 but the %s is SIIT. Please match us correctly.",
				sender, receiver);
		return -EINVAL;
	}

	log_err("The %s sent a packet with an unknown stateness: '%c'",
			sender, hdr->type);
	return -EINVAL;
}

static int validate_version(struct request_hdr *hdr,
		char *sender, char *receiver)
{
	__u32 hdr_version = ntohl(hdr->version);

	if (xlat_version() == hdr_version)
		return 0;

	log_err("Version mismatch. The %s's version is %u.%u.%u.%u,\n"
			"but the %s is %u.%u.%u.%u.\n"
			"Please update the %s.",
			sender,
			hdr_version >> 24, (hdr_version >> 16) & 0xFFU,
			(hdr_version >> 8) & 0xFFU, hdr_version & 0xFFU,
			receiver,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr_version) ? sender : receiver);
	return -EINVAL;
}

int validate_request(void *data, size_t data_len, char *sender, char *receiver,
		bool *peer_is_jool)
{
	int error;

	if (peer_is_jool)
		*peer_is_jool = false;

	if (data_len < sizeof(struct request_hdr)) {
		log_err("Message from the %s is smaller than Jool's header.",
				sender);
		return -EINVAL;
	}

	error = validate_magic(data, sender);
	if (error)
		return error;

	if (peer_is_jool)
		*peer_is_jool = true;

	error = validate_stateness(data, sender, receiver);
	if (error)
		return error;

	return validate_version(data, sender, receiver);
}
