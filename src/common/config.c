#include "common/config.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

void init_request_hdr(struct request_hdr *hdr, enum config_mode mode,
		enum config_operation operation, bool force)
{
	hdr->magic[0] = 'j';
	hdr->magic[1] = 'o';
	hdr->magic[2] = 'o';
	hdr->magic[3] = 'l';
	hdr->castness = 'u';
	hdr->force = force;
	hdr->slop1 = 0;
	hdr->version = htonl(xlat_version());
	hdr->mode = mode;
	hdr->operation = operation;
	hdr->slop2 = 0;
}

int iname_validate(const char *iname, bool allow_null)
{
	unsigned int i;

	if (!iname) {
		if (allow_null)
			return 0;
		return -EINVAL;
	}

	for (i = 0; i < INAME_MAX_LEN; i++) {
		if (iname[i] == '\0')
			return 0;
		if (iname[i] < 32) /* "if not printable" */
			break;
	}

	return -EINVAL;
}

int fw_validate(jframework fw)
{
	return (fw == FW_NETFILTER || fw == FW_IPTABLES) ? 0 : -EINVAL;
}
