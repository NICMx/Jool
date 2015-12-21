#include "nat64/mod/common/alg/ftp/sm.h"
#include <linux/ip.h>
#include <net/ipv6.h>
#include "nat64/mod/common/config.h"

enum ftp_line_type {
	FTPLT_COPY,
	FTPLT_MANGLE,
};

union ftp_line {
	enum ftp_line_type type;

	struct {
		unsigned int start;
		unsigned int end;
	} copy;
	struct {
		const char const *msg;
		/** Do we have to kfree @msg when we're done? */
		bool msg_in_heap;
	} mangle;

	struct list_head hook;
};

static int copy_line(unsigned int start, unsigned int end,
		struct ftp_translated *output)
{
	union ftp_line *line;

	line = kmalloc(sizeof(*line), GFP_ATOMIC);
	if (!line)
		return -ENOMEM;
	line->type = FTPLT_COPY;
	line->copy.start = start;
	line->copy.end = end;

	output->payload_len += end - start;
	list_add_tail(&line->hook, &output->lines);

	return 0;
}

static int add_line(struct ftp_translated *output, char *msg, bool msg_in_heap)
{
	union ftp_line *line;

	line = kmalloc(sizeof(*line), GFP_ATOMIC);
	if (!line) {
		if (msg_in_heap)
			kfree(msg);
		return -ENOMEM;
	}
	line->type = FTPLT_MANGLE;
	line->mangle.msg = msg;
	line->mangle.msg_in_heap = msg_in_heap;

	output->payload_changed = true;
	output->payload_len += strlen(msg);
	list_add_tail(&line->hook, &output->lines);

	return 0;
}

/**
 * @msg MUST end with an FTP newline.
 */
static int respond_to_client(char *msg)
{
	return 0; /* TODO */
}

int ftpsm_client_sent_auth(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	state->client_sent_auth = true;
	return copy_line(input->start, input->end, output);
}

int ftpsm_client_sent_epsv(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	if (config_ftp_requires_algs_request() && !state->algs_requested)
		return copy_line(input->start, input->end, output);

	switch (input->epsv.type) {
	case EPSV_EMPTY:
		break;
	case EPSV_CONTAINS_PROTO:
		if (input->epsv.proto != 2)
			return respond_to_client("522 Network protocol not supported\r\n");
		break;
	case EPSV_ALL:
		return respond_to_client("504 Command not implemented for that parameter\r\n");
	}

	state->client_sent_epsv = true;
	return add_line(output, "PASV\r\n", false);
}

static bool eprt_addr_matches_src(struct ftp_client_msg *input)
{
	struct in6_addr *eprt_addr;
	struct in6_addr *src_addr;

	if (input->eprt.proto != 2)
		return false;

	eprt_addr = &input->eprt.addr6.l3;
	src_addr = &ipv6_hdr(input->skb)->saddr;
	return ipv6_addr_equal(eprt_addr, src_addr);
}

static int create_port(struct ipv4_transport_addr *taddr, char **result)
{
	char *template = "PORT %u,%u,%u,%u,%u,%u\r\n";
	char *msg;
	__u32 addr;
	int error;

	msg = kmalloc(sizeof(template) - 6 * strlen("%u") + 6 * strlen("255"),
			GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	addr = be32_to_cpu(taddr->l3.s_addr);
	error = sprintf(msg, template,
			(addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
			(addr >> 8) & 0xFF, addr & 0xFF,
			(taddr->l4 >> 8) & 0xFF, taddr->l4 & 0xFF);
	if (error) {
		log_debug("sprintf() returned errcode %d.", error);
		kfree(msg);
		return error;
	}

	*result = msg;
	return 0;
}

static int xlat_eprt_into_port_siit(struct ftp_client_msg *input,
		struct ftp_translated *output)
{
	char *msg;
	int error;

	error = create_port(&input->eprt.addr4, &msg);
	if (error)
		return error;

	return add_line(output, msg, true);
}

int pool4_allocate_same_address(struct in_addr *, struct ipv4_transport_addr *);
int bibdb_add(struct ipv6_transport_addr *, struct ipv4_transport_addr *);

static int xlat_eprt_into_port_nat64(struct ftp_client_msg *input,
		struct ftp_translated *output)
{
	struct in_addr tmp;
	struct ipv4_transport_addr taddr;
	char *msg;
	int error;

	tmp.s_addr = ip_hdr(output->skb)->saddr;
	error = pool4_allocate_same_address(&tmp, &taddr);
	if (error)
		return error;

	error = bibdb_add(&input->eprt.addr6, &taddr);
	if (error)
		return error;

	error = create_port(&taddr, &msg);
	if (error)
		return error; /* TODO Maybe revert pool4 allocation and BIB? */

	return add_line(output, msg, true);
}

int ftpsm_client_sent_eprt(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	if (config_ftp_requires_algs_request() && !state->algs_requested)
		return copy_line(input->start, input->end, output);

	if (!eprt_addr_matches_src(input))
		return copy_line(input->start, input->end, output);

	return xlat_is_siit()
			? xlat_eprt_into_port_siit(input, output)
			: xlat_eprt_into_port_nat64(input, output);
}

int ftpsm_client_sent_algs(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	switch (input->algs.arg) {
	case ALGS_STATUS64:
		break;
	case ALGS_ENABLE64:
		state->algs_requested = true;
		break;
	case ALGS_DISABLE64:
		state->algs_requested = false;
		break;
	}

	/*
	 * If respond_to_client() returns an error, we should perhaps revert
	 * the state. An error can pop up even after this function however,
	 * and there is no way to revert state then.
	 * Also, the response might fail to arrive to the client in extreme
	 * scenarios even if respond_to_client() returns 0...
	 * So the error code is quite useless. Whatever; just behave simple and
	 * consistently.
	 */
	if (state->algs_requested) {
		respond_to_client("216 EPSVEPRT FTP ALG enabled.\r\n");
	} else {
		respond_to_client("216 NONE FTP ALG disabled.\r\n");
	}

	output->payload_changed = true; /* Because we're removing the ALGS. */
	return 0; /* copy_line() not wanted here! */
}

int ftpsm_server_denied(struct ftp_server_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	state->client_sent_auth = false;
	state->client_sent_epsv = false;
	return copy_line(input->start, input->end, output);
}

int ftpsm_server_sent_227(struct ftp_server_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state)
{
	char *template = "229 Entering Extended Passive Mode (|||%u|)\r\n";
	char *msg;
	int error;

	if (!state->client_sent_epsv)
		return copy_line(input->start, input->end, output);

	if (input->epsv_227.addr.l3.s_addr != ip_hdr(input->skb)->saddr)
		return add_line(output, "425 Can't open data connection\r\n", false);

	msg = kmalloc(sizeof(template) - strlen("%u") + strlen("65535"),
			GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;
	error = sprintf(msg, template, input->epsv_227.addr.l4);
	if (error) {
		log_debug("sprintf() returned errcode %d.", error);
		kfree(msg);
		return error;
	}

	return add_line(output, msg, true);
}

void ftpsm_server_finished(struct ftp_state *state)
{
	if (state->client_sent_auth)
		state->transparent_mode = true;

	state->client_sent_auth = false;
	state->client_sent_epsv = false;
}

bool ftpsm_is_transparent_mode(struct ftp_state *state)
{
	return state->transparent_mode;
}
