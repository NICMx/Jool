#include <errno.h>
#include <stddef.h>
#include <netlink/attr.h>

#include "netlink.h"
#include "types.h"
#include "nat64/usr/str_utils.h"

struct request {
	enum graybox_command cmd;

	char *file_name;
	unsigned char *pkt;
	int pkt_len;

	__u16 *exceptions;
	int exceptions_len;
};

static int load_pkt(char *filename, struct request *req)
{
	FILE *file;
	int bytes_read;

	file = fopen(filename, "rb");
	if (!file) {
		log_err("Could not open the file %s.", filename);
		return -EINVAL;
	}

	fseek(file, 0, SEEK_END);
	req->pkt_len = ftell(file);
	rewind(file);

	req->pkt = malloc(req->pkt_len);
	if (!req->pkt) {
		log_err("Could not allocate the packet.");
		fclose(file);
		return -ENOMEM;
	}

	bytes_read = fread(req->pkt, 1, req->pkt_len, file);
	fclose(file);

	if (bytes_read != req->pkt_len) {
		log_err("Reading error.");
		free(req->pkt);
		return -EINVAL;
	}

	return 0;
}

int parse_exceptions(char *exceptions, struct request *req)
{
	size_t len;
	int error;

	if (!exceptions) {
		req->exceptions = NULL;
		req->exceptions_len = 0;
		return 0;
	}

	error = str_to_u16_array(exceptions, &req->exceptions, &len);
	if (!error)
		req->exceptions_len = len;
	return error;
}

static int request_create(int argc, char **argv, struct request *req)
{
	char *type;
	char *file;
	char *exceptions;
	int error;

	if (argc < 3) {
		log_err("I need at least 2 arguments.");
		return EINVAL;
	}

	type = argv[1];
	file = argv[2];
	exceptions = (argc >= 4) ? argv[3] : NULL;

	if (strcasecmp(type, "expect")) {
		req->cmd = COMMAND_EXPECT;
	} else if (strcasecmp(type, "send")) {
		req->cmd = COMMAND_SEND;
	} else if (strcasecmp(type, "stats")) {
		req->cmd = COMMAND_STATS;
	} else {
		log_err("'%s' is an unknown operation.", argv[1]);
		return -EINVAL;
	}

	error = load_pkt(file, req);
	if (error)
		return error;

	error = parse_exceptions(exceptions, req);
	if (error) {
		free(req->pkt);
		return error;
	}

	return 0;
}

void request_destroy(struct request *req)
{
	if (req->pkt)
		free(req->pkt);
	if (req->exceptions)
		free(req->exceptions);
}

static int build_packet(struct request *req, struct nl_msg **result)
{
	struct nl_msg *msg;
	int error;

	error = nlsocket_create_msg(req->cmd, &msg);
	if (error)
		return error;

	error = nla_put_string(msg, ATTR_FILENAME, req->file_name);
	if (error)
		goto put_fail;

	error = nla_put(msg, ATTR_PKT, req->pkt_len, req->pkt);
	if (error)
		goto put_fail;

	if (req->exceptions) {
		error = nla_put(msg, ATTR_EXCEPTIONS,
				sizeof(*req->exceptions) * req->exceptions_len,
				req->exceptions);
		if (error)
			goto put_fail;
	}

	*result = msg;
	return 0;

put_fail:
	log_err("Could not write on the packet to kernelspace.");
	nlmsg_free(msg);
	return netlink_print_error(error);
}

int main(int argc, char *argv[])
{
	struct request req;
	struct nl_msg *msg = NULL;
	int error;

	error = request_create(argc, argv, &req);
	if (error)
		return error;

	error = nlsocket_init("graybox");
	if (error)
		goto end1;

	error = build_packet(&req, &msg);
	if (error)
		goto end2;

	error = nlsocket_send(msg);

	nlmsg_free(msg);
end2:
	nlsocket_destroy();
end1:
	request_destroy(&req);
	return error;
}
