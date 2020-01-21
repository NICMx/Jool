#include "expect.h"

#include <errno.h>
#include "log.h"
#include "command/common.h"

static int validate_uint(char const *token)
{
	unsigned int i;

	for (i = 0; token[i]; i++)
		if (token[i] < '0' || '9' < token[i])
			return pr_err("'%c' is not a digit.", token[i]);

	return 0;
}

static int parse_exceptions(char const *_str, struct expect_add_request *req)
{
	char *str;
	char *token;
	unsigned long int tmp;
	int error;

	req->exceptions_len = 0;

	/* we need a copy because strtok corrupts the string */
	str = strdup(_str);
	if (!str)
		return pr_enomem();

	token = strtok(str, ",");
	while (token) {
		if (req->exceptions_len >= EXCEPTIONS_MAX) {
			error = pr_err("Too many exceptions. (Max: %u)",
					EXCEPTIONS_MAX);
			goto abort;
		}

		error = validate_uint(token);
		if (error)
			goto abort;

		errno = 0;
		tmp = strtoul(token, NULL, 10);
		if (errno) {
			error = errno;
			pr_err("Number parsing failed: %s", strerror(error));
			goto abort;
		}

		if (tmp > UINT16_MAX) {
			error = pr_err("%lu is out of bounds. (0-%d)", tmp,
					UINT16_MAX);
			goto abort;
		}

		req->exceptions[req->exceptions_len++] = tmp;
		token = strtok(NULL, ",");
	}

	free(str);
	return 0;

abort:
	free(str);
	return error;
}

int expect_init_request(int argc, char **argv, enum graybox_command *cmd,
		struct expect_add_request *req)
{
	int error;

	if (argc < 1) {
		pr_err("expect needs an operation as first argument.");
		return -EINVAL;
	}

	if (strcasecmp(argv[0], "add") == 0) {
		*cmd = COMMAND_EXPECT_ADD;

		if (argc < 2) {
			pr_err("expect add needs a packet as argument.");
			return -EINVAL;
		}

		req->file_name = argv[1];
		error = load_pkt(argv[1], &req->pkt, &req->pkt_len);
		if (error)
			return error;
		return (argc >= 3) ? parse_exceptions(argv[2], req) : 0;

	} else if (strcasecmp(argv[0], "flush") == 0) {
		*cmd = COMMAND_EXPECT_FLUSH;
		return 0;
	}

	pr_err("Unknown operation for expect: %s", argv[0]);
	return -EINVAL;
}

void expect_add_clean(struct expect_add_request *req)
{
	if (req->pkt)
		free(req->pkt);
}

int expect_add_build_pkt(struct expect_add_request *req, struct nl_msg *pkt)
{
	int error;

	error = nla_put_string(pkt, ATTR_FILENAME, req->file_name);
	if (error)
		return error;

	error = nla_put(pkt, ATTR_PKT, req->pkt_len, req->pkt);
	if (error)
		return error;

	if (req->exceptions_len)
		error = nla_put(pkt, ATTR_EXCEPTIONS,
				sizeof(*req->exceptions) * req->exceptions_len,
				req->exceptions);

	return error;
}
