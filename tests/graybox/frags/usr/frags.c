#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <argp.h>

#include "types.h"
#include "communication.h"

#define MAX_PKT_SIZE 1024

static int create_packet(char *filename, void **pkt, __u32 *file_size)
{
	FILE *file;
	char *buffer;
	size_t bytes_read;

	file = fopen(filename, "rb");
	if (!file) {
		log_err("Could not open the file %s.", filename);
		return -EINVAL;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	buffer = malloc(sizeof(*buffer) * (*file_size));
	if (!buffer) {
		log_err("Could not allocate the packet.");
		fclose(file);
		return -ENOMEM;
	}

	bytes_read = fread(buffer, 1, *file_size, file);
	fclose(file);

	if (bytes_read != (*file_size)) {
		log_err("Reading error.");
		return -EINVAL;
	}

	*pkt = buffer;
	return 0;
}

/* The options we understand. */
static struct argp_option options[] = {
		{"sender",	's', "FILE",	0,	"Send a packet from user space to the sender module."},
		{"receiver",	'r', "FILE",	0,
				"Send a packet from user space to the receiver module."},
		{"flush", 'f', NULL, 0, "Flush all the receiver DB."},
		{ 0 }

};

/* Used by main to communicate with parse_opt. */
struct arguments
{
	enum operations op;
	char *file_name;
	__u8 is_file_set;
	__u8 flush;
};

/*
 * ARGS_DOC. Field 3 in ARGP.
 * A description of the non-option command-line arguments we accept.
 */
static char args_doc[] = "";

/*
 * DOC. Field 4 in ARGP.
 * Program documentation.
 */
static char doc[] = "Packet Sender 'n' Receiver.\v";

/* Parse a single option. */
static int parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key) {
	case 's':
		arguments->op = OP_SENDER;
		if (arguments->is_file_set) {
			log_debug("You can only send one packet at a time.");
			return -EINVAL;
		}

		arguments->file_name = arg;
		arguments->is_file_set = 1;
		break;
	case 'r':
		arguments->op = OP_RECEIVER;
		if (arguments->is_file_set) {
			log_debug("You can only send one packet at a time.");
			return -EINVAL;
		}
		arguments->file_name = arg;
		arguments->is_file_set = 1;
		break;

	case 'f':
		arguments->op = OP_FLUSH_DB;
		arguments->flush = 1;
		break;
/*	case ARGP_KEY_ARG:
		if (state->arg_num > 1) {
			log_err("Too Many arguments.");
			argp_usage (state);
		}

		break;

	case ARGP_KEY_END:
		if (state->arg_num) {
			log_err("not enough arguments.");
			argp_usage (state);
		}

		break;*/

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int argument_parser(int argc, char **argv, struct arguments *arguments)
{
	int error;
	struct argp argp = { options, parse_opt, args_doc, doc };

	arguments->file_name = NULL;
	arguments->op = 0;
	arguments->is_file_set = 0;

	error = argp_parse(&argp, argc, argv, 0, NULL, arguments);
	if (error)
		return error;

	return 0;
}

static int send_packet_to_kernel(struct arguments *args)
{
	void *pkt;
	__u32 pkt_len;
	int error;

	error = create_packet(args->file_name, &pkt, &pkt_len);
	if (error)
		return error;

	error = send_packet(pkt, pkt_len, args->op);
	free(pkt);
	return error;
}

static int flush_database(struct arguments *args)
{
	int error;
	error = send_flush_op(args->is_file_set);
	return error;
}

int main(int argc, char *argv[])
{
	struct arguments arguments;
	int error;

	error = argument_parser(argc, argv, &arguments);
	if (error)
		return -error;

	switch (arguments.op) {
	case OP_SENDER:
		error = send_packet_to_kernel(&arguments);
		break;
	case OP_RECEIVER:
		error = send_packet_to_kernel(&arguments);
		break;
	case OP_FLUSH_DB:
		error = flush_database(&arguments);
		break;
	default:
		log_err("Unknown configuration operation: %u", arguments.op);
		error = -EINVAL;
	}

	return -error;
}
