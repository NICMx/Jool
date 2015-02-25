#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <argp.h>

#include "types.h"
#include "communication.h"
#include "device.h"

#define MAX_PKT_SIZE 1024

const char *argp_program_version = "1.1";
const char *argp_program_bug_address = "jool@nic.mx";

/* Used by main to communicate with parse_opt. */
struct arguments
{
	enum config_operation ops;
	enum config_mode mode;
	__u8 flush;

	struct {
		char *file_name;
		__u8 is_file_set;
	} pkt ;

	struct {
		char *name;
		__u8 is_name_set;
	} device;

	struct {
		__u8 type;
		size_t size;
		void *data;
	} global;
};

enum argp_flags {
	/* Modes */
	ARGP_RECEIVER = 'r',
	ARGP_SENDER = 's',
	ARGP_BYTE = 'g',
	ARGP_DEVICE = 'e',

	/* Operations */
	ARGP_DISPLAY = 'd',
	ARGP_ADD = 'a',
	ARGP_FLUSH = 'f',

	ARGP_PKT = 1000,
	ARGP_NUM_ARRAY = 1001,
	ARGP_DEVICE_NAME = 1002,
};

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

static int set_global_arg(struct arguments *args, __u8 type, size_t size, void *value)
{
	if (args->global.data) {
		log_err("You can only edit one configuration value at a time.");
		return -EINVAL;
	}

	args->global.type = type;
	args->global.size = size;
	args->global.data = malloc(size);
	if (!args->global.data)
		return -ENOMEM;
	memcpy(args->global.data, value, size);

	return 0;
}

static int verify_array_order(__u16 array[], int array_len)
{
	int i;

	if (!array) {
		log_err("Array cannot contain NULL.");
	}

	for (i = 0; i < array_len - 1; i++) {
		if (array[i] > array[i+1]) {
			log_err("Insert the array in ascendent order.");
			return -EINVAL;
		}
	}

	return 0;
}

int str_to_u64(const char *str, __u64 *u64_out, __u64 min, __u64 max)
{
	__u64 result;
	char *endptr;

	errno = 0;
	result = strtoull(str, &endptr, 10);
	if (errno != 0 || str == endptr) {
		log_err("Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err("'%s' is out of bounds (%llu-%llu).", str, min, max);
		return -EINVAL;
	}

	*u64_out = result;
	return 0;
}

static int str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	__u64 result;
	int error;

	error = str_to_u64(str, &result, (__u64) min, (__u64) max);
	if (error)
		return error; /* Error msg already printed. */

	*u16_out = result;
	return 0;
}

#define STR_MAX_LEN 2048
static int str_to_u16_array(const char *str, __u16 **array_out, size_t *array_len_out)
{
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	__u16 *array;
	size_t array_len;

	/* Validate str and copy it to the temp buffer. */
	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	/* Count the number of ints in the string. */
	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		array_len++;
		token = strtok(NULL, ",");
	}

	if (array_len == 0) {
		log_err("'%s' seems to be an empty list, which is not supported.", str);
		return -EINVAL;
	}

	/* Build the result. */
	array = malloc(array_len * sizeof(*array));
	if (!array) {
		log_err("Memory allocation failed. Cannot parse the input...");
		return -ENOMEM;
	}

	strcpy(str_copy, str);

	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		int error;

		error = str_to_u16(token, &array[array_len], 0, 0xFFFF);
		if (error) {
			free(array);
			return error; /* Error msg already printed. */
		}

		array_len++;
		token = strtok(NULL, ",");
	}

	/* Finish. */
	*array_out = array;
	*array_len_out = array_len;
	return 0;
}

static int set_global_u16_array(struct arguments *args, int type, char *value)
{
	__u16* array;
	size_t array_len;
	int error;

	error = str_to_u16_array(value, &array, &array_len);
	if (error)
		return error;

	error = verify_array_order(array, array_len);
	if (error)
		return error;

	error = set_global_arg(args, type, array_len * sizeof(*array), array);
	free(array);
	return error;
}

/* The options we understand. */
static struct argp_option options[] = {
		{ NULL, 0, NULL, 0, "Configuration targets/modes:", 1},
		{ "receiver", ARGP_RECEIVER, NULL, 0, "The command will operate the Receiver module."},
		{ "sender", ARGP_SENDER, NULL, 0, "The command will operate the Sender module."},
		{ "general", ARGP_BYTE, NULL, 0, "The command will operate on bytes module (default)." },
		{ "device", ARGP_DEVICE, NULL, 0, "The command will operate on interface module. "},
		{ NULL, 0, NULL, 0, "Operations:", 2 },
		{ "display", ARGP_DISPLAY, NULL, 0, "Display an element of the target."},
		{ "add", ARGP_ADD, NULL, 0, "Add an element to the target." },
		{ "flush", ARGP_FLUSH, NULL, 0, "Clear the target." },
		{ NULL, 0, NULL, 0, "Sender and Receiver options:", 3 },
		{ "pkt", ARGP_PKT, "FILE", 0, "Packet that will be parse as skb."},
		{ NULL, 0, NULL, 0, "Byte options:", 4 },
		{ "numArray", ARGP_NUM_ARRAY, "NUM[,NUM]*", 0, "Set the bytes that will be skip when "
				"compared an incoming SKB, bytes must be ascendent."},
		{ NULL, 0, NULL, 0, "Interface options: ", 4},
		{ "name", ARGP_DEVICE_NAME, "NAME", 0, "Set the device interface that the graybox will take "
				"the packets"},
		{0},
};

static int update_state(struct arguments *args, enum config_mode valid_modes,
		enum config_operation valid_ops)
{
	enum config_mode common_modes;
	enum config_operation common_ops;

	common_modes = args->mode & valid_modes;
	if (!common_modes || (common_modes | valid_modes) != valid_modes)
		goto fail;
	args->mode = common_modes;

	common_ops = args->ops & valid_ops;
	if (!common_ops || (common_ops | valid_ops) != valid_ops)
		goto fail;
	args->ops = common_ops;

	return 0;

fail:
	log_err("Illegal combination of parameters. See `graybox --help`.");
	return -EINVAL;
}


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
static int parse_opt(int key, char *str, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
		know is a pointer to our arguments structure. */
	struct arguments *args = state->input;
	int error = 0;

	switch (key) {
	case ARGP_RECEIVER:
		error = update_state(args, MODE_RECEIVER, RECEIVER_OPS);
		break;
	case ARGP_SENDER:
		error = update_state(args, MODE_SENDER, SENDER_OPS);
		break;
	case ARGP_BYTE:
		error = update_state(args, MODE_BYTE, BYTE_OPS);
		break;
	case ARGP_DEVICE:
		error = update_state(args, MODE_DEVICE, DEVICE_OPS);
		break;
	case ARGP_DISPLAY:
		error = update_state(args, DISPLAY_MODES, OP_DISPLAY);
		break;
	case ARGP_ADD:
		error = update_state(args, ADD_MODES, OP_ADD);
		break;
	case ARGP_FLUSH:
		error = update_state(args, FLUSH_MODES, OP_FLUSH);
		args->flush = 1;
		break;
	case ARGP_PKT:
		error = update_state(args, MODE_RECEIVER | MODE_SENDER, OP_ADD);
		if (error)
			goto err;
		if (args->pkt.is_file_set) {
			log_err("You can only send one packet at a time.");
			return -EINVAL;
		}
		args->pkt.is_file_set = 1;
		args->pkt.file_name = str;
		break;
	case ARGP_NUM_ARRAY:
		error = update_state(args, MODE_BYTE, OP_ADD);
		if (error)
			goto err;

		error = set_global_u16_array(args, 1/*TODO: set a type?*/, str);
		break;
	case ARGP_DEVICE_NAME:
		error = update_state(args, MODE_DEVICE, OP_ADD | OP_REMOVE);
		if (error)
			goto err;

		args->device.is_name_set = 1;
		args->device.name = str;
		break;

	default:
		error = ARGP_ERR_UNKNOWN;
	}

err:
	return error;
}

/**
 * Zeroizes all of "num"'s bits, except the last one. Returns the result.
 */
static unsigned int zeroize_upper_bits(__u8 num)
{
	__u8 mask = 0x01;

	do {
		if ((num & mask) != 0)
			return num & mask;
		mask <<= 1;
	} while (mask);

	return num;
}

static int argument_parser(int argc, char **argv, struct arguments *arguments)
{
	int error;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(arguments, 0, sizeof(*arguments));
	arguments->mode = 0xFF;
	arguments->ops = 0xFF;

	error = argp_parse(&argp, argc, argv, 0, NULL, arguments);
	if (error)
		return error;

	arguments->mode = zeroize_upper_bits(arguments->mode);
	arguments->ops = zeroize_upper_bits(arguments->ops);

	return 0;
}

static int send_packet_to_kernel(struct arguments *args)
{
	void *pkt;
	__u32 pkt_len;
	int error;

	error = create_packet(args->pkt.file_name, &pkt, &pkt_len);
	if (error)
		return error;

	/* In strlen(args->pkt.file_name), plus "1" because of the null character. */
	error = send_packet(pkt, pkt_len, args->pkt.file_name, strlen(args->pkt.file_name) + 1,
			args->mode, args->ops);
	free(pkt);
	return error;
}

static int flush_database(struct arguments *args)
{
	return send_flush_op(args->mode, args->ops);
}

static int general_send_array(struct arguments *args)
{
	return global_update(args->global.type, args->global.size, args->global.data);
}

static int main_wrapped(int argc, char **argv)
{
	struct arguments args;
	int error;
	error = argument_parser(argc, argv, &args);
	if (error)
		return error;

	switch (args.mode) {
	case MODE_RECEIVER:
		switch (args.ops) {
		case OP_DISPLAY:
			return receiver_display();
		case OP_ADD:
			return send_packet_to_kernel(&args);
		case OP_FLUSH:
			return flush_database(&args);
		default:
			log_err("Unknown operation for receiver mode.");
			return -EINVAL;
		}
		break;
	case MODE_SENDER:
		switch (args.ops) {
		case OP_ADD:
			return send_packet_to_kernel(&args);
		default:
			log_err("Unknown operation for sender mode.");
			return -EINVAL;
		}
		break;
	case MODE_DEVICE:
		switch (args.ops) {
		case OP_ADD:
			if (!args.device.is_name_set) {
				log_err("Please set the device name, that you want to add (--name)");
				return -EINVAL;
			}
			return dev_add(args.device.name, strlen(args.device.name) + 1);
		case OP_DISPLAY:
			return dev_display();
		case OP_FLUSH:
			return dev_flush();
		case OP_REMOVE:
			if (!args.device.is_name_set) {
				log_err("Please set the device name, that you want to remove (--name)");
				return -EINVAL;
			}
			/* plus "1" because of the null character. */
			return dev_remove(args.device.name, strlen(args.device.name) + 1);
		}
		break;
	case MODE_BYTE:
		switch (args.ops) {
		case OP_DISPLAY:
			return general_display_array();
		case OP_ADD:
			return general_send_array(&args);
		case OP_FLUSH:
			return flush_database(&args);
		default:
			log_err("Unknown operation for general mode.");
			return -EINVAL;
		}
		break;
	}

	log_err("Unknown configuration mode: %u", args.mode);
	return -EINVAL;
}

int main(int argc, char *argv[])
{
	return -main_wrapped(argc, argv);
}
