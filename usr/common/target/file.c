#include "nat64/usr/file.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/usr/cJSON.h"
#include "nat64/usr/global.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/nl/buffer.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/argp/options.h"

static int do_parsing(char *buffer);
static int parse_siit_json(cJSON *json);
static int parse_nat64_json(cJSON *json);
static int handle_global(cJSON *global_json);
static int handle_pool6(cJSON *pool6_json);
static int handle_eamt(cJSON *json);
static int handle_addr4_pool(cJSON *json, enum parse_section section);
static int handle_pool4(cJSON *pool4);
static int handle_bib(cJSON *bib);

extern int parse_file(char *file_name)
{
	FILE *file;
	long length;
	long read_bytes = 0;
	char *buffer;
	int error;

	file = fopen(file_name, "rb");
	if (!file) {
		perror("fopen() error");
		return -EINVAL;
	}

	error = fseek(file, 0, SEEK_END);
	if (error) {
		perror("fseek() 1 error");
		goto fail;
	}

	length = ftell(file);
	if (length == -1) {
		perror("ftell() error");
		error = length;
		goto fail;
	}

	error = fseek(file, 0, SEEK_SET);
	if (error) {
		perror("fseek() 2 error");
		goto fail;
	}

	buffer = malloc(length);
	if (!buffer) {
		log_err("Out of memory.");
		error = -ENOMEM;
		goto fail;
	}

	while (read_bytes < length)
		read_bytes += fread(&buffer[read_bytes], 1, length, file);

	fclose(file);

	error = do_parsing(buffer);
	free(buffer);
	return error;

fail:
	fclose(file);
	return error;
}

static int validate_file_type(cJSON *json_structure)
{
	char *siit = "SIIT";
	char *nat64 = "NAT64";
	char *expected;

	cJSON *file_type = cJSON_GetObjectItem(json_structure, "File_Type");
	if (!file_type)
		return 0; /* The user doesn't care. */

	expected = xlat_is_siit() ? siit : nat64;

	if (strcmp(file_type->valuestring, expected) != 0) {
		log_err("File_Type is supposed to be '%s' (got '%s').",
				expected, file_type->valuestring);
		return -EINVAL;
	}

	return 0;
}

static int do_parsing(char *buffer)
{
	int error;

	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
		log_err("The JSON parsing yielded the following error:");
		log_err("%s", cJSON_GetErrorPtr());
		return -EINVAL;
	}

	error = validate_file_type(json);
	if (error)
		return error;

	return xlat_is_siit() ? parse_siit_json(json) : parse_nat64_json(json);
}

static int write_section(struct nl_buffer *buffer, enum parse_section section)
{
	__u16 tmp = section;
	int error;

	error = nlbuffer_write(buffer, &tmp, sizeof(tmp));
	if (error)
		log_err("Writing on an empty buffer yielded error %d.", error);

	return error;
}

static struct nl_buffer *buffer_create(enum parse_section section)
{
	struct nl_buffer *buffer;
	struct request_hdr hdr;
	int error;

	buffer = nlbuffer_create();
	if (!buffer) {
		log_err("Out of memory.");
		return NULL;
	}

	init_request_hdr(&hdr, 0, MODE_PARSE_FILE, OP_ADD);
	error = nlbuffer_write(buffer, &hdr, sizeof(hdr));
	if (error) {
		log_err("Writing on an empty buffer yielded error %d.", error);
		goto fail;
	}

	error = write_section(buffer, section);
	if (error)
		goto fail;

	return buffer;

fail:
	nlbuffer_destroy(buffer);
	return NULL;
}

static int buffer_write(struct nl_buffer *buffer,
		void *payload, size_t payload_len,
		enum parse_section section)
{
	int error;

	error = nlbuffer_write(buffer, payload, payload_len);
	if (!error || error != -ENOSPC)
		return error;

	error = nlbuffer_flush(buffer);
	if (error)
		return error;
	error = write_section(buffer, section);
	return error ? : nlbuffer_write(buffer, payload, payload_len);
}

static int send_ctrl_msg(enum parse_section section)
{
	struct nl_buffer *buffer;
	int error;

	buffer = buffer_create(section);
	if (!buffer)
		return -ENOMEM;

	error = nlbuffer_flush(buffer);
	nlbuffer_destroy(buffer);
	return error;
}

static int parse_siit_json(cJSON *json)
{
	int error;

	error = send_ctrl_msg(SEC_INIT);
	if (error)
		return error;

	cJSON *global = cJSON_GetObjectItem(json, "Global");
	error = handle_global(global);
	if (error)
		return error;

	cJSON *pool6_json = cJSON_GetObjectItem(json, "Pool6");
	error = handle_pool6(pool6_json);
	if (error)
		return error;

	cJSON *eamt_json = cJSON_GetObjectItem(json, "EAMT");
	error = handle_eamt(eamt_json);
	if (error)
		return error;

	cJSON *blacklist_json = cJSON_GetObjectItem(json, "Blacklist");
	error = handle_addr4_pool(blacklist_json, SEC_BLACKLIST);
	if (error)
		return error;

	cJSON *pool6791_json = cJSON_GetObjectItem(json, "Pool6791");
	error = handle_addr4_pool(pool6791_json, SEC_POOL6791);
	if (error)
		return error;

	return send_ctrl_msg(SEC_COMMIT);
}

static int parse_nat64_json(cJSON *json)
{
	int error;

	error = send_ctrl_msg(SEC_INIT);
	if (error)
		return error;

	cJSON *global = cJSON_GetObjectItem(json, "Global");
	error = handle_global(global);
	if (error)
		return error;

	cJSON *pool6_json = cJSON_GetObjectItem(json, "Pool6");
	error = handle_pool6(pool6_json);
	if (error)
		return error;

	cJSON *pool4_json = cJSON_GetObjectItem(json, "Pool4");
	error = handle_pool4(pool4_json);
	if (error)
		return error;

	cJSON *bib_json = cJSON_GetObjectItem(json, "BIB");
	error = handle_bib(bib_json);
	if (error)
		return error;

	return send_ctrl_msg(SEC_COMMIT);
}

static int write_bool(struct nl_buffer *buffer, enum global_type type,
		cJSON *json)
{
	struct global_value *chunk;
	size_t size;
	int error;

	size = sizeof(struct global_value) + sizeof(__u8);
	chunk = malloc(size);
	if (!chunk) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	chunk->type = type;
	chunk->len = size;
	error = str_to_bool(json->valuestring, (__u8 *)(chunk + 1));
	if (error)
		goto end;

	error = buffer_write(buffer, chunk, size, SEC_GLOBAL);
	/* Fall through. */

end:
	free(chunk);
	return error;
}

static int write_number(struct nl_buffer *buffer, enum global_type type,
		cJSON *json)
{
	struct global_value *chunk;
	size_t size;
	int error;

	size = sizeof(struct global_value) + sizeof(__u64);
	chunk = malloc(size);
	if (!chunk) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	chunk->type = type;
	chunk->len = size;
	error = str_to_u64(json->valuestring, (__u64 *)(chunk + 1), 0, MAX_U64);
	if (error)
		goto end;

	error = buffer_write(buffer, chunk, size, SEC_GLOBAL);
	/* Fall through. */

end:
	free(chunk);
	return error;
}

static int write_plateaus(struct nl_buffer *buffer, cJSON *root)
{
	struct global_value *chunk;
	size_t size;
	cJSON *json;
	__u16 *plateaus;
	__u16 i;
	int error;

	i = 0;
	for (json = root->child; json; json = json->next) {
		if (i > PLATEAUS_MAX) {
			log_err("Too many plateaus. (max is %u)", PLATEAUS_MAX);
			return -EINVAL;
		}
		i++;
	}

	size = sizeof(struct global_value) + i * sizeof(__u16);
	chunk = malloc(size);
	if (!chunk) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	chunk->type = MTU_PLATEAUS;
	chunk->len = size;
	plateaus = (__u16 *)(chunk + 1);

	i = 0;
	for (json = root->child; json; json = json->next) {
		error = str_to_u16(json->valuestring, &plateaus[i], 0, 0xFFFF);
		if (error)
			goto end;
		i++;
	}

	error = buffer_write(buffer, chunk, size, SEC_GLOBAL);
	/* Fall through. */

end:
	free(chunk);
	return error;
}

static int write_field(cJSON *json, struct argp_option *opt,
		struct nl_buffer *buffer)
{
	if (strcmp(opt->arg, BOOL_FORMAT) == 0) {
		return write_bool(buffer, opt->key, json);
	} else if (strcmp(opt->arg, NUM_FORMAT) == 0) {
		return write_number(buffer, opt->key, json);
	} else if (strcmp(opt->arg, NUM_ARRAY_FORMAT) == 0) {
		return write_plateaus(buffer, json);
	}

	log_err("Unimplemented data type: %s", opt->arg);
	return -EINVAL;
}

static int handle_global_field(cJSON *json, struct nl_buffer *buffer)
{
	struct argp_option *opts;
	unsigned int i;
	int error;

	opts = get_global_opts();
	if (!opts)
		return -ENOMEM;

	for (i = 0; opts[i].name && opts[i].key; i++) {
		if (strcmp(json->string, opts[i].name) == 0) {
			error = write_field(json, &opts[i], buffer);
			free(opts);
			return error;
		}
	}

	log_err("Unknown global configuration field: %s", json->string);
	free(opts);
	return -EINVAL;
}

static int handle_global(cJSON *json)
{
	struct nl_buffer *buffer;
	int error;

	if (!json)
		return 0;

	buffer = buffer_create(SEC_GLOBAL);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next) {
		error = handle_global_field(json, buffer);
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_pool6(cJSON *pool6_json)
{
	struct nl_buffer *buffer;
	struct ipv6_prefix prefix;
	int error;

	if (!pool6_json)
		return 0;

	buffer = buffer_create(SEC_POOL6);
	if (!buffer)
		return -ENOMEM;

	error = str_to_prefix6(pool6_json->valuestring, &prefix);
	if (error)
		goto end;

	error = buffer_write(buffer, &prefix, sizeof(prefix), SEC_POOL6);
	if (error)
		goto end;

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_eamt(cJSON *json)
{
	struct nl_buffer *buffer;
	cJSON *prefix_json;
	struct eamt_entry eam;
	unsigned int i = 1;
	int error;

	if (!json)
		return 0;

	buffer = buffer_create(SEC_EAMT);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next, i++) {
		prefix_json = cJSON_GetObjectItem(json, "ipv6_prefix");
		if (!prefix_json) {
			log_err("EAM entry #%u lacks an ipv6_prefix field.", i);
			error = -EINVAL;
			goto end;
		}
		error = str_to_prefix6(prefix_json->valuestring, &eam.prefix6);
		if (error) {
			log_err("Error found on EAM entry #%u.", i);
			goto end;
		}

		prefix_json = cJSON_GetObjectItem(json, "ipv4_prefix");
		if (!prefix_json) {
			log_err("EAM entry #%u lacks an ipv4_prefix field.", i);
			error = -EINVAL;
			goto end;
		}
		error = str_to_prefix4(prefix_json->valuestring, &eam.prefix4);
		if (error) {
			log_err("Error found on EAM entry #%u.", i);
			goto end;
		}

		error = buffer_write(buffer, &eam, sizeof(eam), SEC_EAMT);
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_addr4_pool(cJSON *json, enum parse_section section)
{
	struct nl_buffer *buffer;
	struct ipv4_prefix prefix;
	int error;

	if (!json)
		return 0;

	buffer = buffer_create(section);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next) {
		error = str_to_prefix4(json->valuestring, &prefix);
		if (error)
			goto end;
		error = buffer_write(buffer, &prefix, sizeof(prefix), section);
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_pool4(cJSON *json)
{
	struct nl_buffer *buffer;
	struct cJSON *child;
	struct pool4_entry_usr entry;
	unsigned int i = 1;
	int error = 0;

	if (!json)
		return 0;

	buffer = buffer_create(SEC_POOL4);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next, i++) {
		child = cJSON_GetObjectItem(json, "mark");
		entry.mark = child ? child->valueint : 0;

		child = cJSON_GetObjectItem(json, "protocol");
		if (!child) {
			log_err("Pool4 entry %u lacks a protocol field.", i);
			error = -EINVAL;
			goto end;
		}
		entry.proto = str_to_l4proto(child->valuestring);
		if (entry.proto == L4PROTO_OTHER) {
			log_err("Protocol '%s' is unknown.",
					child->valuestring);
			error = -EINVAL;
			goto end;
		}

		child = cJSON_GetObjectItem(json, "prefix");
		if (!child) {
			log_err("Pool4 entry %u lacks a prefix field.", i);
			error = -EINVAL;
			goto end;
		}
		error = str_to_prefix4(child->valuestring, &entry.addrs);
		if (error)
			goto end;

		child = cJSON_GetObjectItem(json, "port_range");
		if (child) {
			error = str_to_port_range(child->valuestring,
					&entry.ports);
			if (error)
				goto end;
		} else {
			entry.ports.min = DEFAULT_POOL4_MIN_PORT;
			entry.ports.max = DEFAULT_POOL4_MAX_PORT;
		}

		error = buffer_write(buffer, &entry, sizeof(entry), SEC_POOL4);
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_bib(cJSON *json)
{
	/* TODO first do the kernel part. */
	return 0;
}
