#include "nat64/usr/json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/usr/cJSON.h"
#include "nat64/usr/file.h"
#include "nat64/usr/global.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/nl/buffer.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/argp/options.h"

static int do_parsing(char *buffer);
static int parse_siit_json(cJSON *json);
static int parse_nat64_json(cJSON *json);
static int handle_global(cJSON *json, bool *globals_found);
static int handle_pool6(cJSON *pool6_json);
static int handle_eamt(cJSON *json);
static int handle_addr4_pool(cJSON *json, enum parse_section section);
static int handle_pool4(cJSON *pool4);
static int handle_bib(cJSON *bib);

int parse_file(char *file_name)
{
	char *buffer;
	int error;

	error = file_to_string(file_name, &buffer);
	if (error)
		return error;

	error = do_parsing(buffer);
	free(buffer);
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

	if (strcasecmp(file_type->valuestring, expected) != 0) {
		log_err("File_Type is supposed to be '%s' (got '%s').",
				expected, file_type->valuestring);
		return -EINVAL;
	}

	return 0;
}

static int print_datatype_error(const char *field, cJSON *json, char *expected)
{
	switch (json->type) {
	case cJSON_False:
		log_err("%s 'false' is not a valid %s.", field, expected);
		break;
	case cJSON_True:
		log_err("%s 'true' is not a valid %s.", field, expected);
		break;
	case cJSON_NULL:
		log_err("%s 'null' is not a valid %s.", field, expected);
		break;
	case cJSON_Number:
		if (json->numflags & VALUENUM_UINT)
			log_err("%s '%u' is not a valid %s.", field,
					json->valueuint, expected);
		else if (json->numflags & VALUENUM_INT)
			log_err("%s '%d' is not a valid %s.", field,
					json->valueint, expected);
		else
			log_err("%s '%f' is not a valid %s.", field,
					json->valuedouble, expected);
		break;
	case cJSON_String:
		log_err("%s '%s' is not a valid %s.", field, json->valuestring,
				expected);
		break;
	case cJSON_Array:
		log_err("%s appears to be an array, not a %s.", field,
				expected);
		break;
	case cJSON_Object:
		log_err("%s appears to be an object, not a %s.", field,
				expected);
		break;
	}

	if (strcmp(expected, "boolean") == 0 || strcmp(expected, "int") == 0)
		log_err("(Note: Quotation marks might also be the problem.)");

	return -EINVAL;
}

static int validate_json_uint(const char *field, struct cJSON *node,
		unsigned int min, unsigned int max)
{
	if (node->type != cJSON_Number || !(node->numflags & VALUENUM_UINT))
		return print_datatype_error(field, node, "unsigned integer");

	if (node->valueuint < min || max < node->valueuint) {
		log_err("%s %u is out of range (%u-%u).", field,
				node->valueuint, min, max);
		return -EINVAL;
	}

	return 0;
}

static int validate_u32(const char *field, struct cJSON *node)
{
	return validate_json_uint(field, node, 0, MAX_U32);
}

static int validate_u16(const char *field, struct cJSON *node)
{
	return validate_json_uint(field, node, 0, MAX_U16);
}

static int validate_u8(const char *field, struct cJSON *node)
{
	return validate_json_uint(field, node, 0, MAX_U8);
}

static int do_parsing(char *buffer)
{
	int error;

	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
		log_err("The JSON parser got confused around about here:");
		log_err("%s", cJSON_GetErrorPtr());
		return -EINVAL;
	}

	error = validate_file_type(json);
	if (error)
		return error;

	return xlat_is_siit() ? parse_siit_json(json) : parse_nat64_json(json);
}

static void check_duplicates(bool *found, char *section)
{
	if (*found)
		log_info("Note: I found multiple '%s' sections.", section);
	*found = true;
}

static int init_buffer(struct nl_buffer *buffer, enum parse_section section)
{
	struct request_hdr hdr;
	__u16 tmp = section;
	int error;

	init_request_hdr(&hdr, MODE_PARSE_FILE, OP_ADD);
	error = nlbuffer_write(buffer, &hdr, sizeof(hdr));
	if (error) {
		log_err("Writing on an empty buffer yielded error %d.", error);
		return error;
	}

	error = nlbuffer_write(buffer, &tmp, sizeof(tmp));
	if (error)
		log_err("Writing on an empty buffer yielded error %d.", error);

	return error;
}

static struct nl_buffer *buffer_alloc(enum parse_section section)
{
	struct nl_buffer *buffer;

	buffer = nlbuffer_alloc();
	if (!buffer) {
		log_err("Out of memory.");
		return NULL;
	}

	if (init_buffer(buffer, section)) {
		nlbuffer_destroy(buffer);
		return NULL;
	}

	return buffer;
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

	error = init_buffer(buffer, section);
	if (error)
		return error;

	return nlbuffer_write(buffer, payload, payload_len);
}

static int send_ctrl_msg(enum parse_section section)
{
	struct nl_buffer *buffer;
	int error;

	buffer = buffer_alloc(section);
	if (!buffer)
		return -ENOMEM;

	error = nlbuffer_flush(buffer);
	nlbuffer_destroy(buffer);
	return error;
}

static bool *create_globals_found_array(void)
{
	struct argp_option *opts;
	size_t i;

	opts = get_global_opts();
	if (!opts)
		return NULL;

	for (i = 0; opts[i].name; i++)
		/* No code; just counting. */;

	free(opts);

	return calloc(i, sizeof(bool));
}

static int parse_siit_json(cJSON *json)
{
	bool global_found = false;
	bool pool6_found = false;
	bool eamt_found = false;
	bool blacklist_found = false;
	bool pool6791_found = false;
	bool *globals_found;
	int error;

	error = send_ctrl_msg(SEC_INIT);
	if (error)
		return error;

	globals_found = create_globals_found_array();
	if (!globals_found) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	for (json = json->child; json; json = json->next) {
		if (strcasecmp(OPTNAME_GLOBAL, json->string) == 0) {
			check_duplicates(&global_found, OPTNAME_GLOBAL);
			error = handle_global(json, globals_found);
		} else if (strcasecmp(OPTNAME_POOL6, json->string) == 0) {
			check_duplicates(&pool6_found, OPTNAME_POOL6);
			error = handle_pool6(json);
		} else if (strcasecmp(OPTNAME_EAMT, json->string) == 0) {
			check_duplicates(&eamt_found, OPTNAME_EAMT);
			error = handle_eamt(json);
		} else if (strcasecmp(OPTNAME_BLACKLIST, json->string) == 0) {
			check_duplicates(&blacklist_found, OPTNAME_BLACKLIST);
			error = handle_addr4_pool(json, SEC_BLACKLIST);
		} else if (strcasecmp(OPTNAME_RFC6791, json->string) == 0) {
			check_duplicates(&pool6791_found, OPTNAME_RFC6791);
			error = handle_addr4_pool(json, SEC_POOL6791);
		} else if (strcasecmp("file_type", json->string) == 0) {
			/* No code. */
		} else {
			log_err("I don't know what '%s' is; Canceling.",
					json->string);
			error = -EINVAL;
		}

		if (error) {
			free(globals_found);
			return error;
		}
	}
	free(globals_found);

	return send_ctrl_msg(SEC_COMMIT);
}

static int parse_nat64_json(cJSON *json)
{
	bool global_found = false;
	bool pool6_found = false;
	bool pool4_found = false;
	bool bib_found = false;
	bool *globals_found;
	int error;

	error = send_ctrl_msg(SEC_INIT);
	if (error)
		return error;

	globals_found = create_globals_found_array();
	if (!globals_found) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	for (json = json->child; json; json = json->next) {
		if (strcasecmp(OPTNAME_GLOBAL, json->string) == 0) {
			check_duplicates(&global_found, OPTNAME_GLOBAL);
			error = handle_global(json, globals_found);
		} else if (strcasecmp(OPTNAME_POOL6, json->string) == 0) {
			check_duplicates(&pool6_found, OPTNAME_POOL6);
			error = handle_pool6(json);
		} else if (strcasecmp(OPTNAME_POOL4, json->string) == 0) {
			check_duplicates(&pool4_found, OPTNAME_POOL4);
			error = handle_pool4(json);
		} else if (strcasecmp(OPTNAME_BIB, json->string) == 0) {
			check_duplicates(&bib_found, OPTNAME_BIB);
			error = handle_bib(json);
		} else if (strcasecmp("file_type", json->string) == 0) {
			/* No code. */
		} else {
			log_err("I don't know what '%s' is; Canceling.",
					json->string);
			error = -EINVAL;
		}

		if (error) {
			log_info("Error code: %d", error);
			free(globals_found);
			return error;
		}
	}
	free(globals_found);

	return send_ctrl_msg(SEC_COMMIT);
}

static int write_bool(struct nl_buffer *buffer, struct argp_option *opt,
		cJSON *json)
{
	struct {
		struct global_value hdr;
		__u8 payload;
	} msg;

	msg.hdr.type = opt->key;
	msg.hdr.len = sizeof(msg);
	switch (json->type) {
	case cJSON_True:
		msg.payload = true;
		break;
	case cJSON_False:
		msg.payload = false;
		break;
	default:
		return print_datatype_error(opt->name, json, "boolean");
	}

	return buffer_write(buffer, &msg, msg.hdr.len, SEC_GLOBAL);
}

static int write_number(struct nl_buffer *buffer, struct argp_option *opt,
		cJSON *json)
{
	struct {
		struct global_value hdr;
		/*
		 * Please note: This assumes there are no __u64 global numbers.
		 * If you want to add a __u64, you will have to pack this,
		 * otherwise the compiler will add slop (because sizeof(hdr) is
		 * 32) and everything will stop working.
		 */
		union {
			__u8 payload8[4];
			__u16 payload16[2];
			__u32 payload32;
		};
	} msg;
	int error;

	/*
	 * TODO (fine) This is going overboard.
	 * There's too much to tweak whenever we want to add a global value.
	 * There should be a central static database of globals (keeping track
	 * of their types and sizes and whatnot) and everything should just
	 * query that.
	 */

	msg.hdr.type = opt->key;
	msg.hdr.len = sizeof(msg.hdr);
	switch (opt->key) {
	case F_ARGS:
	case NEW_TOS:
	case EAM_HAIRPINNING_MODE:
		error = validate_u8(opt->name, json);
		if (error)
			return error;
		msg.hdr.len += sizeof(__u8);
		msg.payload8[0] = json->valueuint;
		break;
	case SS_MAX_PAYLOAD:
		error = validate_u16(opt->name, json);
		if (error)
			return error;
		msg.hdr.len += sizeof(__u16);
		msg.payload16[0] = json->valueuint;
		break;
	case MAX_PKTS:
	case SS_CAPACITY:
	case UDP_TIMEOUT:
	case ICMP_TIMEOUT:
	case TCP_EST_TIMEOUT:
	case TCP_TRANS_TIMEOUT:
	case FRAGMENT_TIMEOUT:
	case SS_FLUSH_DEADLINE:
		error = validate_u32(opt->name, json);
		if (error)
			return error;
		msg.hdr.len += sizeof(__u32);
		msg.payload32 = json->valueuint;
		break;
	default:
		log_err("Unknown global type: %u", opt->key);
		return -EINVAL;
	}

	return buffer_write(buffer, &msg, msg.hdr.len, SEC_GLOBAL);
}

static int write_plateaus(struct nl_buffer *buffer, cJSON *root)
{
	struct global_value *chunk;
	size_t size;
	cJSON *json;
	__u16 *plateaus;
	__u16 i;
	/* TODO (later) I found a bug in gcc; remove "= -EINVAL." */
	int error = -EINVAL;

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
		error = validate_u16(OPTNAME_MTU_PLATEAUS, json);
		if (error)
			goto end;
		plateaus[i] = json->valueuint;
		i++;
	}

	error = buffer_write(buffer, chunk, size, SEC_GLOBAL);
	/* Fall through. */

end:
	free(chunk);
	return error;
}

static int write_optional_prefix6(struct nl_buffer *buffer,
		enum global_type type, cJSON *json)
{
	struct {
		struct global_value hdr;
		struct ipv6_prefix payload;
	} msg;
	int error;

	msg.hdr.type = type;
	msg.hdr.len = sizeof(msg.hdr);
	if (json->type != cJSON_NULL) {
		msg.hdr.len += sizeof(msg.payload);
		error = str_to_prefix6(json->valuestring, &msg.payload);
		if (error)
			return error;
	}

	return buffer_write(buffer, &msg, msg.hdr.len, SEC_GLOBAL);
}

static int write_field(cJSON *json, struct argp_option *opt,
		struct nl_buffer *buffer)
{
	if (strcmp(opt->arg, BOOL_FORMAT) == 0) {
		return write_bool(buffer, opt, json);
	} else if (strcmp(opt->arg, NUM_FORMAT) == 0) {
		return write_number(buffer, opt, json);
	} else if (strcmp(opt->arg, NUM_ARRAY_FORMAT) == 0) {
		return write_plateaus(buffer, json);
	} else if (strcmp(opt->arg, OPTIONAL_PREFIX6_FORMAT) == 0) {
		return write_optional_prefix6(buffer, opt->key, json);
	}

	log_err("Unimplemented data type: %s", opt->arg);
	return -EINVAL;
}

static int handle_global_field(cJSON *json, struct nl_buffer *buffer,
		bool *globals_found)
{
	struct argp_option *opts;
	unsigned int i;
	int error;

	opts = get_global_opts();
	if (!opts)
		return -ENOMEM;

	for (i = 0; opts[i].name && opts[i].key; i++) {
		if (strcasecmp(json->string, opts[i].name) == 0) {
			error = write_field(json, &opts[i], buffer);
			if (globals_found[i])
				log_info("Note: I found multiple '%s' definitions.",
						opts[i].name);
			globals_found[i] = true;
			free(opts);
			return error;
		}
	}

	log_err("Unknown global configuration field: %s", json->string);
	free(opts);
	return -EINVAL;
}

static int handle_global(cJSON *json, bool *globals_found)
{
	struct nl_buffer *buffer;
	int error;

	if (!json)
		return 0;

	buffer = buffer_alloc(SEC_GLOBAL);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next) {
		error = handle_global_field(json, buffer, globals_found);
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

	buffer = buffer_alloc(SEC_POOL6);
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

	buffer = buffer_alloc(SEC_EAMT);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next, i++) {
		prefix_json = cJSON_GetObjectItem(json, "ipv6 Prefix");
		if (!prefix_json) {
			log_err("EAM entry #%u lacks an 'ipv6 prefix' field.", i);
			error = -EINVAL;
			goto end;
		}
		error = str_to_prefix6(prefix_json->valuestring, &eam.prefix6);
		if (error) {
			log_err("Error found on EAM entry #%u.", i);
			goto end;
		}

		prefix_json = cJSON_GetObjectItem(json, "ipv4 Prefix");
		if (!prefix_json) {
			log_err("EAM entry #%u lacks an 'ipv4 prefix' field.", i);
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

	buffer = buffer_alloc(section);
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

static int parse_max_iterations(struct cJSON *node,
		struct pool4_entry_usr *entry)
{
	int error = 0;

	switch (node->type) {
	case cJSON_Number:
		error = validate_json_uint(OPTNAME_MAX_ITERATIONS, node, 1,
				MAX_U32);
		if (error)
			return error;
		entry->flags = ITERATIONS_SET;
		entry->iterations = node->valueuint;
		break;
	case cJSON_String:
		if (strcmp(node->valuestring, "auto") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_AUTO;
			entry->iterations = 0;
		} else if (strcmp(node->valuestring, "infinity") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_INFINITE;
			entry->iterations = 0;
			return 0;
		} else {
			log_err("Unrecognized string: '%s'", node->valuestring);
			error = -EINVAL;
		}
		break;
	default:
		print_datatype_error(OPTNAME_MAX_ITERATIONS, node,
				"string or number");
		error = -EINVAL;
	}

	return error;
}

static int handle_pool4(cJSON *json)
{
	struct nl_buffer *buffer;
	struct cJSON *child;
	struct pool4_entry_usr entry;
	unsigned int i = 1;
	int error;

	if (!json)
		return 0;

	buffer = buffer_alloc(SEC_POOL4);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next, i++) {
		child = cJSON_GetObjectItem(json, OPTNAME_MARK);
		if (child) {
			error = validate_u32(OPTNAME_MARK, child);
			if (error)
				goto end;
			entry.mark = child->valueuint;
		} else {
			entry.mark = 0;
		}

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
		error = str_to_prefix4(child->valuestring, &entry.range.prefix);
		if (error)
			goto end;

		child = cJSON_GetObjectItem(json, "port range");
		if (child) {
			error = str_to_port_range(child->valuestring,
					&entry.range.ports);
			if (error)
				goto end;
		} else {
			entry.range.ports.min = DEFAULT_POOL4_MIN_PORT;
			entry.range.ports.max = DEFAULT_POOL4_MAX_PORT;
		}

		child = cJSON_GetObjectItem(json, OPTNAME_MAX_ITERATIONS);
		if (child) {
			error = parse_max_iterations(child, &entry);
			if (error)
				goto end;
		} else {
			entry.iterations = 0;
			entry.flags = 0;
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
	/*
	 * xTODO (wontfix) <- The x prevents Eclipse from indexing this to-do.
	 *
	 * It seems like it's impossible to support this without slowing
	 * important BIB/session operations about an order of magnitude down.
	 * The BIB/session module is already pretty freaking dense already, too.
	 * It really doesn't want more constraints.
	 *
	 * The core of the issue is that, unlike the other databases, BIB is a
	 * uniform blend between preconfigured stuff (static BIB entries) and
	 * dynamic stuff (dynamic BIB entries and sessions). There is no atomic
	 * way to replace *only* the preconfigured stuff.
	 *
	 * Atomic static BIB entries are also hardly critical so this is going
	 * to be postponed indefinitely until somebody gets miraculously
	 * enlightened.
	 *
	 * I'm not getting my hopes up.
	 */
	log_err("Sorry; BIB atomic configuration is not implemented.");
	return -EINVAL;
}
