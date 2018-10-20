#include "usr/common/nl/json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "common/config.h"
#include "common/constants.h"
#include "common/types.h"
#include "usr/common/cJSON.h"
#include "usr/common/file.h"
#include "usr/common/netlink.h"
#include "usr/common/str_utils.h"
#include "usr/common/nl/buffer.h"
#include "usr/common/nl/global.h"

/*
 * Note: These variables prevent this module from being thread-safe.
 * This is fine for now.
 */
static char *iname;
static jframework fw;
static bool force;

static int do_parsing(char *buffer);
static int parse_siit_json(cJSON *json);
static int parse_nat64_json(cJSON *json);
static int handle_global(cJSON *json, bool *globals_found);
static int handle_eamt(cJSON *json);
static int handle_blacklist(cJSON *json);
static int handle_pool4(cJSON *pool4);
static int handle_bib(cJSON *bib);

int parse_file(char *file_name, bool _force)
{
	char *buffer;
	int error;

	force = _force;

	error = file_to_string(file_name, &buffer);
	if (error)
		return error;

	error = do_parsing(buffer);
	free(buffer);
	return error;
}

/*
 * Sets the @iname global variable according to the contents of @json.
 */
static int prepare_instance(cJSON *json)
{
	int error;

	iname = NULL;
	fw = 0;

	for (json = json->child; json; json = json->next) {
		if (strcasecmp(OPTNAME_INAME, json->string) == 0) {
			if (iname)
				goto iname_exists;
			error = iname_validate(json->valuestring, false);
			if (error)
				return error;

			iname = json->valuestring;
		}

		if (strcasecmp(OPTNAME_FW, json->string) == 0) {
			if (fw)
				goto fw_exists;
			if (STR_EQUAL(json->valuestring, "netfilter"))
				fw |= FW_NETFILTER;
			else if (STR_EQUAL(json->valuestring, "iptables"))
				fw |= FW_IPTABLES;
			else
				goto unknown_fw;
		}

		/*
		 * Keep iterating; we want to error if the user defined
		 * something twice.
		 */
	}

	if (!iname) {
		log_err("The file is missing the '%s' tag.", OPTNAME_INAME);
		return -EINVAL;
	}
	if (!fw) {
		log_err("The file is missing the '%s' tag.", OPTNAME_FW);
		return -EINVAL;
	}

	return 0;

iname_exists:
	log_err("Multiple '%s's found; Aborting.", OPTNAME_INAME);
	return -EEXIST;
fw_exists:
	log_err("Multiple '%s's found; Aborting.", OPTNAME_FW);
	return -EEXIST;
unknown_fw:
	log_err("Unknown framework: '%s'", json->valuestring);
	return -EINVAL;
}

static int print_type_error(char const *field, cJSON *json,
		char const *expected)
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

static int validate_uint(char *field_name, cJSON *node,
		__u64 min, __u64 max)
{
	if (node->type != cJSON_Number || !(node->numflags & VALUENUM_UINT))
		return print_type_error(field_name, node, "unsigned integer");

	if (node->valueuint < min || max < node->valueuint) {
		log_err("%s %u is out of range (%llu-%llu).", field_name,
				node->valueuint, min, max);
		return -EINVAL;
	}

	return 0;
}

static void check_duplicates(bool *found, char *section)
{
	if (*found)
		log_info("Note: I found multiple '%s' sections.", section);
	*found = true;
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

	error = prepare_instance(json);
	if (error)
		return error;

	return xlat_is_siit() ? parse_siit_json(json) : parse_nat64_json(json);
}

static int init_buffer(struct nl_buffer *buffer, enum parse_section section)
{
	struct request_hdr hdr;
	__u16 tmp = section;
	int error;

	init_request_hdr(&hdr, MODE_PARSE_FILE, OP_ADD, force);
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

	buffer = nlbuffer_alloc(iname);
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

static int buffer_write(struct nl_buffer *buffer, enum parse_section section,
		void *payload, size_t payload_len)
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
	struct request_init request;
	int error;

	buffer = buffer_alloc(section);
	if (!buffer)
		return -ENOMEM;

	if (section == SEC_INIT) {
		request.fw = fw;
		error = buffer_write(buffer, section, &request, sizeof(request));
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static bool *create_globals_found_array(void)
{
	unsigned int field_count;
	get_global_fields(NULL, &field_count);
	return calloc(field_count, sizeof(bool));
}

static int parse_siit_json(cJSON *json)
{
	bool global_found = false;
	bool eamt_found = false;
	bool blacklist_found = false;
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
		} else if (strcasecmp(OPTNAME_EAMT, json->string) == 0) {
			check_duplicates(&eamt_found, OPTNAME_EAMT);
			error = handle_eamt(json);
		} else if (strcasecmp(OPTNAME_BLACKLIST, json->string) == 0) {
			check_duplicates(&blacklist_found, OPTNAME_BLACKLIST);
			error = handle_blacklist(json);
		} else if (strcasecmp(OPTNAME_INAME, json->string) == 0) {
			/* No code. */
		} else if (strcasecmp(OPTNAME_FW, json->string) == 0) {
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
		} else if (strcasecmp(OPTNAME_POOL4, json->string) == 0) {
			check_duplicates(&pool4_found, OPTNAME_POOL4);
			error = handle_pool4(json);
		} else if (strcasecmp(OPTNAME_BIB, json->string) == 0) {
			check_duplicates(&bib_found, OPTNAME_BIB);
			error = handle_bib(json);
		} else if (strcasecmp(OPTNAME_INAME, json->string) == 0) {
			/* No code. */
		} else if (strcasecmp(OPTNAME_FW, json->string) == 0) {
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

static int write_bool(struct global_field *field, cJSON *json, void *payload)
{
	config_bool cb_true = true;
	config_bool cb_false = false;

	switch (json->type) {
	case cJSON_True:
		memcpy(payload, &cb_true, sizeof(cb_true));
		return 0;
	case cJSON_False:
		memcpy(payload, &cb_false, sizeof(cb_false));
		return 0;
	}

	return print_type_error(field->name, json, "boolean");
}

static int write_u8(struct global_field *field, cJSON *json, void *payload)
{
	__u8 value;
	int error;

	error = validate_uint(field->name, json, field->min, field->max);
	if (error)
		return error;

	value = json->valueuint;
	memcpy(payload, &value, sizeof(value));
	return 0;
}

static int write_u32(struct global_field *field, cJSON *json, void *payload)
{
	__u32 value;
	int error;

	error = validate_uint(field->name, json, field->min, field->max);
	if (error)
		return error;

	value = json->valueuint;
	memcpy(payload, &value, sizeof(value));
	return 0;
}

static int write_others(struct global_field *field, cJSON *json, void *payload)
{
	if (json->type == cJSON_NULL)
		return field->type->parse(field, "null", payload);
	if (json->type == cJSON_String)
		return field->type->parse(field, json->valuestring, payload);

	return print_type_error(field->name, json, field->type->name);
}

static int write_plateaus(struct global_field *field, cJSON *node, void *payload)
{
	struct mtu_plateaus *plateaus = payload;
	unsigned int i = 0;
	int error;

	for (node = node->child; node; node = node->next) {
		if (i > PLATEAUS_MAX) {
			log_err("Too many plateaus. (max is %u)", PLATEAUS_MAX);
			return -EINVAL;
		}

		error = validate_uint(field->name, node, 0, MAX_U16);
		if (error)
			return error;

		plateaus->values[i] = node->valueuint;
		i++;
	}

	plateaus->count = i;
	return 0;
}

static int write_field(cJSON *json, struct global_field *field,
		struct nl_buffer *buffer)
{
	size_t size;
	struct global_value *hdr;
	void *payload;
	int error = -EINVAL;

	size = sizeof(struct global_value) + field->type->size;
	hdr = malloc(size);
	if (!hdr)
		return -ENOMEM;
	payload = hdr + 1;

	hdr->type = global_field_index(field);
	hdr->len = field->type->size;

	/*
	 * TODO This does not scale well. We'll need a big refactor of the json
	 * module or use some other library.
	 */
	switch (field->type->id) {
	case GTI_BOOL:
		error = write_bool(field, json, payload);
		break;
	case GTI_NUM8:
		error = write_u8(field, json, payload);
		break;
	case GTI_NUM32:
		error = write_u32(field, json, payload);
		break;
	case GTI_PLATEAUS:
		error = write_plateaus(field, json, payload);
		break;
	case GTI_PREFIX6:
	case GTI_PREFIX4:
	case GTI_HAIRPIN_MODE:
		error = write_others(field, json, payload);
		break;
	}

	if (!error)
		error = buffer_write(buffer, SEC_GLOBAL, hdr, size);

	free(hdr);
	return error;
}

static int handle_global_field(cJSON *json, struct nl_buffer *buffer,
		bool *globals_found)
{
	struct global_field *fields;
	unsigned int i;
	int error;

	get_global_fields(&fields, NULL);

	for (i = 0; fields[i].name; i++) {
		if (STR_EQUAL(json->string, fields[i].name)) {
			error = write_field(json, &fields[i], buffer);
			if (globals_found[i])
				log_info("Note: I found multiple '%s' definitions.",
						fields[i].name);
			globals_found[i] = true;
			return error;
		}
	}

	log_err("Unknown global configuration field: %s", json->string);
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

		error = buffer_write(buffer, SEC_EAMT, &eam, sizeof(eam));
		if (error)
			goto end;
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

static int handle_blacklist(cJSON *json)
{
	struct nl_buffer *buffer;
	struct ipv4_prefix prefix;
	int error;

	if (!json)
		return 0;

	buffer = buffer_alloc(SEC_BLACKLIST);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child; json; json = json->next) {
		error = str_to_prefix4(json->valuestring, &prefix);
		if (error)
			goto end;
		error = buffer_write(buffer, SEC_BLACKLIST,
				&prefix, sizeof(prefix));
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
		error = validate_uint(OPTNAME_MAX_ITERATIONS, node, 1, MAX_U32);
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
		print_type_error(OPTNAME_MAX_ITERATIONS, node,
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
			error = validate_uint(OPTNAME_MARK, child, 0, MAX_U32);
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

		error = buffer_write(buffer, SEC_POOL4, &entry, sizeof(entry));
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
