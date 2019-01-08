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

struct json_meta {
	char *name; /* This being NULL signals the end of the array. */
	/* Second argument is @arg1 and third argument is @arg2. */
	int (*handler)(cJSON *, void *, void *);
	void *arg1;
	void *arg2;
	bool mandatory;
	bool already_found;
};

/*
 * =================================
 * ======== Error functions ========
 * =================================
 */

static int duplicates_found(char *name)
{
	log_err("Multiple '%s' tags found. Aborting...", name);
	return -EEXIST;
}

static int missing_tag(char *parent, char *child)
{
	log_err("Object '%s' is missing the '%s' child.",
			parent ? parent : "<unnamed>", child);
	return -EINVAL;
}

static int type_mismatch(char const *field, cJSON *json, char const *expected)
{
	if (!field)
		field = "<unnamed>";

	switch (json->type) {
	case cJSON_False:
		log_err("The '%s' element 'false' is not a valid %s.",
				field, expected);
		break;
	case cJSON_True:
		log_err("The '%s' element 'true' is not a valid %s.",
				field, expected);
		break;
	case cJSON_NULL:
		log_err("The '%s' element 'null' is not a valid %s.",
				field, expected);
		break;
	case cJSON_Number:
		if (json->numflags & VALUENUM_UINT)
			log_err("The '%s' element '%u' is not a valid %s.",
					field, json->valueuint, expected);
		else if (json->numflags & VALUENUM_INT)
			log_err("The '%s' element '%d' is not a valid %s.",
					field, json->valueint, expected);
		else
			log_err("The '%s' element '%f' is not a valid %s.",
					field, json->valuedouble, expected);
		break;
	case cJSON_String:
		log_err("The '%s' element '%s' is not a valid %s.",
				field, json->valuestring, expected);
		break;
	case cJSON_Array:
		log_err("The '%s' element appears to be an array, not a '%s'.",
				field, expected);
		break;
	case cJSON_Object:
		log_err("The '%s' element appears to be an object, not a '%s'.",
				field, expected);
		break;
	}

	if (strcmp(expected, "boolean") == 0 || strcmp(expected, "int") == 0)
		log_err("(Note: Quotation marks might also be the problem.)");

	return -EINVAL;
}

static int string_expected(const char *field, cJSON *json)
{
	return type_mismatch(field, json, "String");
}

/*
 * =================================
 * ============= Utils =============
 * =================================
 */

static bool tagname_equals(cJSON *json, char *name)
{
	return strcasecmp(json->string, name) == 0;
}

static int validate_uint(char *field_name, cJSON *node,
		__u64 min, __u64 max)
{
	if (node->type != cJSON_Number || !(node->numflags & VALUENUM_UINT))
		return type_mismatch(field_name, node, "unsigned integer");

	if (node->valueuint < min || max < node->valueuint) {
		log_err("%s %u is out of range (%llu-%llu).", field_name,
				node->valueuint, min, max);
		return -EINVAL;
	}

	return 0;
}

/*
 * =================================
 * ========= Netlink Buffer ========
 * =================================
 */

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

/*
 * ==================================
 * ===== Generic object handlers ====
 * ==================================
 */

static int handle_child(struct cJSON *child, struct json_meta *metadata)
{
	struct json_meta *meta;

	if (tagname_equals(child, "comment"))
		return 0;

	for (meta = metadata; meta->name; meta++) {
		if (tagname_equals(child, meta->name)) {
			if (meta->already_found)
				return duplicates_found(meta->name);
			meta->already_found = true;
			return meta->handler(child, meta->arg1, meta->arg2);
		}
	}

	log_err("Unknown tag: '%s'", child->string);
	return -EINVAL;
}

static int handle_object(cJSON *obj, struct json_meta *metadata)
{
	struct json_meta *meta;
	cJSON *child;
	int error;

	if (obj->type != cJSON_Object)
		return type_mismatch(obj->string, obj, "Object");

	for (child = obj->child; child; child = child->next) {
		error = handle_child(child, metadata);
		if (error)
			return error;
	}

	for (meta = metadata; meta->name; meta++)
		if (meta->mandatory && !meta->already_found)
			return missing_tag(obj->string, meta->name);

	return 0;
}

static int handle_array(cJSON *json, char *name, enum parse_section section,
		int (*entry_handler)(cJSON *, struct nl_buffer *))
{
	struct nl_buffer *buffer;
	unsigned int i;
	int error;

	if (json->type != cJSON_Array)
		return type_mismatch(name, json, "Array");

	buffer = buffer_alloc(section);
	if (!buffer)
		return -ENOMEM;

	for (json = json->child, i = 1; json; json = json->next, i++) {
		error = entry_handler(json, buffer);
		if (error) {
			log_err("Error found on %s entry #%u.", name, i);
			goto end;
		}
	}

	error = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return error;
}

/*
 * =================================
 * == Message writing for globals ==
 * =================================
 */

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

	return type_mismatch(field->name, json, "boolean");
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

static int write_timeout(struct global_field *field, cJSON *json, void *payload)
{
	__u32 value;
	int error;

	if (json->type != cJSON_String)
		return string_expected(field->name, json);

	error = str_to_timeout(json->valuestring, &value, field->min,
			field->max);
	if (error)
		return error;

	memcpy(payload, &value, sizeof(value));
	return 0;
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

static int write_others(struct global_field *field, cJSON *json, void *payload)
{
	if (json->type == cJSON_NULL)
		return field->type->parse(field, "null", payload);
	if (json->type == cJSON_String)
		return field->type->parse(field, json->valuestring, payload);

	return type_mismatch(field->name, json, field->type->name);
}

/*
 * =================================
 * ======= Global tag handler ======
 * =================================
 */

static int write_global(struct cJSON *json, void *_field, void *buffer)
{
	struct global_field *field = _field;
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
	case GTI_TIMEOUT:
		error = write_timeout(field, json, payload);
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

static int create_globals_meta(struct nl_buffer *buffer,
		struct json_meta **result)
{
	struct global_field *fields;
	unsigned int field_count;
	struct json_meta *meta;
	unsigned int i;

	get_global_fields(&fields, &field_count);

	meta = malloc(field_count * sizeof(struct json_meta) + 1);
	if (!meta) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	for (i = 0; i < field_count; i++) {
		meta[i].name = fields[i].name;
		meta[i].handler = write_global;
		meta[i].arg1 = &fields[i];
		meta[i].arg2 = buffer;
		meta[i].mandatory = false;
		meta[i].already_found = false;
	}
	meta[field_count].name = NULL;

	*result = meta;
	return 0;
}

static int handle_global(cJSON *json)
{
	struct nl_buffer *buffer;
	struct json_meta *meta;
	int error;

	buffer = buffer_alloc(SEC_GLOBAL);
	if (!buffer)
		return -ENOMEM;
	error = create_globals_meta(buffer, &meta);
	if (error)
		goto end2;

	error = handle_object(json, meta);
	if (error)
		goto end;

	error = nlbuffer_flush(buffer);
	/* Fall through. */
end:
	free(meta);
end2:
	nlbuffer_destroy(buffer);
	return error;
}

/*
 * =================================
 * === Parsers of database fields ==
 * =================================
 */

static int json2prefix6(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix6(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static int json2prefix4(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix4(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static int json2mark(cJSON *json, void *arg1, void *arg2)
{
	__u32 *mark = arg1;
	int error;

	error = validate_uint(json->string, json, 0, MAX_U32);
	if (error)
		return error;

	*mark = json->valueint;
	return 0;
}

static int json2port_range(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_port_range(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static int json2max_iterations(cJSON *json, void *arg1, void *arg2)
{
	struct pool4_entry_usr *entry = arg1;
	int error = 0;

	switch (json->type) {
	case cJSON_Number:
		error = validate_uint(OPTNAME_MAX_ITERATIONS, json, 1, MAX_U32);
		if (error)
			return error;
		entry->flags = ITERATIONS_SET;
		entry->iterations = json->valueuint;
		break;
	case cJSON_String:
		if (strcmp(json->valuestring, "auto") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_AUTO;
			entry->iterations = 0;
		} else if (strcmp(json->valuestring, "infinity") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_INFINITE;
			entry->iterations = 0;
			return 0;
		} else {
			log_err("Unrecognized string: '%s'", json->valuestring);
			error = -EINVAL;
		}
		break;
	default:
		error = type_mismatch(OPTNAME_MAX_ITERATIONS, json,
				"string or number");
	}

	return error;
}

static int json2taddr6(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_addr6_port(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static int json2taddr4(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_addr4_port(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static int json2proto(cJSON *json, void *arg1, void *arg2)
{
	l4_protocol proto;

	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	proto = str_to_l4proto(json->valuestring);
	if (proto == L4PROTO_OTHER) {
		log_err("Protocol '%s' is unknown.", json->valuestring);
		return -EINVAL;
	}

	*((__u8 *)arg1) = proto;
	return 0;
}

/*
 * =================================
 * ===== Database tag handlers =====
 * =================================
 */

static int handle_eam_entry(cJSON *json, struct nl_buffer *buffer)
{
	struct eamt_entry eam;
	struct json_meta meta[] = {
		{ "ipv6 prefix", json2prefix6, &eam.prefix6, NULL, true },
		{ "ipv4 prefix", json2prefix4, &eam.prefix4, NULL, true },
		{ NULL },
	};
	int error;

	error = handle_object(json, meta);
	if (error)
		return error;

	return buffer_write(buffer, SEC_EAMT, &eam, sizeof(eam));
}

static int handle_blacklist_entry(cJSON *json, struct nl_buffer *buffer)
{
	struct ipv4_prefix prefix;
	int error;

	if (json->type != cJSON_String)
		return string_expected("blacklist entry", json);

	error = str_to_prefix4(json->valuestring, &prefix);
	if (error)
		return error;

	return buffer_write(buffer, SEC_BLACKLIST, &prefix, sizeof(prefix));
}

static int handle_pool4_entry(cJSON *json, struct nl_buffer *buffer)
{
	struct pool4_entry_usr entry;
	struct json_meta meta[] = {
		{ OPTNAME_MARK, json2mark, &entry.mark, NULL, false },
		{ "protocol", json2proto, &entry.proto, NULL, true },
		{ "prefix", json2prefix4, &entry.range.prefix, NULL, true },
		{ "port range", json2port_range, &entry.range.ports, NULL, false },
		{ OPTNAME_MAX_ITERATIONS, json2max_iterations, &entry, NULL, false },
		{ NULL },
	};
	int error;

	entry.mark = 0;
	entry.range.ports.min = DEFAULT_POOL4_MIN_PORT;
	entry.range.ports.max = DEFAULT_POOL4_MAX_PORT;
	entry.iterations = 0;
	entry.flags = 0;

	error = handle_object(json, meta);
	if (error)
		return error;

	return buffer_write(buffer, SEC_POOL4, &entry, sizeof(entry));
}

static int handle_bib_entry(cJSON *json, struct nl_buffer *buffer)
{
	struct bib_entry_usr entry;
	struct json_meta meta[] = {
		{ "ipv6 address", json2taddr6, &entry.addr6, NULL, true },
		{ "ipv4 address", json2taddr4, &entry.addr4, NULL, true },
		{ "protocol", json2proto, &entry.l4_proto, NULL, true },
		{ NULL },
	};
	int error;

	entry.is_static = true;

	error = handle_object(json, meta);
	if (error)
		return error;

	return buffer_write(buffer, SEC_BIB, &entry, sizeof(entry));
}

/*
 * ==========================================
 * = Second level tag handlers, second pass =
 * ==========================================
 */

static int do_nothing(cJSON *json, void *arg1, void *arg2)
{
	return 0;
}

static int handle_global_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_global(json);
}

static int handle_eamt_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_EAMT, SEC_EAMT, handle_eam_entry);
}

static int handle_bl4_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_BLACKLIST, SEC_BLACKLIST,
			handle_blacklist_entry);
}

static int handle_pool4_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_POOL4, SEC_POOL4, handle_pool4_entry);
}

static int handle_bib_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_BIB, SEC_BIB, handle_bib_entry);
}

/*
 * ==================================
 * = Root tag handlers, second pass =
 * ==================================
 */

static int parse_siit_json(cJSON *json)
{
	struct json_meta meta[] = {
		/* instance and framework were already handled. */
		{ OPTNAME_INAME, do_nothing, NULL, NULL, true },
		{ OPTNAME_FW, do_nothing, NULL, NULL, true },
		{ OPTNAME_GLOBAL, handle_global_tag, NULL, NULL, false },
		{ OPTNAME_EAMT, handle_eamt_tag, NULL, NULL, false },
		{ OPTNAME_BLACKLIST, handle_bl4_tag, NULL, NULL, false },
		{ NULL },
	};

	return handle_object(json, meta);
}

static int parse_nat64_json(cJSON *json)
{
	struct json_meta meta[] = {
		/* instance and framework were already handled. */
		{ OPTNAME_INAME, do_nothing, NULL, NULL, true },
		{ OPTNAME_FW, do_nothing, NULL, NULL, true },
		{ OPTNAME_GLOBAL, handle_global_tag, NULL, NULL, false },
		{ OPTNAME_POOL4, handle_pool4_tag, NULL, NULL, false },
		{ OPTNAME_BIB, handle_bib_tag, NULL, NULL, false },
		{ NULL },
	};

	return handle_object(json, meta);
}

/*
 * =========================================
 * = Second level tag handlers, first pass =
 * =========================================
 */

static int handle_instance_tag(cJSON *json, void *_iname, void *arg2)
{
	int error;

	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	error = iname_validate(json->valuestring, false);
	if (error)
		return error;
	if (_iname && strcmp(_iname, json->valuestring) != 0) {
		log_err("The -i command line argument (%s) does not match the instance name defined in the file (%s).\n"
				"You might want to delete one of them.",
				(char *)_iname, json->valuestring);
		return -EINVAL;
	}

	iname = json->valuestring;
	return 0;
}

static int handle_framework_tag(cJSON *json, void *arg1, void *arg2)
{
	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	if (STR_EQUAL(json->valuestring, "netfilter")) {
		fw |= FW_NETFILTER;
		return 0;
	} else if (STR_EQUAL(json->valuestring, "iptables")) {
		fw |= FW_IPTABLES;
		return 0;
	}

	log_err("Unknown framework: '%s'", json->valuestring);
	return -EINVAL;
}

/*
 * ================================
 * = Root tag handler, first pass =
 * ================================
 */

/*
 * Sets the @iname and @fw global variables according to @_iname and @json.
 */
static int prepare_instance(char *_iname, cJSON *json)
{
	struct json_meta meta[] = {
		{ OPTNAME_INAME, handle_instance_tag, _iname, NULL, false },
		{ OPTNAME_FW, handle_framework_tag, NULL, NULL, true },
		/* The rest will be handled later. */
		{ OPTNAME_GLOBAL, do_nothing },
		{ OPTNAME_EAMT, do_nothing },
		{ OPTNAME_BLACKLIST, do_nothing },
		{ OPTNAME_POOL4, do_nothing },
		{ OPTNAME_BIB, do_nothing },
		{ NULL },
	};
	int error;

	iname = NULL;
	fw = 0;

	/*
	 * We want to be a little lenient if the user defines both -i and the
	 * instance tag. Normally, we would complain about the duplication, but
	 * we don't want to return negative reinforcement if the user is simply
	 * used to input -i and the strings are the same. This would only be
	 * irritating.
	 * So don't do `iname = _iname` yet.
	 */
	error = iname_validate(_iname, true);
	if (error)
		return error;

	error = handle_object(json, meta);
	if (error)
		return error;

	if (!iname && !_iname)
		return missing_tag("root", OPTNAME_INAME);
	if (!iname)
		iname = _iname;

	return 0;
}

/*
 * =================================
 * ======== Outer functions ========
 * =================================
 */

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

static int do_parsing(char *iname, char *buffer)
{
	int error;

	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
		log_err("The JSON parser got confused around the beginning of this string:");
		log_err("%s", cJSON_GetErrorPtr());
		return -EINVAL;
	}

	error = prepare_instance(iname, json);
	if (error)
		return error;

	error = send_ctrl_msg(SEC_INIT);
	if (error)
		return error;

	error = xlat_is_siit() ? parse_siit_json(json) : parse_nat64_json(json);
	if (error)
		return error;

	return send_ctrl_msg(SEC_COMMIT);
}

int parse_file(char *iname, char *file_name, bool _force)
{
	char *buffer;
	int error;

	force = _force;

	error = file_to_string(file_name, &buffer);
	if (error)
		return error;

	error = do_parsing(iname, buffer);
	free(buffer);
	return error;
}
