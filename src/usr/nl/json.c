#include "json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "common/config.h"
#include "common/constants.h"
#include "common/globals.h"
#include "usr/util/cJSON.h"
#include "usr/util/file.h"
#include "usr/util/str_utils.h"

/* TODO (warning) These variables prevent this module from being thread-safe. */
static struct jool_socket sk;
static char *iname;
static jframework fw;
static bool force;

struct json_meta {
	char *name; /* This being NULL signals the end of the array. */
	/* Second argument is @arg1 and third argument is @arg2. */
	struct jool_result (*handler)(cJSON *, void *, void *);
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

static struct jool_result duplicates_found(char *name)
{
	return result_from_error(
		-EEXIST,
		"Multiple '%s' tags found. Aborting...", name
	);
}

static struct jool_result missing_tag(char *parent, char *child)
{
	return result_from_error(
		-EINVAL,
		"Object '%s' is missing the '%s' child.",
		parent ? parent : "<unnamed>", child
	);
}

static struct jool_result type_mismatch(char const *field, cJSON *json,
		char const *expected)
{
	if (!field)
		field = "<unnamed>";

	switch (json->type) {
	case cJSON_False:
		return result_from_error(
			-EINVAL,
			"The '%s' element 'false' is not a valid %s.",
			field, expected
		);
	case cJSON_True:
		return result_from_error(
			-EINVAL,
			"The '%s' element 'true' is not a valid %s.",
			field, expected
		);
	case cJSON_NULL:
		return result_from_error(
			-EINVAL,
			"The '%s' element 'null' is not a valid %s.",
			field, expected
		);
	case cJSON_Number:
		if (json->numflags & VALUENUM_UINT) {
			return result_from_error(
				-EINVAL,
				"The '%s' element '%u' is not a valid %s.",
				field, json->valueuint, expected
			);
		}

		if (json->numflags & VALUENUM_INT) {
			return result_from_error(
				-EINVAL,
				"The '%s' element '%d' is not a valid %s.",
				field, json->valueint, expected
			);
		}

		return result_from_error(
			-EINVAL,
			"The '%s' element '%f' is not a valid %s.",
			field, json->valuedouble, expected
		);

	case cJSON_String:
		return result_from_error(
			-EINVAL,
			"The '%s' element '%s' is not a valid %s.",
			field, json->valuestring, expected
		);
	case cJSON_Array:
		return result_from_error(
			-EINVAL,
			"The '%s' element appears to be an array, not a '%s'.",
			field, expected
		);
	case cJSON_Object:
		return result_from_error(
			-EINVAL,
			"The '%s' element appears to be an object, not a '%s'.",
			field, expected
		);
	}

	return result_from_error(
		-EINVAL,
		"The '%s' element has unknown type. (Expected a '%s'.)",
		field, expected
	);
}

static struct jool_result string_expected(const char *field, cJSON *json)
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

static struct jool_result validate_uint(char *field_name, cJSON *node,
		__u64 min, __u64 max)
{
	if (node->type != cJSON_Number || !(node->numflags & VALUENUM_UINT))
		return type_mismatch(field_name, node, "unsigned integer");

	if (node->valueuint < min || max < node->valueuint) {
		return result_from_error(
			-EINVAL,
			"%s %u is out of range (%llu-%llu).",
			field_name, node->valueuint, min, max
		);
	}

	return result_success();
}

/*
 * =================================
 * ========= Netlink Buffer ========
 * =================================
 */

static struct jool_result init_buffer(struct nl_buffer *buffer,
		enum parse_section section)
{
	struct request_hdr hdr;
	__u16 tmp = section;
	struct jool_result result;

	init_request_hdr(&hdr, MODE_PARSE_FILE, OP_ADD, force);
	result = nlbuffer_write(buffer, &hdr, sizeof(hdr));
	if (result.error)
		return result;

	return nlbuffer_write(buffer, &tmp, sizeof(tmp));
}

static struct jool_result buffer_alloc(enum parse_section section,
		struct nl_buffer **out)
{
	struct nl_buffer *buffer;
	struct jool_result result;

	buffer = nlbuffer_alloc(&sk, iname);
	if (!buffer)
		return result_from_enomem();

	result = init_buffer(buffer, section);
	if (result.error) {
		nlbuffer_destroy(buffer);
		return result;
	}

	*out = buffer;
	return result;
}

static struct jool_result buffer_write(struct nl_buffer *buffer,
		enum parse_section section, void *payload, size_t payload_len)
{
	struct jool_result result;

	result = nlbuffer_write(buffer, payload, payload_len);
	if (result.error != -ENOSPC)
		return result;

	result = nlbuffer_flush(buffer);
	if (result.error)
		return result;

	result = init_buffer(buffer, section);
	if (result.error)
		return result;

	return nlbuffer_write(buffer, payload, payload_len);
}

/*
 * ==================================
 * ===== Generic object handlers ====
 * ==================================
 */

static struct jool_result handle_child(struct cJSON *child,
		struct json_meta *metadata)
{
	struct json_meta *meta;

	if (tagname_equals(child, "comment"))
		return result_success();

	for (meta = metadata; meta->name; meta++) {
		if (tagname_equals(child, meta->name)) {
			if (meta->already_found)
				return duplicates_found(meta->name);
			meta->already_found = true;
			return meta->handler(child, meta->arg1, meta->arg2);
		}
	}

	return result_from_error(-EINVAL, "Unknown tag: '%s'", child->string);
}

static struct jool_result handle_object(cJSON *obj, struct json_meta *metadata)
{
	struct json_meta *meta;
	cJSON *child;
	struct jool_result result;

	if (obj->type != cJSON_Object)
		return type_mismatch(obj->string, obj, "Object");

	for (child = obj->child; child; child = child->next) {
		result = handle_child(child, metadata);
		if (result.error)
			return result;
	}

	for (meta = metadata; meta->name; meta++)
		if (meta->mandatory && !meta->already_found)
			return missing_tag(obj->string, meta->name);

	return result_success();
}

static struct jool_result handle_array(cJSON *json, char *name,
		enum parse_section section,
		struct jool_result (*entry_handler)(cJSON *, struct nl_buffer *))
{
	struct nl_buffer *buffer;
	unsigned int i;
	struct jool_result result;

	if (json->type != cJSON_Array)
		return type_mismatch(name, json, "Array");

	result = buffer_alloc(section, &buffer);
	if (result.error)
		return result;

	for (json = json->child, i = 1; json; json = json->next, i++) {
		result = entry_handler(json, buffer);
		if (result.error)
			goto end;
	}

	result = nlbuffer_flush(buffer);
	/* Fall through. */

end:
	nlbuffer_destroy(buffer);
	return result;
}

/*
 * =================================
 * == Message writing for globals ==
 * =================================
 */

static struct jool_result write_bool(struct global_field *field, cJSON *json,
		void *payload)
{
	config_bool cb_true = true;
	config_bool cb_false = false;

	switch (json->type) {
	case cJSON_True:
		memcpy(payload, &cb_true, sizeof(cb_true));
		return result_success();
	case cJSON_False:
		memcpy(payload, &cb_false, sizeof(cb_false));
		return result_success();
	}

	return type_mismatch(field->name, json, "boolean");
}

static struct jool_result write_u8(struct global_field *field, cJSON *json,
		void *payload)
{
	__u8 value;
	struct jool_result result;

	result = validate_uint(field->name, json, field->min, field->max);
	if (result.error)
		return result;

	value = json->valueuint;
	memcpy(payload, &value, sizeof(value));
	return result;
}

static struct jool_result write_u32(struct global_field *field, cJSON *json,
		void *payload)
{
	__u32 value;
	struct jool_result result;

	result = validate_uint(field->name, json, field->min, field->max);
	if (result.error)
		return result;

	value = json->valueuint;
	memcpy(payload, &value, sizeof(value));
	return result;
}

static struct jool_result write_timeout(struct global_field *field, cJSON *json,
		void *payload)
{
	__u32 value;
	struct jool_result result;

	if (json->type != cJSON_String)
		return string_expected(field->name, json);

	result = str_to_timeout(json->valuestring, &value, field->min,
			field->max);
	if (result.error)
		return result;

	memcpy(payload, &value, sizeof(value));
	return result;
}

static struct jool_result write_plateaus(struct global_field *field,
		cJSON *node, void *payload)
{
	struct mtu_plateaus *plateaus = payload;
	unsigned int i = 0;
	struct jool_result result;

	for (node = node->child; node; node = node->next) {
		if (i > PLATEAUS_MAX) {
			return result_from_error(
				-EINVAL,
				"Too many plateaus. (max is %u)", PLATEAUS_MAX
			);
		}

		result = validate_uint(field->name, node, 0, MAX_U16);
		if (result.error)
			return result;

		plateaus->values[i] = node->valueuint;
		i++;
	}

	plateaus->count = i;
	return result_success();
}

static struct jool_result write_others(struct global_field *field, cJSON *json,
		void *payload)
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

static struct jool_result write_field(struct global_field *field, struct cJSON *json, void *payload)
{
	/*
	 * TODO (fine) This does not scale well. We'll need a big refactor of
	 * the json module or use some other library.
	 */
	switch (field->type->id) {
	case GTI_BOOL:
		return write_bool(field, json, payload);
	case GTI_NUM8:
		return write_u8(field, json, payload);
	case GTI_NUM32:
		return write_u32(field, json, payload);
	case GTI_TIMEOUT:
		return write_timeout(field, json, payload);
	case GTI_PLATEAUS:
		return write_plateaus(field, json, payload);
	case GTI_PREFIX6:
	case GTI_PREFIX4:
	case GTI_HAIRPIN_MODE:
		return write_others(field, json, payload);
	}

	return result_from_error(
		-EINVAL,
		"Unknown field type: %u", field->type->id
	);
}

static struct jool_result write_global(struct cJSON *json, void *_field,
		void *buffer)
{
	struct global_field *field = _field;
	size_t size;
	struct global_value *hdr;
	struct jool_result result;

	size = sizeof(struct global_value) + field->type->size;
	hdr = malloc(size);
	if (!hdr)
		return result_from_enomem();

	hdr->type = global_field_index(field);
	hdr->len = field->type->size;

	result = write_field(field, json, hdr + 1);
	if (!result.error)
		result = buffer_write(buffer, SEC_GLOBAL, hdr, size);

	free(hdr);
	return result;
}

static struct jool_result create_globals_meta(struct nl_buffer *buffer,
		struct json_meta **globals_meta)
{
	struct global_field *fields;
	unsigned int field_count;
	struct json_meta *meta;
	unsigned int i;

	*globals_meta = NULL; /* Actually unneeded; shuts up gcc */
	get_global_fields(&fields, &field_count);

	meta = malloc(field_count * sizeof(struct json_meta) + 1);
	if (!meta)
		return result_from_enomem();

	for (i = 0; i < field_count; i++) {
		meta[i].name = fields[i].name;
		meta[i].handler = write_global;
		meta[i].arg1 = &fields[i];
		meta[i].arg2 = buffer;
		meta[i].mandatory = false;
		meta[i].already_found = false;
	}
	meta[field_count].name = NULL;

	*globals_meta = meta;
	return result_success();
}

static struct jool_result handle_global(cJSON *json)
{
	struct nl_buffer *buffer;
	struct json_meta *meta;
	struct jool_result result;

	result = buffer_alloc(SEC_GLOBAL, &buffer);
	if (result.error)
		return result;
	result = create_globals_meta(buffer, &meta);
	if (result.error)
		goto end2;

	result = handle_object(json, meta);
	if (result.error)
		goto end;

	result = nlbuffer_flush(buffer);
	/* Fall through. */
end:
	free(meta);
end2:
	nlbuffer_destroy(buffer);
	return result;
}

/*
 * =================================
 * === Parsers of database fields ==
 * =================================
 */

static struct jool_result json2prefix6(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix6(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static struct jool_result json2prefix4(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_prefix4(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static struct jool_result json2mark(cJSON *json, void *arg1, void *arg2)
{
	__u32 *mark = arg1;
	struct jool_result result;

	result = validate_uint(json->string, json, 0, MAX_U32);
	if (result.error)
		return result;

	*mark = json->valueint;
	return result;
}

static struct jool_result json2port_range(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_port_range(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static struct jool_result json2max_iterations(cJSON *json,
		void *arg1, void *arg2)
{
	struct pool4_entry_usr *entry = arg1;
	struct jool_result result;

	switch (json->type) {
	case cJSON_Number:
		result = validate_uint(OPTNAME_MAX_ITERATIONS, json, 1, MAX_U32);
		if (result.error)
			return result;
		entry->flags = ITERATIONS_SET;
		entry->iterations = json->valueuint;
		return result_success();

	case cJSON_String:
		if (strcmp(json->valuestring, "auto") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_AUTO;
			entry->iterations = 0;
			return result_success();
		}

		if (strcmp(json->valuestring, "infinity") == 0) {
			entry->flags = ITERATIONS_SET | ITERATIONS_INFINITE;
			entry->iterations = 0;
			return result_success();
		}

		return result_from_error(
			-EINVAL,
			"Unrecognized string: '%s'", json->valuestring
		);
	}

	return type_mismatch(OPTNAME_MAX_ITERATIONS, json, "string or number");
}

static struct jool_result json2taddr6(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_addr6_port(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static struct jool_result json2taddr4(cJSON *json, void *arg1, void *arg2)
{
	return (json->type == cJSON_String)
			? str_to_addr4_port(json->valuestring, arg1)
			: string_expected(json->string, json);
}

static struct jool_result json2proto(cJSON *json, void *arg1, void *arg2)
{
	l4_protocol proto;

	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	proto = str_to_l4proto(json->valuestring);
	if (proto == L4PROTO_OTHER) {
		return result_from_error(
			-EINVAL,
			"Protocol '%s' is unknown.", json->valuestring
		);
	}

	*((__u8 *)arg1) = proto;
	return result_success();
}

/*
 * =================================
 * ===== Database tag handlers =====
 * =================================
 */

static struct jool_result handle_eam_entry(cJSON *json,
		struct nl_buffer *buffer)
{
	struct eamt_entry eam;
	struct json_meta meta[] = {
		{ "ipv6 prefix", json2prefix6, &eam.prefix6, NULL, true },
		{ "ipv4 prefix", json2prefix4, &eam.prefix4, NULL, true },
		{ NULL },
	};
	struct jool_result result;

	result = handle_object(json, meta);
	if (result.error)
		return result;

	return buffer_write(buffer, SEC_EAMT, &eam, sizeof(eam));
}

static struct jool_result handle_blacklist_entry(cJSON *json,
		struct nl_buffer *buffer)
{
	struct ipv4_prefix prefix;
	struct jool_result result;

	if (json->type != cJSON_String)
		return string_expected("blacklist entry", json);

	result = str_to_prefix4(json->valuestring, &prefix);
	if (result.error)
		return result;

	return buffer_write(buffer, SEC_BLACKLIST, &prefix, sizeof(prefix));
}

static struct jool_result handle_pool4_entry(cJSON *json,
		struct nl_buffer *buffer)
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
	struct jool_result result;

	entry.mark = 0;
	entry.range.ports.min = DEFAULT_POOL4_MIN_PORT;
	entry.range.ports.max = DEFAULT_POOL4_MAX_PORT;
	entry.iterations = 0;
	entry.flags = 0;

	result = handle_object(json, meta);
	if (result.error)
		return result;

	return buffer_write(buffer, SEC_POOL4, &entry, sizeof(entry));
}

static struct jool_result handle_bib_entry(cJSON *json,
		struct nl_buffer *buffer)
{
	struct bib_entry_usr entry;
	struct json_meta meta[] = {
		{ "ipv6 address", json2taddr6, &entry.addr6, NULL, true },
		{ "ipv4 address", json2taddr4, &entry.addr4, NULL, true },
		{ "protocol", json2proto, &entry.l4_proto, NULL, true },
		{ NULL },
	};
	struct jool_result result;

	entry.is_static = true;

	result = handle_object(json, meta);
	if (result.error)
		return result;

	return buffer_write(buffer, SEC_BIB, &entry, sizeof(entry));
}

/*
 * ==========================================
 * = Second level tag handlers, second pass =
 * ==========================================
 */

static struct jool_result do_nothing(cJSON *json, void *arg1, void *arg2)
{
	return result_success();
}

static struct jool_result handle_global_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_global(json);
}

static struct jool_result handle_eamt_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_EAMT, SEC_EAMT, handle_eam_entry);
}

static struct jool_result handle_bl4_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_BLACKLIST, SEC_BLACKLIST,
			handle_blacklist_entry);
}

static struct jool_result handle_pool4_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_POOL4, SEC_POOL4, handle_pool4_entry);
}

static struct jool_result handle_bib_tag(cJSON *json, void *arg1, void *arg2)
{
	return handle_array(json, OPTNAME_BIB, SEC_BIB, handle_bib_entry);
}

/*
 * ==================================
 * = Root tag handlers, second pass =
 * ==================================
 */

static struct jool_result parse_siit_json(cJSON *json)
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

static struct jool_result parse_nat64_json(cJSON *json)
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

static struct jool_result handle_instance_tag(cJSON *json, void *_iname,
		void *arg2)
{
	int error;

	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	error = iname_validate(json->valuestring, false);
	if (error) {
		return result_from_error(
			error,
			INAME_VALIDATE_ERRMSG,
			INAME_MAX_LEN - 1
		);
	}
	if (_iname && strcmp(_iname, json->valuestring) != 0) {
		return result_from_error(
			-EINVAL,
			"The -i command line argument (%s) does not match the instance name defined in the file (%s).\n"
			"You might want to delete one of them.",
			(char *)_iname, json->valuestring
		);
	}

	iname = json->valuestring;
	return result_success();
}

static struct jool_result handle_framework_tag(cJSON *json,
		void *arg1, void *arg2)
{
	if (json->type != cJSON_String)
		return string_expected(json->string, json);

	if (STR_EQUAL(json->valuestring, "netfilter")) {
		fw |= FW_NETFILTER;
		return result_success();
	} else if (STR_EQUAL(json->valuestring, "iptables")) {
		fw |= FW_IPTABLES;
		return result_success();
	}

	return result_from_error(
		-EINVAL,
		"Unknown framework: '%s'", json->valuestring
	);
}

/*
 * ================================
 * = Root tag handler, first pass =
 * ================================
 */

/*
 * Sets the @iname and @fw global variables according to @_iname and @json.
 */
static struct jool_result prepare_instance(char *_iname, cJSON *json)
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
	struct jool_result result;

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
	result.error = iname_validate(_iname, true);
	if (result.error) {
		return result_from_error(
			result.error,
			INAME_VALIDATE_ERRMSG,
			INAME_MAX_LEN - 1
		);
	}

	result = handle_object(json, meta);
	if (result.error)
		return result;

	if (!iname && !_iname)
		return missing_tag("root", OPTNAME_INAME);
	if (!iname)
		iname = _iname;

	return result;
}

/*
 * =================================
 * ======== Outer functions ========
 * =================================
 */

static struct jool_result send_ctrl_msg(enum parse_section section)
{
	struct nl_buffer *buffer;
	struct request_init request;
	struct jool_result result;

	result = buffer_alloc(section, &buffer);
	if (result.error)
		return result;

	if (section == SEC_INIT) {
		request.fw = fw;
		result = buffer_write(buffer, section, &request, sizeof(request));
		if (result.error)
			goto end;
	}

	result = nlbuffer_flush(buffer);
	/* Fall through */

end:
	nlbuffer_destroy(buffer);
	return result;
}

static struct jool_result do_parsing(char *iname, char *buffer)
{
	struct jool_result result;

	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
		return result_from_error(
			-EINVAL,
			"The JSON parser got confused around the beginning of this string:\n"
			"%s", cJSON_GetErrorPtr()
		);
	}

	result = prepare_instance(iname, json);
	if (result.error)
		return result;

	result = send_ctrl_msg(SEC_INIT);
	if (result.error)
		return result;

	result = xlat_is_siit() ? parse_siit_json(json) : parse_nat64_json(json);
	if (result.error)
		return result;

	return send_ctrl_msg(SEC_COMMIT);
}

struct jool_result parse_file(struct jool_socket *_sk, char *iname,
		char *file_name, bool _force)
{
	char *buffer;
	struct jool_result result;

	sk = *_sk;
	force = _force;

	result = file_to_string(file_name, &buffer);
	if (result.error)
		return result;

	result = do_parsing(iname, buffer);
	free(buffer);
	return result;
}
