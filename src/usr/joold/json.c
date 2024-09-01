#include "usr/joold/json.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "usr/util/file.h"

static int pr_result(char const *filename, struct jool_result *result)
{
	int error = result->error;
	fprintf(stderr, "%s: %s\n", filename, result->msg);
	result_cleanup(result);
	return error;
}

int read_json(char const *filename, cJSON **out)
{
	char *file;
	cJSON *json;
	struct jool_result result;

	result = file_to_string(filename, &file);
	if (result.error)
		return pr_result(filename, &result);

	json = cJSON_Parse(file);
	if (!json) {
		fprintf(stderr, "%s: JSON syntax error.\n", filename);
		fprintf(stderr, "The JSON parser got confused around about here:\n");
		fprintf(stderr, "%s\n", cJSON_GetErrorPtr());
		free(file);
		return 1;
	}

	free(file);
	*out = json;
	return 0;
}

int json2str(char const *filename, cJSON *json, char const *key, char **dst)
{
	char *tmp;

	json = cJSON_GetObjectItem(json, key);
	if (!json)
		return 0;

	if (json->type != cJSON_String) {
		fprintf(stderr, "%s: Field '%s' is not a string.\n",
			filename, key);
		return EINVAL;
	}

	tmp = strdup(json->valuestring);
	if (!tmp)
		return ENOMEM;

	*dst = tmp;
	return 0;
}

int json2int(char const *filename, cJSON *json, char const *key, int *dst)
{
	json = cJSON_GetObjectItem(json, key);
	if (!json)
		return 0;

	if (!(json->numflags & VALUENUM_INT)) {
		fprintf(stderr, "%s: Field '%s' is not a valid integer.\n",
			filename, key);
		return EINVAL;
	}

	*dst = json->valueint;
	return 0;
}
