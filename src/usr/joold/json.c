#include "usr/joold/json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>

#include "usr/joold/log.h"
#include "usr/util/file.h"

int read_json(char const *filename, cJSON **out)
{
	char *file;
	cJSON *json;
	struct jool_result result;

	syslog(LOG_INFO, "Opening file %s...", filename);
	result = file_to_string(filename, &file);
	if (result.error)
		return pr_result(&result);

	json = cJSON_Parse(file);
	if (!json) {
		syslog(LOG_ERR, "JSON syntax error.");
		syslog(LOG_ERR, "The JSON parser got confused around about here:");
		syslog(LOG_ERR, "%s", cJSON_GetErrorPtr());
		free(file);
		return 1;
	}

	free(file);
	*out = json;
	return 0;
}

int json2str(cJSON *json, char const *key, char **dst)
{
	char *tmp;

	json = cJSON_GetObjectItem(json, key);
	if (!json)
		return 0;

	tmp = strdup(json->valuestring);
	if (tmp)
		return ENOMEM;

	*dst = tmp;
	return 0;
}

int json2int(cJSON *json, char const *key, int *dst)
{
	json = cJSON_GetObjectItem(json, key);
	if (!json)
		return 0;

	if (!(json->numflags & VALUENUM_INT)) {
		syslog(LOG_ERR, "%s '%s' is not a valid integer.", key,
			json->valuestring);
		return EINVAL;
	}

	*dst = json->valueint;
	return 0;
}
