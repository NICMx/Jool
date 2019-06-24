#include "log.h"

int log_result(struct jool_result *result)
{
	int error = result->error;

	if (error)
		log_err("%s", result->msg);

	result_cleanup(result);
	return error;
}
