#include <limits.h>
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/cJSON.h"

int parse_bool_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * configured_flag, __u8  * out_value)
{
	int error = 0;
	cJSON * read_value = cJSON_GetObjectItem(json_object, parameter_name) ;

	*configured_flag = 0;

	if (read_value) {
		error = str_to_bool(read_value->valuestring,out_value) ;
		*configured_flag = 1;

		if (error) {
			log_err("%s, not valid!. %s: %s", parameter_name, section,read_value->valuestring);
			return error;
		}
	}

	return 0;
}

int parse_u8_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * configured_flag, __u8 * out_value)
{
	int error = 0;
	cJSON * read_value = cJSON_GetObjectItem(json_object, parameter_name) ;

	*configured_flag = 0;

	if (read_value) {
		error = str_to_u8(read_value->valuestring,out_value,0,255);
		*configured_flag = 1;
		if (error) {
			log_err("%s, not valid!. %s: %s", parameter_name, section,read_value->valuestring);
			return error;
		}
	}

	return 0;
}

int parse_u16_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * configured_flag, __u16 * out_value)
{
	int error = 0;

	cJSON * read_value = cJSON_GetObjectItem(json_object, parameter_name) ;
	*configured_flag = 0;

	if (read_value) {
		error = str_to_u16(read_value->valuestring,out_value,0,65534) ;
		*configured_flag = 1;
		if (error) {
			log_err("%s, not valid!. %s: %s", parameter_name, section,read_value->valuestring);
			return error;
		}
	}


	return error;
}

int parse_u64_parameter(cJSON * json_object, char * parameter_name,char * section, __u8 * configured_flag, __u64 * out_value)
{
	int error = 0;
	cJSON * read_value = cJSON_GetObjectItem(json_object, parameter_name) ;

	*configured_flag = 0;

	if (read_value) {
		error = str_to_u64(read_value->valuestring,out_value,0,UINT_MAX) ;
		*configured_flag = 1;
		if (error) {
			log_err("%s, not valid!. %s: %s", parameter_name, section,read_value->valuestring);
			return error;
		}
	}

	return 0;
}
