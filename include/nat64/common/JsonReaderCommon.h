#ifndef JSONREADERCOMMON_H_
#define JSONREADERCOMMON_H_


int parse_bool_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * out_was_null, __u8  * out_value);

int parse_u8_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * out_was_null, __u8 * out_value);

int parse_u16_parameter(cJSON * json_object, char * parameter_name, char * section, __u8 * out_was_null, __u16 * out_value);

int parse_u64_parameter(cJSON * json_object, char * parameter_name,char * section, __u8 * out_was_null, __u64 * out_value);


#endif /* JSONREADERCOMMON_H_ */
