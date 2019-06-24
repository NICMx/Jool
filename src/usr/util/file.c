#include "file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Remember to free @result when you're done.
 */
struct jool_result file_to_string(char *file_name, char **out)
{
	FILE *file;
	long int length;
	long int total_read;
	size_t current_read;
	char *buffer;
	int error;

	file = fopen(file_name, "rb");
	if (!file)
		return result_from_errno(errno, "fopen");

	error = fseek(file, 0, SEEK_END);
	if (error) {
		error = errno;
		fclose(file);
		return result_from_errno(error, "fseek1");
	}

	length = ftell(file);
	if (length == -1) {
		error = errno;
		fclose(file);
		return result_from_errno(error, "ftell");
	}

	error = fseek(file, 0, SEEK_SET);
	if (error) {
		error = errno;
		fclose(file);
		return result_from_errno(error, "fseek2");
	}

	buffer = malloc(length + 1);
	if (!buffer) {
		fclose(file);
		return result_from_enomem();
	}

	total_read = 0;
	while (total_read < length) {
		current_read = fread(&buffer[total_read], 1, length, file);
		if (current_read == 0 && ferror(file)) {
			free(buffer);
			fclose(file);
			/* There's literally no way to get an error code. */
			return result_from_errno(-EINVAL, "fread");
		}

		total_read += current_read;
	}

	fclose(file);

	buffer[total_read] = '\0';
	*out = buffer;
	return result_success();
}
