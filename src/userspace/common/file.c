#include "nat64/usr/file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "nat64/common/types.h"

/**
 * Remember to free @result when you're done.
 */
int file_to_string(char *file_name, char **result)
{
	FILE *file;
	long int length;
	long int total_read;
	size_t current_read;
	char *buffer;
	int error;

	file = fopen(file_name, "rb");
	if (!file) {
		perror("fopen() error");
		return -EINVAL;
	}

	error = fseek(file, 0, SEEK_END);
	if (error) {
		perror("fseek() 1 error");
		goto fail;
	}

	length = ftell(file);
	if (length == -1) {
		perror("ftell() error");
		error = length;
		goto fail;
	}

	error = fseek(file, 0, SEEK_SET);
	if (error) {
		perror("fseek() 2 error");
		goto fail;
	}

	buffer = malloc(length + 1);
	if (!buffer) {
		log_err("Out of memory.");
		error = -ENOMEM;
		goto fail;
	}

	total_read = 0;
	while (total_read < length) {
		current_read = fread(&buffer[total_read], 1, length, file);
		if (current_read == 0 && (error = ferror(file))) {
			log_err("Reading the file threw error code %d.", error);
			log_err("I don't know which is the correct way to stringify that code.");
			errno = error;
			perror("Let's try this one");
			free(buffer);
			goto fail;
		}

		total_read += current_read;
	}

	fclose(file);

	buffer[total_read] = '\0';
	*result = buffer;
	return 0;

fail:
	fclose(file);
	return error;
}
