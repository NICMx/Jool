#include "file.h"

#include <errno.h>
#include "log.h"
#include "netlink/file.h"

int handle_file_update(int argc, char **argv)
{
	if (argc != 2) {
		log_err("Expected only one argument (the file name).");
		return -EINVAL;
	}

	return file_update(argv[0]);
}
