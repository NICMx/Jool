#ifndef SRC_USERSPACE_CLIENT_REQUIREMENTS_H_
#define SRC_USERSPACE_CLIENT_REQUIREMENTS_H_

#include <stdbool.h>

struct requirement {
	bool set;
	char *what;
};

int requirement_print(struct requirement *reqs);

#endif /* SRC_USERSPACE_CLIENT_REQUIREMENTS_H_ */
