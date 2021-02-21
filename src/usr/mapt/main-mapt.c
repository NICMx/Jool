#include "usr/argp/main.h"
#include "usr/argp/xlator_type.h"

int main(int argc, char **argv)
{
	xt_set(XT_MAPT);
	return jool_main(argc, argv);
}
