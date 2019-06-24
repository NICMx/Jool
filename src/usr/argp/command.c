#include "command.h"

#include "common/xlat.h"

bool cmdopt_is_hidden(struct cmd_option *option)
{
	return option->hidden || !(xlat_type() & option->xt);
}
