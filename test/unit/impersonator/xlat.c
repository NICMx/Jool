#include "common/xlat.h"

xlator_type xlat_type(void)
{
#ifdef SIIT
	return XT_SIIT;
#else
	return XT_NAT64;
#endif
}

const char *xlat_get_name(void)
{
	return "Unit Test";
}
