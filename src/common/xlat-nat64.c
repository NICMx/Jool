#include "common/xlat.h"

int xlat_type(void)
{
	return XT_NAT64;
}

const char *xlat_get_name(void)
{
	return "NAT64 Jool";
}
