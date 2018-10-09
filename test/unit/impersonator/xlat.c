#include "common/xlat.h"

bool xlat_is_siit(void)
{
#ifdef SIIT
	return true;
#else
	return false;
#endif
}

const char *xlat_get_name(void)
{
	return "Unit Test";
}
