#ifndef _JOOL_COMM_NAT64_H
#define _JOOL_COMM_NAT64_H

/**
 * @file
 * Extremely general global stuff.
 *
 * @author Alberto Leiva
 */


#define MODULE_NAME "Jool"


/**
 * Please tend to use nat64_is_stateful() instead of this macro. By using the function version,
 * your compilations will be aware of the alternate mode so you will not accidentally wreck it.
 * Also the function reminds you to #include this file, whereas this macro doesn't (and if you
 * don't your code will always be stateless).
 * Also #ifdefs look hairy.
 *
 * TODO check whenever this macro is used, nat64.h is #included.
 */
//#define STATEFUL

/* TODO (fine) #include bool? */
static inline int nat64_is_stateful(void)
{
#ifdef STATEFUL
	return 1;
#else
	return 0;
#endif
}

#endif /* _JOOL_COMM_NAT64_H */
