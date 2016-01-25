#ifndef _JOOL_MOD_TIMER_H
#define _JOOL_MOD_TIMER_H

/**
 * @file
 * An all-purpose timer used to trigger some of Jool's events. Always runs, as
 * long as Jool is modprobed. At time of writing, this induces session and
 * fragment expiration.
 *
 * Why don't the session and fragment code manage their own timers?
 * Because that's more code and I don't see how it would improve anything.
 */

int timer_init(void);
void timer_destroy(void);

#endif /* _JOOL_MOD_TIMER_H */
