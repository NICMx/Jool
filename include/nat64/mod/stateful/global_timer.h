#ifndef _JOOL_MOD_GLOBAL_TIMER_H
#define _JOOL_MOD_GLOBAL_TIMER_H

/**
 * @file
 * Timer used to trigger some of Jool's events. Always runs, as long as Jool
 * is modprobed. At time of writing, this induces fragment expiration.
 */

int global_timer_init(void);
void global_timer_destroy(void);

#endif /* _JOOL_MOD_GLOBAL_TIMER_H */
