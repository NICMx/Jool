#ifndef _JOOL_MOD_SESSION_TIMER_H
#define _JOOL_MOD_SESSION_TIMER_H

/**
 * @file
 * Timer used to trigger some of Jool's events. Always runs, as long as Jool
 * is modprobed. At time of writing, this induces session expiration.
 */

int session_timer_init(void);
void session_timer_destroy(void);

#endif /* _JOOL_MOD_SESSION_TIMER_H */
