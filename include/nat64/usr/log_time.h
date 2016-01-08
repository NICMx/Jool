#ifndef _JOOL_USR_LOG_TIME_H
#define _JOOL_USR_LOG_TIME_H

#ifdef BENCHMARK

int logtime_display(void);

#else /* BENCHMARK */

int logtime_display(void)
{
	return 0;
}

#endif

#endif /* _JOOL_USR_LOG_TIME_H */
