#ifndef SRC_USR_JOOLD_LOG_H_
#define SRC_USR_JOOLD_LOG_H_

#ifdef JOOLD_DEBUG
#define SYSLOG_DBG(...) syslog(LOG_DEBUG, __VA_ARGS__);
#else
#define SYSLOG_DBG(...)
#endif

#endif /* SRC_USR_JOOLD_LOG_H_ */
