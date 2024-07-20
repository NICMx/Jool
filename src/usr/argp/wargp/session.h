#ifndef SRC_USR_ARGP_WARGP_SESSION_H_
#define SRC_USR_ARGP_WARGP_SESSION_H_

int handle_session_display(char *, int, char **, void const *);
int handle_session_follow(char *, int, char **, void const *);

void autocomplete_session_display(void const *);
void autocomplete_session_follow(void const *);

#endif /* SRC_USR_ARGP_WARGP_SESSION_H_ */
