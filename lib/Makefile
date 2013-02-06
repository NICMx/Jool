# make libxt_NAT64.so

IDIR =../include/nat64
CFLAGS = -O2 -Wall -I$(IDIR)

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
