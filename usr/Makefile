# Make libxt_nat64.so
IDIR =../include
CFLAGS = -O2 -Wall -I$(IDIR)
lib%.so: lib%.o
	gcc -shared -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -fPIC -D_INIT=lib$*_init -c -o $@ $<;
