CFLAGS = -O2 -Wall -I../..
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)

all:
	make libxt_JOOL_SIIT.so;
	make libxt_JOOL.so;
install:
	cp *.so ${XTABLES_SO_DIR}
uninstall:
	rm -f ${XTABLES_SO_DIR}/libxt_JOOL_SIIT.so
	rm -f ${XTABLES_SO_DIR}/libxt_JOOL.so
lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean:
	rm -f *.so
