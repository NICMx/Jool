CFLAGS = -O2 -Wall -I../.. $(shell pkg-config xtables --cflags)
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)

all:
	make libxt_JOOL_SIIT.so;
	make libxt_JOOL.so;
install:
	mkdir -p ${DESTDIR}${XTABLES_SO_DIR}
	cp *.so ${DESTDIR}${XTABLES_SO_DIR}
uninstall:
	rm -f ${DESTDIR}${XTABLES_SO_DIR}/libxt_JOOL_SIIT.so
	rm -f ${DESTDIR}${XTABLES_SO_DIR}/libxt_JOOL.so
lib%.so: lib%.o
	gcc -shared -fPIC ${LDFLAGS} -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean distclean:
	rm -f *.so
distdir:
	mkdir -p ${distdir}
	cp * ${distdir}
