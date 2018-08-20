CFLAGS = -O2 -Wall -I../../include
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)

all:
	make libxt_JOOL_SIIT.so;
	make libxt_JOOL.so;
install:
	sudo cp *.so ${XTABLES_SO_DIR}
lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean:
	rm *.so