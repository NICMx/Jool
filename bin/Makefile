MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -I$(src)/../mod
EXTRA_CFLAGS += -I$(src)/../include

# Hash table test.
obj-m += hash_table.o
hash_table-objs += ../unit/nf_nat64_hash_table_test.o

# Bib-session test.
obj-m += bib_session.o
bib_session-objs += ../mod/nf_nat64_types.o
bib_session-objs += ../mod/nf_nat64_bib.o
bib_session-objs += ../mod/nf_nat64_session.o
bib_session-objs += ../unit/nf_nat64_bib_session_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
