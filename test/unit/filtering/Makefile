MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

UNIT = filtering

obj-m += $(UNIT).o

$(UNIT)-objs += ../../../src/common/types.o
$(UNIT)-objs += ../../../src/mod/common/types.o
$(UNIT)-objs += ../../../src/mod/common/address.o
$(UNIT)-objs += ../framework/unit_test.o

$(UNIT)-objs += ../../../src/mod/common/packet.o
$(UNIT)-objs += ../../../src/mod/common/rfc6052.o
$(UNIT)-objs += ../../../src/mod/common/skbuff.o
$(UNIT)-objs += ../../../src/mod/common/translation_state.o
$(UNIT)-objs += ../../../src/mod/common/wrapper-config.o
$(UNIT)-objs += ../../../src/mod/common/wrapper-global.o
$(UNIT)-objs += ../../../src/mod/common/xlator.o
$(UNIT)-objs += ../../../src/mod/common/db/global.o
$(UNIT)-objs += ../../../src/mod/common/db/rbtree.o
$(UNIT)-objs += ../../../src/mod/common/db/pool4/db.o
$(UNIT)-objs += ../../../src/mod/common/db/pool4/empty.o
$(UNIT)-objs += ../../../src/mod/common/db/pool4/rfc6056.o
$(UNIT)-objs += ../../../src/mod/common/db/bib/db.o
$(UNIT)-objs += ../../../src/mod/common/db/bib/entry.o
$(UNIT)-objs += ../../../src/mod/common/db/bib/pkt_queue.o
$(UNIT)-objs += ../../../src/mod/common/nl/attribute.o
$(UNIT)-objs += ../../../src/mod/common/steps/determine_incoming_tuple.o
$(UNIT)-objs += ../../../src/mod/common/steps/compute_outgoing_tuple.o
$(UNIT)-objs += ../../../src/mod/common/steps/handling_hairpinning_nat64.o
$(UNIT)-objs += ../framework/skb_generator.o
$(UNIT)-objs += ../framework/types.o
$(UNIT)-objs += ../impersonator/icmp_wrapper.o
$(UNIT)-objs += ../impersonator/send_packet.o
$(UNIT)-objs += ../impersonator/siit.o
$(UNIT)-objs += ../impersonator/stats.o
$(UNIT)-objs += ../impersonator/nf_hook.o
$(UNIT)-objs += ../impersonator/route.o
$(UNIT)-objs += impersonator.o
$(UNIT)-objs += filtering_and_updating_test.o

$(UNIT)-objs += ../../../src/mod/common/ipv6_hdr_iterator.o
$(UNIT)-objs += ../../../src/mod/common/rfc7915/common.o
$(UNIT)-objs += ../../../src/mod/common/rfc7915/core.o
$(UNIT)-objs += ../../../src/mod/common/rfc7915/4to6.o
$(UNIT)-objs += ../../../src/mod/common/rfc7915/6to4.o

EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING
ccflags-y := -I$(src)/../../../src -I$(src)/..

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(UNIT).ko && sudo rmmod $(UNIT)
	sudo dmesg -tc | less
