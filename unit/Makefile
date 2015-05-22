MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DSTATEFUL

#CC=cgcc
ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod/common
ccflags-y += -I$(src)/../mod/stateful
ccflags-y += -I$(src)/../mod/stateless


ADDR = addr
ITERATOR = iterator
HASHTABLE = hashtable
RFC6052 = rfc6052
PKT = pkt
RBTREE = rbtree
POOL4DB = pool4db
BIB = bib
SESSION = session
FRAGDB = fragdb
INCOMING = incoming
FILTERING = filtering
OUTGOING = outgoing
TRANSLATE = translate
HAIRPINNING = hairpinning
PKTQUEUE = pktqueue
CONFIG_PROTO = config_proto
LOGTIME = logtime
MAPPING = mapping
PALLOC = palloc4


obj-m += $(ADDR).o
obj-m += $(ITERATOR).o
obj-m += $(HASHTABLE).o
obj-m += $(RFC6052).o
obj-m += $(PKT).o
obj-m += $(RBTREE).o
obj-m += $(POOL4DB).o
obj-m += $(BIB).o
obj-m += $(SESSION).o
obj-m += $(FRAGDB).o
obj-m += $(INCOMING).o
obj-m += $(FILTERING).o
obj-m += $(OUTGOING).o
obj-m += $(TRANSLATE).o
obj-m += $(HAIRPINNING).o
obj-m += $(PKTQUEUE).o
obj-m += $(CONFIG_PROTO).o
#obj-m += $(LOGTIME).o
# Note, this is compiling with -DSTATEFUL, even though is part of the stateless translator.
# At the moment this doesn't cause any trouble, but it means we might need to refactor this
# Makefile to make better room for stateless tests.
obj-m += $(MAPPING).o
obj-m += $(PALLOC).o


MIN_REQS = ../mod/common/types.o \
	../mod/common/address.o \
	framework/str_utils.o \
	framework/unit_test.o \
	impersonator/stats.o


$(ADDR)-objs += $(MIN_REQS)
$(ADDR)-objs += address_test.o

$(ITERATOR)-objs += $(MIN_REQS)
$(ITERATOR)-objs += ipv6_hdr_iterator_test.o

$(HASHTABLE)-objs += $(MIN_REQS)
$(HASHTABLE)-objs += hash_table_test.o

$(RFC6052)-objs += $(MIN_REQS)
$(RFC6052)-objs += ../mod/common/pool6.o
$(RFC6052)-objs += rfc6052_test.o

$(PKT)-objs += $(MIN_REQS)
$(PKT)-objs += ../mod/common/ipv6_hdr_iterator.o
$(PKT)-objs += ../mod/common/packet.o
$(PKT)-objs += framework/skb_generator.o
$(PKT)-objs += framework/types.o
$(PKT)-objs += impersonator/icmp_wrapper.o
$(PKT)-objs += packet_test.o

$(RBTREE)-objs += $(MIN_REQS)
$(RBTREE)-objs += rbtree_test.o

$(POOL4DB)-objs += $(MIN_REQS)
$(POOL4DB)-objs += ../mod/stateful/pool4/table.o
$(POOL4DB)-objs += ../mod/stateful/pool4/entry.o
$(POOL4DB)-objs += pool4db_test.o

$(BIB)-objs += $(MIN_REQS)
$(BIB)-objs += ../mod/common/config.o
$(BIB)-objs += ../mod/common/rbtree.o
$(BIB)-objs += ../mod/stateful/bib/entry.o
$(BIB)-objs += ../mod/stateful/bib/table.o
$(BIB)-objs += framework/bib.o
$(BIB)-objs += bib_test.o

$(SESSION)-objs += $(MIN_REQS)
$(SESSION)-objs += ../mod/common/config.o
$(SESSION)-objs += ../mod/common/ipv6_hdr_iterator.o
$(SESSION)-objs += ../mod/common/packet.o
$(SESSION)-objs += ../mod/common/pool6.o
$(SESSION)-objs += ../mod/common/rbtree.o
$(SESSION)-objs += ../mod/common/rfc6052.o
$(SESSION)-objs += ../mod/stateful/bib_db.o
$(SESSION)-objs += ../mod/stateful/host6_node.o
$(SESSION)-objs += ../mod/stateful/pkt_queue.o
$(SESSION)-objs += framework/session.o
$(SESSION)-objs += framework/skb_generator.o
$(SESSION)-objs += framework/types.o
$(SESSION)-objs += impersonator/icmp_wrapper.o
$(SESSION)-objs += impersonator/route.o
$(SESSION)-objs += session_test.o

$(FRAGDB)-objs += $(MIN_REQS)
$(FRAGDB)-objs += ../mod/common/config.o
$(FRAGDB)-objs += ../mod/common/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../mod/common/packet.o
$(FRAGDB)-objs += ../mod/common/random.o
$(FRAGDB)-objs += framework/skb_generator.o
$(FRAGDB)-objs += framework/types.o
$(FRAGDB)-objs += impersonator/icmp_wrapper.o
$(FRAGDB)-objs += fragment_db_test.o

$(INCOMING)-objs += $(MIN_REQS)
$(INCOMING)-objs += ../mod/common/ipv6_hdr_iterator.o
$(INCOMING)-objs += ../mod/common/packet.o
$(INCOMING)-objs += framework/skb_generator.o
$(INCOMING)-objs += framework/types.o
$(INCOMING)-objs += impersonator/icmp_wrapper.o
$(INCOMING)-objs += impersonator/stats.o
$(INCOMING)-objs += determine_incoming_tuple_test.o

$(FILTERING)-objs += $(MIN_REQS)
$(FILTERING)-objs += ../mod/common/config.o
$(FILTERING)-objs += ../mod/common/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../mod/common/packet.o
$(FILTERING)-objs += ../mod/common/pool6.o
$(FILTERING)-objs += ../mod/common/rbtree.o
$(FILTERING)-objs += ../mod/common/rfc6052.o
$(FILTERING)-objs += ../mod/stateful/bib_db.o
$(FILTERING)-objs += ../mod/stateful/host6_node.o
$(FILTERING)-objs += ../mod/stateful/pkt_queue.o
$(FILTERING)-objs += ../mod/stateful/session_db.o
$(FILTERING)-objs += framework/init.o
$(FILTERING)-objs += framework/session.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += impersonator/icmp_wrapper.o
$(FILTERING)-objs += impersonator/route.o
$(FILTERING)-objs += impersonator/stats.o
$(FILTERING)-objs += filtering_and_updating_test.o

$(OUTGOING)-objs += $(MIN_REQS)
$(OUTGOING)-objs += ../mod/common/config.o
$(OUTGOING)-objs += ../mod/common/pool6.o
$(OUTGOING)-objs += ../mod/common/rbtree.o
$(OUTGOING)-objs += ../mod/common/rfc6052.o
$(OUTGOING)-objs += ../mod/stateful/bib_db.o
$(OUTGOING)-objs += ../mod/stateful/compute_outgoing_tuple.o
$(OUTGOING)-objs += ../mod/stateful/host6_node.o
$(OUTGOING)-objs += ../mod/stateful/pkt_queue.o
$(OUTGOING)-objs += ../mod/stateful/session_db.o
$(OUTGOING)-objs += framework/init.o
$(OUTGOING)-objs += framework/session.o
$(OUTGOING)-objs += framework/types.o
$(OUTGOING)-objs += impersonator/icmp_wrapper.o
$(OUTGOING)-objs += impersonator/route.o
$(OUTGOING)-objs += compute_outgoing_tuple_test.o

$(TRANSLATE)-objs += $(MIN_REQS)
$(TRANSLATE)-objs += ../mod/common/config.o
$(TRANSLATE)-objs += ../mod/common/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../mod/common/packet.o
$(TRANSLATE)-objs += ../mod/common/pool6.o
$(TRANSLATE)-objs += ../mod/common/rfc6052.o
$(TRANSLATE)-objs += ../mod/common/rfc6145/common.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += framework/validator.o
$(TRANSLATE)-objs += impersonator/icmp_wrapper.o
$(TRANSLATE)-objs += impersonator/send_packet.o
$(TRANSLATE)-objs += impersonator/stats.o
$(TRANSLATE)-objs += translate_packet_test.o

$(HAIRPINNING)-objs += $(MIN_REQS)
$(HAIRPINNING)-objs += ../mod/common/blacklist.o
$(HAIRPINNING)-objs += ../mod/common/config.o
$(HAIRPINNING)-objs += ../mod/common/core.o
$(HAIRPINNING)-objs += ../mod/common/ipv6_hdr_iterator.o
$(HAIRPINNING)-objs += ../mod/common/packet.o
$(HAIRPINNING)-objs += ../mod/common/pool6.o
$(HAIRPINNING)-objs += ../mod/common/random.o
$(HAIRPINNING)-objs += ../mod/common/rbtree.o
$(HAIRPINNING)-objs += ../mod/common/rfc6052.o
$(HAIRPINNING)-objs += ../mod/common/rfc6145/4to6.o
$(HAIRPINNING)-objs += ../mod/common/rfc6145/6to4.o
$(HAIRPINNING)-objs += ../mod/common/rfc6145/common.o
$(HAIRPINNING)-objs += ../mod/common/rfc6145/core.o
$(HAIRPINNING)-objs += ../mod/stateful/bib_db.o
$(HAIRPINNING)-objs += ../mod/stateful/compute_outgoing_tuple.o
$(HAIRPINNING)-objs += ../mod/stateful/determine_incoming_tuple.o
$(HAIRPINNING)-objs += ../mod/stateful/filtering_and_updating.o
$(HAIRPINNING)-objs += ../mod/stateful/fragment_db.o
$(HAIRPINNING)-objs += ../mod/stateful/handling_hairpinning.o
$(HAIRPINNING)-objs += ../mod/stateful/host6_node.o
$(HAIRPINNING)-objs += ../mod/stateful/pkt_queue.o
$(HAIRPINNING)-objs += ../mod/stateful/session_db.o
$(HAIRPINNING)-objs += framework/bib.o
$(HAIRPINNING)-objs += framework/init.o
$(HAIRPINNING)-objs += framework/session.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += impersonator/icmp_wrapper.o
$(HAIRPINNING)-objs += impersonator/route.o
$(HAIRPINNING)-objs += impersonator/send_packet.o
$(HAIRPINNING)-objs += impersonator/stats.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o

$(PKTQUEUE)-objs += $(MIN_REQS)
$(PKTQUEUE)-objs += ../mod/stateful/bib_db.o
$(PKTQUEUE)-objs += ../mod/stateful/host6_node.o
$(PKTQUEUE)-objs += ../mod/stateful/session_db.o
$(PKTQUEUE)-objs += ../mod/common/config.o
$(PKTQUEUE)-objs += ../mod/common/ipv6_hdr_iterator.o
$(PKTQUEUE)-objs += ../mod/common/packet.o
$(PKTQUEUE)-objs += ../mod/common/pool6.o
$(PKTQUEUE)-objs += ../mod/common/rbtree.o
$(PKTQUEUE)-objs += ../mod/common/rfc6052.o
$(PKTQUEUE)-objs += framework/init.o
$(PKTQUEUE)-objs += framework/session.o
$(PKTQUEUE)-objs += framework/skb_generator.o
$(PKTQUEUE)-objs += framework/types.o
$(PKTQUEUE)-objs += impersonator/icmp_wrapper.o
$(PKTQUEUE)-objs += impersonator/route.o
$(PKTQUEUE)-objs += impersonator/stats.o
$(PKTQUEUE)-objs += pkt_queue_test.o

$(CONFIG_PROTO)-objs += $(MIN_REQS)
$(CONFIG_PROTO)-objs += ../mod/common/blacklist.o
$(CONFIG_PROTO)-objs += ../mod/common/config.o
$(CONFIG_PROTO)-objs += ../mod/common/ipv6_hdr_iterator.o
$(CONFIG_PROTO)-objs += ../mod/common/nl_buffer.o
$(CONFIG_PROTO)-objs += ../mod/common/packet.o
$(CONFIG_PROTO)-objs += ../mod/common/pool6.o
$(CONFIG_PROTO)-objs += ../mod/common/random.o
$(CONFIG_PROTO)-objs += ../mod/common/rbtree.o
$(CONFIG_PROTO)-objs += ../mod/common/rfc6052.o
$(CONFIG_PROTO)-objs += ../mod/common/rfc6145/4to6.o
$(CONFIG_PROTO)-objs += ../mod/common/rfc6145/6to4.o
$(CONFIG_PROTO)-objs += ../mod/common/rfc6145/common.o
$(CONFIG_PROTO)-objs += ../mod/common/rfc6145/core.o
$(CONFIG_PROTO)-objs += ../mod/common/route.o
$(CONFIG_PROTO)-objs += ../mod/stateful/bib_db.o
$(CONFIG_PROTO)-objs += ../mod/stateful/filtering_and_updating.o
$(CONFIG_PROTO)-objs += ../mod/stateful/fragment_db.o
$(CONFIG_PROTO)-objs += ../mod/stateful/host6_node.o
$(CONFIG_PROTO)-objs += ../mod/stateful/pkt_queue.o
$(CONFIG_PROTO)-objs += ../mod/stateful/session_db.o
$(CONFIG_PROTO)-objs += ../mod/stateful/static_routes.o
$(CONFIG_PROTO)-objs += framework/init.o
$(CONFIG_PROTO)-objs += impersonator/icmp_wrapper.o
$(CONFIG_PROTO)-objs += impersonator/stats.o
$(CONFIG_PROTO)-objs += nl_handler_test.o

$(LOGTIME)-objs += $(MIN_REQS)
$(LOGTIME)-objs += log_time_test.o

$(MAPPING)-objs += $(MIN_REQS)
$(MAPPING)-objs += ../mod/common/rbtree.o
$(MAPPING)-objs += eamt_test.o

$(PALLOC)-objs += $(MIN_REQS)
$(PALLOC)-objs += port_allocator_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod $(ADDR).ko && sudo rmmod $(ADDR)
	-sudo insmod $(ITERATOR).ko && sudo rmmod $(ITERATOR)
	-sudo insmod $(HASHTABLE).ko && sudo rmmod $(HASHTABLE)
	-sudo insmod $(RFC6052).ko && sudo rmmod $(RFC6052)
	-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(RBTREE).ko && sudo rmmod $(RBTREE)
	-sudo insmod $(POOL4DB).ko && sudo rmmod $(POOL4DB)
	-sudo insmod $(BIB).ko && sudo rmmod $(BIB)
	-sudo insmod $(SESSION).ko && sudo rmmod $(SESSION)
	-sudo insmod $(FRAGDB).ko && sudo rmmod $(FRAGDB)
	-sudo insmod $(INCOMING).ko && sudo rmmod $(INCOMING)
	-sudo insmod $(FILTERING).ko && sudo rmmod $(FILTERING)
	-sudo insmod $(OUTGOING).ko && sudo rmmod $(OUTGOING)
	-sudo insmod $(TRANSLATE).ko && sudo rmmod $(TRANSLATE)
	-sudo insmod $(HAIRPINNING).ko && sudo rmmod $(HAIRPINNING)
	-sudo insmod $(PKTQUEUE).ko && sudo rmmod $(PKTQUEUE)
	-sudo insmod $(CONFIG_PROTO).ko && sudo rmmod $(CONFIG_PROTO)
	#-sudo insmod $(LOGTIME).ko && sudo rmmod $(LOGTIME)
	-sudo insmod $(MAPPING).ko && sudo rmmod $(MAPPING)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
