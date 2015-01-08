MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING

#CC=cgcc
ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


ITERATOR = iterator
HASHTABLE = hashtable
RFC6052 = rfc6052
PKT = pkt
RBTREE = rbtree
POOLNUM = poolnum
POOL4 = pool4
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
SEND_PKT = send_pkt
MAPPING = mapping


#obj-m += $(ITERATOR).o
#obj-m += $(HASHTABLE).o
#obj-m += $(RFC6052).o
#obj-m += $(PKT).o
#obj-m += $(RBTREE).o
#obj-m += $(POOLNUM).o
#obj-m += $(POOL4).o
#obj-m += $(BIB).o
#obj-m += $(SESSION).o
#obj-m += $(FRAGDB).o
#obj-m += $(INCOMING).o
#obj-m += $(FILTERING).o
#obj-m += $(OUTGOING).o
#obj-m += $(TRANSLATE).o
#obj-m += $(HAIRPINNING).o
#obj-m += $(PKTQUEUE).o
#obj-m += $(CONFIG_PROTO).o
#obj-m += $(LOGTIME).o
#obj-m += $(SEND_PKT).o
obj-m += $(MAPPING).o


MIN_REQS = ../mod/common/types.o framework/str_utils.o framework/unit_test.o impersonator/stats.o


$(ITERATOR)-objs += $(MIN_REQS)
$(ITERATOR)-objs += ipv6_hdr_iterator_test.o

$(HASHTABLE)-objs += $(MIN_REQS)
$(HASHTABLE)-objs += hash_table_test.o

$(RFC6052)-objs += $(MIN_REQS)
$(RFC6052)-objs += rfc6052_test.o

$(PKT)-objs += $(MIN_REQS)
$(PKT)-objs += ../mod/ipv6_hdr_iterator.o
$(PKT)-objs += ../mod/packet.o
$(PKT)-objs += framework/skb_generator.o
$(PKT)-objs += framework/types.o
$(PKT)-objs += impersonator/icmp_wrapper.o
$(PKT)-objs += packet_test.o

$(RBTREE)-objs += $(MIN_REQS)
$(RBTREE)-objs += rbtree_test.o

$(POOLNUM)-objs += $(MIN_REQS)
$(POOLNUM)-objs += ../mod/random.o
$(POOLNUM)-objs += pool_num_test.o

$(POOL4)-objs += $(MIN_REQS)
$(POOL4)-objs += ../mod/poolnum.o
$(POOL4)-objs += ../mod/random.o
$(POOL4)-objs += pool4_test.o

$(BIB)-objs += $(MIN_REQS)
# The BIB test cannot use the pool4 impersonator
# because it needs to test exhaustion.
$(BIB)-objs += ../mod/pool4.o
$(BIB)-objs += ../mod/host6_node.o
$(BIB)-objs += ../mod/poolnum.o
$(BIB)-objs += ../mod/random.o
$(BIB)-objs += ../mod/rbtree.o
$(BIB)-objs += framework/bib.o
$(BIB)-objs += framework/types.o
$(BIB)-objs += impersonator/icmp_wrapper.o
$(BIB)-objs += bib_test.o

$(SESSION)-objs += $(MIN_REQS)
$(SESSION)-objs += ../mod/host6_node.o
$(SESSION)-objs += ../mod/bib_db.o
$(SESSION)-objs += ../mod/ipv6_hdr_iterator.o
$(SESSION)-objs += ../mod/packet.o
$(SESSION)-objs += ../mod/pool6.o
$(SESSION)-objs += ../mod/rfc6052.o
$(SESSION)-objs += ../mod/pkt_queue.o
$(SESSION)-objs += ../mod/rbtree.o
$(SESSION)-objs += framework/session.o
$(SESSION)-objs += framework/skb_generator.o
$(SESSION)-objs += framework/types.o
$(SESSION)-objs += impersonator/icmp_wrapper.o
$(SESSION)-objs += impersonator/pool4.o
$(SESSION)-objs += impersonator/send_packet.o
$(SESSION)-objs += session_test.o

$(FRAGDB)-objs += $(MIN_REQS)
$(FRAGDB)-objs += ../mod/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../mod/packet.o
$(FRAGDB)-objs += ../mod/random.o
$(FRAGDB)-objs += framework/skb_generator.o
$(FRAGDB)-objs += framework/types.o
$(FRAGDB)-objs += impersonator/icmp_wrapper.o
$(FRAGDB)-objs += fragment_db_test.o

$(INCOMING)-objs += $(MIN_REQS)
$(INCOMING)-objs += ../mod/ipv6_hdr_iterator.o
$(INCOMING)-objs += ../mod/packet.o
$(INCOMING)-objs += framework/skb_generator.o
$(INCOMING)-objs += framework/types.o
$(INCOMING)-objs += impersonator/icmp_wrapper.o
$(INCOMING)-objs += impersonator/stats.o
$(INCOMING)-objs += determine_incoming_tuple_test.o

$(FILTERING)-objs += $(MIN_REQS)
$(FILTERING)-objs += ../mod/host6_node.o
$(FILTERING)-objs += ../mod/bib_db.o
$(FILTERING)-objs += ../mod/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../mod/packet.o
$(FILTERING)-objs += ../mod/pkt_queue.o
$(FILTERING)-objs += ../mod/pool6.o
$(FILTERING)-objs += ../mod/rbtree.o
$(FILTERING)-objs += ../mod/rfc6052.o
$(FILTERING)-objs += ../mod/session_db.o
$(FILTERING)-objs += framework/session.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += impersonator/icmp_wrapper.o
$(FILTERING)-objs += impersonator/pool4.o
$(FILTERING)-objs += impersonator/send_packet.o
$(FILTERING)-objs += impersonator/stats.o
$(FILTERING)-objs += filtering_and_updating_test.o

$(OUTGOING)-objs += $(MIN_REQS)
$(OUTGOING)-objs += ../mod/host6_node.o
$(OUTGOING)-objs += ../mod/bib_db.o
$(OUTGOING)-objs += ../mod/compute_outgoing_tuple.o
$(OUTGOING)-objs += ../mod/packet.o
$(OUTGOING)-objs += ../mod/ipv6_hdr_iterator.o
$(OUTGOING)-objs += ../mod/pkt_queue.o
$(OUTGOING)-objs += ../mod/pool6.o
$(OUTGOING)-objs += ../mod/rbtree.o
$(OUTGOING)-objs += ../mod/rfc6052.o
$(OUTGOING)-objs += ../mod/session_db.o
$(OUTGOING)-objs += framework/types.o
$(OUTGOING)-objs += framework/session.o
$(OUTGOING)-objs += impersonator/icmp_wrapper.o
$(OUTGOING)-objs += impersonator/pool4.o
$(OUTGOING)-objs += impersonator/send_packet.o
$(OUTGOING)-objs += compute_outgoing_tuple_test.o

$(TRANSLATE)-objs += $(MIN_REQS)
$(TRANSLATE)-objs += ../mod/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../mod/packet.o
$(TRANSLATE)-objs += ../mod/ttp/common.o
$(TRANSLATE)-objs += ../mod/ttp/config.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += framework/validator.o
$(TRANSLATE)-objs += impersonator/icmp_wrapper.o
$(TRANSLATE)-objs += impersonator/send_packet.o
$(TRANSLATE)-objs += impersonator/stats.o
$(TRANSLATE)-objs += translate_packet_test.o

$(HAIRPINNING)-objs += $(MIN_REQS)
$(HAIRPINNING)-objs += ../mod/host6_node.o
$(HAIRPINNING)-objs += ../mod/bib_db.o
$(HAIRPINNING)-objs += ../mod/compute_outgoing_tuple.o
$(HAIRPINNING)-objs += ../mod/core.o
$(HAIRPINNING)-objs += ../mod/determine_incoming_tuple.o
$(HAIRPINNING)-objs += ../mod/filtering_and_updating.o
$(HAIRPINNING)-objs += ../mod/fragment_db.o
$(HAIRPINNING)-objs += ../mod/handling_hairpinning.o
$(HAIRPINNING)-objs += ../mod/ipv6_hdr_iterator.o
$(HAIRPINNING)-objs += ../mod/packet.o
$(HAIRPINNING)-objs += ../mod/pool6.o
$(HAIRPINNING)-objs += ../mod/random.o
$(HAIRPINNING)-objs += ../mod/rfc6052.o
$(HAIRPINNING)-objs += ../mod/pkt_queue.o
$(HAIRPINNING)-objs += ../mod/rbtree.o
$(HAIRPINNING)-objs += ../mod/session_db.o
$(HAIRPINNING)-objs += ../mod/ttp/4to6.o
$(HAIRPINNING)-objs += ../mod/ttp/6to4.o
$(HAIRPINNING)-objs += ../mod/ttp/common.o
$(HAIRPINNING)-objs += ../mod/ttp/config.o
$(HAIRPINNING)-objs += ../mod/ttp/core.o
$(HAIRPINNING)-objs += framework/bib.o
$(HAIRPINNING)-objs += framework/session.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += impersonator/icmp_wrapper.o
$(HAIRPINNING)-objs += impersonator/pool4.o
$(HAIRPINNING)-objs += impersonator/send_packet.o
$(HAIRPINNING)-objs += impersonator/stats.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o

$(PKTQUEUE)-objs += $(MIN_REQS)
$(PKTQUEUE)-objs += ../mod/host6_node.o
$(PKTQUEUE)-objs += ../mod/bib_db.o
$(PKTQUEUE)-objs += ../mod/packet.o
$(PKTQUEUE)-objs += ../mod/ipv6_hdr_iterator.o
$(PKTQUEUE)-objs += ../mod/pool6.o
$(PKTQUEUE)-objs += ../mod/rfc6052.o
$(PKTQUEUE)-objs += ../mod/rbtree.o
$(PKTQUEUE)-objs += ../mod/session_db.o
$(PKTQUEUE)-objs += framework/session.o
$(PKTQUEUE)-objs += framework/skb_generator.o
$(PKTQUEUE)-objs += framework/types.o
$(PKTQUEUE)-objs += impersonator/icmp_wrapper.o
$(PKTQUEUE)-objs += impersonator/pool4.o
$(PKTQUEUE)-objs += impersonator/send_packet.o
$(PKTQUEUE)-objs += impersonator/stats.o
$(PKTQUEUE)-objs += pkt_queue_test.o

$(CONFIG_PROTO)-objs += $(MIN_REQS)
$(CONFIG_PROTO)-objs += ../mod/filtering_and_updating.o
$(CONFIG_PROTO)-objs += ../mod/packet.o
$(CONFIG_PROTO)-objs += ../mod/pkt_queue.o
$(CONFIG_PROTO)-objs += ../mod/ipv6_hdr_iterator.o
$(CONFIG_PROTO)-objs += ../mod/pool6.o
$(CONFIG_PROTO)-objs += ../mod/rfc6052.o
$(CONFIG_PROTO)-objs += ../mod/random.o
$(CONFIG_PROTO)-objs += ../mod/rbtree.o
$(CONFIG_PROTO)-objs += ../mod/fragment_db.o
$(CONFIG_PROTO)-objs += ../mod/host6_node.o
$(CONFIG_PROTO)-objs += ../mod/bib_db.o
$(CONFIG_PROTO)-objs += ../mod/session_db.o
$(CONFIG_PROTO)-objs += ../mod/send_packet.o
$(CONFIG_PROTO)-objs += ../mod/ttp/4to6.o
$(CONFIG_PROTO)-objs += ../mod/ttp/6to4.o
$(CONFIG_PROTO)-objs += ../mod/ttp/common.o
$(CONFIG_PROTO)-objs += ../mod/ttp/config.o
$(CONFIG_PROTO)-objs += ../mod/ttp/core.o
$(CONFIG_PROTO)-objs += impersonator/icmp_wrapper.o
$(CONFIG_PROTO)-objs += impersonator/pool4.o
$(CONFIG_PROTO)-objs += impersonator/stats.o
$(CONFIG_PROTO)-objs += config_proto_test.o

$(LOGTIME)-objs += $(MIN_REQS)
$(LOGTIME)-objs += log_time_test.o

$(SEND_PKT)-objs += $(MIN_REQS)
$(SEND_PKT)-objs += framework/skb_generator.o
$(SEND_PKT)-objs += framework/types.o
$(SEND_PKT)-objs += framework/validator.o
$(SEND_PKT)-objs += impersonator/icmp_wrapper.o
$(SEND_PKT)-objs += ../mod/ipv6_hdr_iterator.o
$(SEND_PKT)-objs += ../mod/packet.o
$(SEND_PKT)-objs += send_packet_test.o

$(MAPPING)-objs += $(MIN_REQS)
$(MAPPING)-objs += ../mod/common/rbtree.o
$(MAPPING)-objs += address_mapping_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod $(ITERATOR).ko && sudo rmmod $(ITERATOR)
	-sudo insmod $(HASHTABLE).ko && sudo rmmod $(HASHTABLE)
	-sudo insmod $(RFC6052).ko && sudo rmmod $(RFC6052)
	-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(RBTREE).ko && sudo rmmod $(RBTREE)
	-sudo insmod $(POOLNUM).ko && sudo rmmod $(POOLNUM)
	# Warning: This test is lenghty! It might freeze your computer for a couple of seconds.
	-sudo insmod $(POOL4).ko && sudo rmmod $(POOL4)
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
	-sudo insmod $(LOGTIME).ko && sudo rmmod $(LOGTIME)
	-sudo insmod $(SEND_PKT).ko && sudo rmmod $(SEND_PKT)
	-sudo insmod $(MAPPING).ko && sudo rmmod $(MAPPING)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
