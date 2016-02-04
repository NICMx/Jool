PROJECTS = addr bibdb bibtable config_proto eamt filtering fragdb hashtable iterator logtime palloc4 pkt pool4db rbtree rfc6052 sessiondb sessiontable translate 
CLEANPROJECTS = $(patsubst %,%.clean,$(PROJECTS))

all: $(PROJECTS)

$(PROJECTS):
	$(MAKE) -C $@

clean: $(CLEANPROJECTS)
	find ../../mod -type f -name "*.o" -delete

$(CLEANPROJECTS):
	$(MAKE) -C $(@:.clean=) clean

.PHONY: clean $(PROJECTS) $(CLEANPROJECTS)
