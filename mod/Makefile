PROJECTS = stateless stateful
OTHER_TARGETS = modules modules_install clean


all: $(PROJECTS)
	# Running the dependencies is enough.
$(PROJECTS):
	$(MAKE) -C $@
$(OTHER_TARGETS):
	$(foreach dir, $(PROJECTS), make -C $(dir) $@;)


.PHONY: $(PROJECTS) $(OTHER_TARGETS)
