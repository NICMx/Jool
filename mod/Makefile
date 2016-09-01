PROJECTS = stateless stateful
OTHER_TARGETS = modules modules_install install clean debug


all: $(PROJECTS)
	# Running the dependencies is enough.
$(PROJECTS):
	$(MAKE) -C $@
$(OTHER_TARGETS):
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) $@;)


.PHONY: $(PROJECTS) $(OTHER_TARGETS)
