#!/bin/sh

git clean -dfx \
	-e .cproject \
	-e .project \
	-e .settings \
	-e .metadata \
	-e Debug/ \
	-e sandbox/
