POLYTRACKER_FILES:=$(shell find ../build -type f -print)

.PHONY: all
all: bin/mutool_track

.PHONY: polytracker
polytracker: Dockerfile build.sh
	./build.sh

bin/mutool_track: polytracker Dockerfile-mutool Dockerfile build_mutool.sh $(POLYTRACKER_FILES)
	./build_mutool.sh
