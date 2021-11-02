POLYTRACKER_FILES:=$(shell find ../build -type f '(' -name "*.so" ')' -print)
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: all
all: bin/mutool_track

.PHONY: clean
clean:
	rm -rf bin ../build

.PHONY: polytracker
polytracker: Dockerfile build.sh
	./build.sh

bin/mutool_track: $(POLYTRACKER_FILES)
	./build.sh
	./build_mutool.sh

.PHONY: run_remote_debug_container
run_remote_debug_container: bin/mutool_track
	echo "Running the remote dev Docker container; ^C this process to end it."
	docker run --rm \
		--mount type=bind,source="$(ROOT_DIR)/..",target=/polytracker \
  		--mount type=bind,source="$(ROOT_DIR)/bin",target=/sources/bin \
    	-p127.0.0.1:2222:22 --name polytracker_remote_env trailofbits/polytrackerbuilder-mupdf
