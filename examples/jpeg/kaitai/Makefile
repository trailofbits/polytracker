KAITAI_DIR=kaitai
KAITAI_HEADERS=$(wildcard $(KAITAI_DIR)/*.h)
KAITAI_RUNTIME=$(KAITAI_DIR)/kaitaistream.cpp
SOURCES=$(wildcard *.cpp)
BUILD_DIR=build
CXXFLAGS=-O3 -DKS_STR_ENCODING_NONE
LD=clang++

.phony: all
all: jpeg_example

build:
	mkdir -p build/kaitai

jpeg_example: $(patsubst %.cpp, $(BUILD_DIR)/%.o, $(SOURCES)) $(BUILD_DIR)/kaitai/kaitaistream.o
	$(CXX) $^ -o $@

$(BUILD_DIR)/%.o : build %.cpp $(KAITAI_HEADERS) $(wildcard *.h)
	$(CXX) $(CXXFLAGS) -I. -c $*.cpp -o $@

.phony: clean
clean:
	rm -rf build .built_docker_image

.phony: docker
docker .built_docker_image: $(KAITAI_HEADERS) $(wildcard *.h) $(SOURCES) $(KAITAI_RUNTIME)
ifeq ($(shell docker images -q trailofbits/polytracker),)
	@echo "Building the base PolyTracker Docker container..."
	docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
endif
	docker build -t trailofbits/polytracker-demo-jpeg-kaitai -f Dockerfile .
	touch .built_docker_image
