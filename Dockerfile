FROM polytracker-llvm AS base
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>
MAINTAINER Carson Harmon <carson.harmon@trailofbits.com> 

FROM ubuntu:bionic AS builder
# Clang and LLVM binaries with our DFSan mods
COPY --from=base /polytracker_clang /polytracker_clang
# Contains libcxx for target, and polytracker private libcxx 
COPY --from=base /cxx_libs /cxx_libs
# Contains gclang produced bitcode for libcxx. For libcxx instrumentation
COPY --from=base /cxx_clean_bitcode /cxx_clean_bitcode
# Contains LLVM headers used to build polytracker 
COPY --from=base /polytracker-llvm /polytracker-llvm

ENV PATH="/polytracker_clang/bin:${PATH}"
ENV PATH="$PATH:/root/go/bin"

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update  \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      cmake                                           \
      git                                             \
      ninja-build                                     \
      python3-pip                                     \
      python3.7-dev                                   \
      golang                                          \
      libgraphviz-dev                                 \
      graphviz                                                                                

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 10
RUN python3 -m pip install pip
RUN python3 -m pip install pytest
RUN go get github.com/SRI-CSL/gllvm/cmd/...

COPY . /polytracker
RUN mkdir /polytracker/build
WORKDIR /polytracker/build
RUN cmake -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE -DCXX_LIB_PATH=/cxx_libs .. 
RUN ninja install

# Setting up build enviornment for targets 
WORKDIR /
RUN mkdir /build_artifacts
ENV WLLVM_BC_STORE=/cxx_clean_bitcode
ENV WLLVM_ARTIFACT_STORE=/build_artifacts
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
