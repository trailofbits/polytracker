FROM ubuntu:jammy as base

LABEL org.opencontainers.image.authors="evan.sultanik@trailofbits.com"

ARG BUILD_TYPE="Release"
ARG PARALLEL_LINK_JOBS=1
ARG LLVM_TARGET_NAME=X86

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install \
  ninja-build                                         \
  python3-pip                                         \
  python3.8-dev                                       \
  python-is-python3                                   \
  ca-certificates                                     \
  libstdc++-10-dev                                    \
  golang                                              \
  clang-12                                            \
  cmake                                               \
  git                                                 \
  file

RUN update-alternatives --install /usr/bin/opt opt /usr/bin/opt-12 10
RUN update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-12 10
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 10
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-12 10

WORKDIR /
RUN git clone --depth 1 --branch llvmorg-13.0.1 https://github.com/llvm/llvm-project.git
RUN git clone --depth 1 --branch master https://github.com/trailofbits/blight.git

RUN pip3 install pytest /blight

RUN update-ca-certificates

RUN GO111MODULE=off go get github.com/SRI-CSL/gllvm/cmd/...
ENV PATH="$PATH:/root/go/bin"

FROM base as libcxx

ENV CC="gclang"
ENV CXX="gclang++"

ENV LIBCXX_BUILD_DIR=/llvm-project/llvm/build
ENV LIBCXX_INSTALL_DIR=/cxx_lib

RUN cmake -GNinja \
  -B$LIBCXX_BUILD_DIR \
  -S/llvm-project/runtimes \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_INSTALL_PREFIX=$LIBCXX_INSTALL_DIR \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi"

RUN cmake --build $LIBCXX_BUILD_DIR --target install-cxx install-cxxabi -j$((`nproc`+1))

FROM libcxx as polytracker-python

WORKDIR /workdir
COPY . /polytracker

RUN pip3 install /polytracker

FROM polytracker-python as polytracker-cxx

ARG DFSAN_FILENAME_ARCH=x86_64

ENV CC="clang"
ENV CXX="clang++"
RUN cmake -GNinja \
  -B/polytracker/build \
  -S/polytracker \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCXX_LIB_PATH=$LIBCXX_INSTALL_DIR

RUN cmake --build /polytracker/build --target install -j$((`nproc`+1))

# Setting up build enviornment for targets
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
ENV PATH=/polytracker/build/bin:$PATH
ENV DFSAN_OPTIONS="strict_data_dependencies=0"
ENV COMPILER_DIR=/polytracker/build/share/polytracker
ENV CXX_LIB_PATH=/cxx_lib
ENV WLLVM_BC_STORE=/cxx_clean_bitcode
ENV WLLVM_ARTIFACT_STORE=/build_artifacts
ENV DFSAN_LIB_PATH=/polytracker/build/lib/linux/libclang_rt.dfsan-${DFSAN_FILENAME_ARCH}.a

RUN mkdir $WLLVM_BC_STORE
RUN mkdir $WLLVM_ARTIFACT_STORE
