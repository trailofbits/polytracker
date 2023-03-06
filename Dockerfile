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
  golang                                              \
  clang-12                                            \
  cmake                                               \
  git                                                 \
  file

RUN pip3 install pytest blight

RUN update-alternatives --install /usr/bin/opt opt /usr/bin/opt-12 10
RUN update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-12 10
RUN update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-12 10
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 10
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-12 10

RUN GO111MODULE=off go get github.com/SRI-CSL/gllvm/cmd/...
ENV PATH="$PATH:/root/go/bin"

FROM base as llvm-sources

RUN git clone --depth 1 --branch llvmorg-13.0.0 https://github.com/llvm/llvm-project.git /llvm-project

FROM llvm-sources as clean-libcxx

ENV BITCODE=/cxx_clean_bitcode
RUN mkdir -p $BITCODE
ENV WLLVM_BC_STORE=$BITCODE

ENV LIBCXX_BUILD_DIR=/llvm-project/build
ENV LIBCXX_INSTALL_DIR=/cxx_lib/clean_build

RUN cmake -GNinja \
  -B$LIBCXX_BUILD_DIR \
  -S/llvm-project/runtimes \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_C_COMPILER="gclang" \
  -DCMAKE_CXX_COMPILER="gclang++" \
  -DCMAKE_INSTALL_PREFIX=$LIBCXX_INSTALL_DIR \
  -DLIBCXXABI_ENABLE_SHARED=NO \
  -DLIBCXX_ENABLE_SHARED=NO \
  -DLIBCXX_CXX_ABI="libcxxabi" \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi"

RUN cmake --build $LIBCXX_BUILD_DIR --target install-cxx install-cxxabi -j$((`nproc`+1))

FROM clean-libcxx as polytracker-libcxx

ENV BITCODE=/cxx_poly_bitcode
RUN mkdir -p $BITCODE
ENV WLLVM_BC_STORE=$BITCODE

ENV LIBCXX_BUILD_DIR=/llvm-project/llvm/build
ENV LIBCXX_INSTALL_DIR=/cxx_lib/poly_build

RUN cmake -GNinja \
  -B$LIBCXX_BUILD_DIR \
  -S/llvm-project/runtimes \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_C_COMPILER="gclang" \
  -DCMAKE_CXX_COMPILER="gclang++" \
  -DCMAKE_INSTALL_PREFIX=$LIBCXX_INSTALL_DIR \
  -DLIBCXXABI_ENABLE_SHARED=NO \
  -DLIBCXX_ENABLE_SHARED=NO \
  -DLIBCXX_ABI_VERSION=2 \
  -DLIBCXX_CXX_ABI="libcxxabi" \
  -DLIBCXX_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi"

RUN cmake --build $LIBCXX_BUILD_DIR --target install-cxx install-cxxabi -j$((`nproc`+1))

FROM polytracker-libcxx as polytracker-python

WORKDIR /workdir
COPY . /polytracker

RUN pip3 install /polytracker

FROM polytracker-python as polytracker-cxx

ARG DFSAN_FILENAME_ARCH=x86_64

RUN cmake -GNinja \
  -B/polytracker-build \
  -S/polytracker \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_C_COMPILER="clang" \
  -DCMAKE_CXX_COMPILER="clang++" \
  -DCXX_LIB_PATH=/cxx_lib/poly_build \
  -DCMAKE_INSTALL_PREFIX=/polytracker-install

RUN cmake --build /polytracker-build --target install -j$((`nproc`+1))

ENV DFSAN_LIB_PATH=/polytracker-install/lib/linux/libclang_rt.dfsan-${DFSAN_FILENAME_ARCH}.a
ENV CXX_LIB_PATH=/cxx_lib
ENV COMPILER_DIR=/polytracker-install/share/polytracker

ENV DFSAN_OPTIONS="strict_data_dependencies=0"

ENV WLLVM_BC_STORE=/project_bitcode
ENV WLLVM_ARTIFACT_STORE=/project_artifacts

RUN mkdir $WLLVM_ARTIFACT_STORE
RUN mkdir $WLLVM_BC_STORE

ENV PATH=$PATH:/polytracker-install/bin