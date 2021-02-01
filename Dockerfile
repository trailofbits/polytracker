FROM ubuntu:bionic AS builder
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>
MAINTAINER Carson Harmon <carson.harmon@trailofbits.com> 

# Multi stage build, first install some dependencies 
RUN DEBIAN_FRONTEND=noninteractive apt-get -y update  \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      wget                                            \
      gnupg

# Add the LLVM repo for Ubuntu packages, since the official Ubuntu repo has an
# LLVM that doesn't work right with polytracker for some reason.
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" >>/etc/apt/sources.list

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update  \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      clang-7                                         \
      cmake                                           \
      git                                             \
      lld-7                                           \
      llvm-7                                          \
      libc++abi-dev				      \
      ninja-build                                     \
      python3-pip                                     \
      python3.7-dev                                   \
      golang                                          \
      libgraphviz-dev                                 \
      graphviz                                        \                                        
      clang-10                                        \
      llvm-10-dev                                     \
      llvm-10-tools                                   \
      lld-10                                          

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 10
RUN python3 -m pip install pip
RUN go get github.com/SRI-CSL/gllvm/cmd/...
ENV PATH="$PATH:/root/go/bin"
RUN python3.7 -m pip install pytest
RUN ln -s /usr/bin/clang-10 /usr/bin/clang
RUN ln -s /usr/bin/clang++-10 /usr/bin/clang++

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
RUN tar -xvf clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
RUN mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 /usr/lib/llvm-10
ENV PATH="/usr/lib/llvm-10/bin:${PATH}"

RUN wget https://releases.llvm.org/7.0.1/clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
RUN tar -xvf clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz 
RUN mv clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04 /usr/lib/llvm-7-test
ENV PATH ="${PATH}:/usr/lib/llvm-7-test"
 
FROM builder AS cxx_builder
RUN git clone https://github.com/llvm/llvm-project.git
#Install latest cmake 
RUN wget https://github.com/Kitware/CMake/releases/download/v3.19.2/cmake-3.19.2-Linux-x86_64.sh
RUN mkdir -p /usr/bin/cmake-3.19
RUN chmod +x cmake-3.19.2-Linux-x86_64.sh && ./cmake-3.19.2-Linux-x86_64.sh --skip-license --prefix=/usr/bin/cmake-3.19
ENV PATH="/usr/bin/cmake-3.19/bin:${PATH}"

#Build the CXX libs for polytracker, and another for targets
ENV CXX_DIR=/cxx_libs
ENV LLVM_CXX_DIR=../../llvm-project/llvm
ENV CLEAN_CXX_DIR=$CXX_DIR/clean_build
ENV BITCODE=/cxx_bitcode
ENV POLY_CXX_DIR=$CXX_DIR/poly_build
ENV CC="gclang"
ENV CXX="gclang++"

RUN mkdir -p $CXX_DIR
WORKDIR $CXX_DIR

RUN mkdir -p $CLEAN_CXX_DIR && mkdir -p $BITCODE
WORKDIR $CLEAN_CXX_DIR

RUN cmake -GNinja ${LLVM_CXX_DIR} \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLIBCXXABI_ENABLE_SHARED=NO \
  -DLIBCXX_ENABLE_SHARED=NO \
  -DLIBCXX_CXX_ABI="libcxxabi" \
  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" 

ENV WLLVM_BC_STORE=$BITCODE
RUN ninja cxx cxxabi

WORKDIR $CXX_DIR

RUN mkdir -p $POLY_CXX_DIR 
WORKDIR  $POLY_CXX_DIR
RUN cmake -GNinja ${LLVM_CXX_DIR} \
  -DLLVM_ENABLE_LIBCXX=ON \
  -DLIBCXX_ABI_NAMESPACE="__p" \
	-DLIBCXXABI_ENABLE_SHARED=NO \
	-DLIBCXX_ENABLE_SHARED=NO \
  -DLIBCXX_ABI_VERSION=2 \
  -DLIBCXX_CXX_ABI="libcxxabi" \
  -DLIBCXX_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" 

ENV WLLVM_BC_STORE=$BITCODE
RUN ninja cxx cxxabi

FROM cxx_builder as dev

WORKDIR /
COPY . /polytracker
WORKDIR /polytracker
#COPY --from=cxx_builder $POLY_BC /
#copy --from=cxx_builder $CLEAN_BC /
COPY --from=cxx_builder $BITCODE /
COPY --from=cxx_builder /cxx_libs /
RUN mv /cxx_libs /polytracker/
ENV CXX_LIBS="/polytracker/cxx_libs"

RUN pip3 install pytest .
RUN rm -rf build && mkdir -p build
WORKDIR /polytracker/build
RUN ln -s /usr/bin/llvm-link-10 /usr/bin/llvm-link
#ENV PATH="/usr/lib/llvm-7/bin:${PATH}"
RUN cmake -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE .. && ninja install
ENV PATH="/polytracker/build/bin/:${PATH}"
ENV CC=polybuild
ENV CXX=polybuild++
ENV LLVM_COMPILER=clang
RUN mkdir -p "/build_artifacts"

# Set the BC store path to the <install_path>/cxx_libs/bitcode/bitcode_store}
#ENV WLLVM_BC_STORE="/polytracker/build/share/polytracker/cxx_libs/bitcode/bitcode_store"
ENV WLLVM_ARTIFACT_STORE="/build_artifacts"
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
WORKDIR /polytracker 
