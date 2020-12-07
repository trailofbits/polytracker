FROM ubuntu:bionic
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

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
			libc++abi-dev																		\
      ninja-build                                     \
			python3-pip																			\
      python3.7-dev																		\
			golang																					\
			libgraphviz-dev																	\
			graphviz

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 10
RUN python3 -m pip install pip

RUN go get github.com/SRI-CSL/gllvm/cmd/...

ENV PATH="$PATH:/root/go/bin"

RUN python3.7 -m pip install pytest

COPY . /polytracker

WORKDIR /polytracker

RUN pip3 install pytest .

RUN rm -rf build && mkdir -p build

WORKDIR /polytracker/build

ENV PATH="/usr/lib/llvm-7/bin:${PATH}"

RUN cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE .. && ninja install
ENV PATH="/polytracker/build/bin/:${PATH}"
ENV CC=polybuild
ENV CXX=polybuild++
ENV LLVM_COMPILER=clang
RUN mkdir -p "/build_artifacts"

# Set the BC store path to the <install_path>/cxx_libs/bitcode/bitcode_store}
ENV WLLVM_BC_STORE="/polytracker/build/share/polytracker/cxx_libs/bitcode/bitcode_store"
ENV WLLVM_ARTIFACT_STORE="/build_artifacts"

ENV POLYTRACKER_CAN_RUN_NATIVELY=1

WORKDIR /polytracker 
