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
			libgraphviz-dev

RUN python3.7 -m pip install pip

RUN go get github.com/SRI-CSL/gllvm/cmd/...

ENV PATH="$PATH:/root/go/bin"

COPY . /polytracker

WORKDIR /polytracker

RUN python3.7 -m pip install pytest

RUN python3.7 -m pip install .

RUN rm /usr/bin/python3 
RUN cp /usr/bin/python3.7 /usr/bin/python3

RUN rm -rf build && mkdir -p build

WORKDIR /polytracker/build

ENV PATH="/usr/lib/llvm-7/bin:${PATH}"

RUN cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE .. && ninja install
ENV CC=/polytracker/build/bin/polytracker/polybuild/polybuild.py
ENV CXX=/polytracker/build/bin/polytracker/polybuild/polybuild++.py
RUN chmod +x ${CC}

# Set the BC store path to the <install_path>/cxx_libs/bitcode/bitcode_store}
ENV WLLVM_BC_STORE="/polytracker/build/bin/polytracker/cxx_libs/bitcode/bitcode_store"

WORKDIR /polytracker 
