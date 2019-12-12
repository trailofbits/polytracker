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
      ninja-build                                     \
      python3-pip                                     \
      python3.7

COPY . /polytracker

WORKDIR /polytracker

RUN rm -rf build && mkdir -p build

WORKDIR /polytracker/build

ENV PATH="/usr/lib/llvm-7/bin:${PATH}"

RUN cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE .. && ninja install

ENV CC=/polytracker/build/bin/polytracker/polyclang
ENV CXX=/polytracker/build/bin/polytracker/polyclang++

WORKDIR / 
