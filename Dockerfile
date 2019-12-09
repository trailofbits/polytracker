FROM ubuntu:bionic
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

RUN apt-get -y update \
 && apt-get install -y \
    cmake \
    git \
    gnupg \
    ninja-build \
    python3-pip \
    python3.7 \
    wget

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | tee -a /etc/apt/sources.list && apt-get -y update && apt-get install -y llvm-7 clang-7

COPY . /polytracker

WORKDIR /polytracker

RUN rm -rf build && mkdir -p build

WORKDIR /polytracker/build

ENV PATH="/usr/lib/llvm-7/bin:${PATH}"

RUN cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ .. && ninja install

ENV CC=/polytracker/build/bin/polytracker/polyclang
ENV CXX=/polytracker/build/bin/polytracker/polyclang++
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /
