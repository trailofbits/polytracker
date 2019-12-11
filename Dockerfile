FROM ubuntu:bionic
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

RUN apt-get -y update && apt-get install -y cmake nlohmann-json-dev gnupg wget ninja-build python3.7 python3-pip git

RUN python3.7 -m pip install pytest

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | tee -a /etc/apt/sources.list && apt-get -y update && apt-get install -y llvm-7 clang-7

WORKDIR /

RUN git clone https://github.com/RoaringBitmap/CRoaring.git

WORKDIR /CRoaring

RUN mkdir -p build && cd build && cmake .. && make && make install

COPY . /polytracker

WORKDIR /polytracker

RUN rm -rf build && mkdir -p build

WORKDIR /polytracker/build

ENV PATH="/usr/lib/llvm-7/bin:${PATH}"

RUN cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE .. && ninja install

ENV CC=/polytracker/build/bin/polytracker/polyclang
ENV CXX=/polytracker/build/bin/polytracker/polyclang++
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR / 
