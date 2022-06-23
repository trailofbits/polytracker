FROM trailofbits/polytracker-llvm:16daa680dcff0dc86ebf6ae81f5382859695cb35

LABEL org.opencontainers.image.authors="evan.sultanik@trailofbits.com"

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update  \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ninja-build                                     \
      python3-pip                                     \
      python3.8-dev                                   \
      libgraphviz-dev                                 \
      libjpeg-dev                                     \
      graphviz                                        \
      vim                                             \
      gdb                                             \
      libncurses5-dev                                 \
      apt-transport-https                             \
      ca-certificates
RUN update-ca-certificates

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 10
RUN python3 -m pip install pip && python3 -m pip install pytest

COPY . /polytracker

RUN mkdir /polytracker/build
WORKDIR /polytracker/build
RUN cmake -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE -DCXX_LIB_PATH=/cxx_libs .. 
RUN ninja install

WORKDIR /blight
RUN git clone https://github.com/trailofbits/blight.git .
RUN pip3 install .

WORKDIR /polytracker
RUN pip3 install .

# Setting up build enviornment for targets 
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
ENV PATH=/polytracker/build/bin:$PATH
ENV DFSAN_OPTIONS="strict_data_dependencies=0"
ENV COMPILER_DIR=/polytracker/build/share/polytracker