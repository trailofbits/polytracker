FROM trailofbits/polytracker-llvm:16daa680dcff0dc86ebf6ae81f5382859695cb35

LABEL org.opencontainers.image.authors="evan.sultanik@trailofbits.com"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update  && \
      apt-get install -y \
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
            ca-certificates                                 \
            libstdc++-10-dev

RUN update-ca-certificates

RUN apt-get install -y software-properties-common && \
      # deadsnakes PPA allows us to install python3.10 on focal
      add-apt-repository ppa:deadsnakes/ppa && \
      apt-get -y update && \
      apt-get install -y \
            python3.10-dev \
            # make update-alternatives work
            python3.10-distutils \
            curl && \
      # need a pip compatible with 3.10
      curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10 && \
      update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 10 && \
      python3 -m pip install pytest

WORKDIR /blight
RUN git clone https://github.com/trailofbits/blight.git .
RUN pip3 install .

COPY . /polytracker

RUN mkdir /polytracker/build
WORKDIR /polytracker/build
RUN cmake -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE -DCXX_LIB_PATH=/cxx_libs ..
RUN ninja install


WORKDIR /polytracker
RUN pip3 install .

# Setting up build enviornment for targets
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
ENV PATH=/polytracker/build/bin:$PATH
ENV DFSAN_OPTIONS="strict_data_dependencies=0"
ENV COMPILER_DIR=/polytracker/build/share/polytracker
