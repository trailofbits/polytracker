FROM trailofbits/polytracker-llvm:b75b84ed4ce03bc4250c32063d08a1cbd8a05e02

MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>
MAINTAINER Carson Harmon <carson.harmon@trailofbits.com>

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update  \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ninja-build                                     \
      python3-pip                                     \
      python3.8-dev                                   \
      libgraphviz-dev                                 \
      graphviz										  \
      libsqlite3-dev                                  \
      vim                                             \
      gdb                                             \
      sqlite3

# For some reason, cxxabi.h alone is installed in the wrong subdirectory:
RUN if [ ! -f "/cxx_libs/poly_build/include/c++/v1/cxxabi.h" ]; then \
      ln -s /cxx_libs/poly_build/include/c++/v1/include/c++/v1/cxxabi.h /cxx_libs/poly_build/include/c++/v1/ \
      ln -s /cxx_libs/poly_build/include/c++/v1/include/c++/v1/__cxxabi_config.h /cxx_libs/poly_build/include/c++/v1/; \
    fi

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 10
RUN python3 -m pip install pip && python3 -m pip install pytest

COPY . /polytracker
WORKDIR /polytracker
RUN pip3 install .
RUN mkdir /polytracker/build
WORKDIR /polytracker/build
RUN cmake -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_VERBOSE_MAKEFILE=TRUE -DCXX_LIB_PATH=/cxx_libs .. 
RUN ninja install


# Setting up build enviornment for targets 
ENV POLYTRACKER_CAN_RUN_NATIVELY=1
ENV CC=/polytracker/build/bin/polybuild_script
ENV CXX=/polytracker/build/bin/polybuild_script++
ENV PATH=/polytracker/build/bin:$PATH
