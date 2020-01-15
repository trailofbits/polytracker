FROM trailofbits/polytracker
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

RUN rm -rf /polytracker/examples/jpeg && mkdir -p /polytracker/examples/jpeg

WORKDIR /polytracker/examples

COPY . /polytracker/examples/jpeg

RUN make -C /polytracker/examples/jpeg clean && make -j$((`nproc`+1)) -C /polytracker/examples/jpeg jpeg_example

# Note, the /workdir directory is intended to be mounted at runtime
VOLUME ["/workdir"]
WORKDIR /workdir
