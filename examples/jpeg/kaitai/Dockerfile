FROM trailofbits/polytracker
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

RUN rm -rf /polytracker/examples/jpeg/kaitai && mkdir -p /polytracker/examples/jpeg/kaitai

WORKDIR /polytracker/examples/jpeg

COPY . /polytracker/examples/jpeg/kaitai

RUN make -C /polytracker/examples/jpeg/kaitai clean && make -j$((`nproc`+1)) -C /polytracker/examples/jpeg/kaitai jpeg_example

# Note, the /workdir directory is intended to be mounted at runtime
VOLUME ["/workdir"]
WORKDIR /workdir
