FROM trailofbits/polytracker
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

RUN rm -rf /polytracker/examples/jpeg/libjpeg && mkdir -p /polytracker/examples/jpeg/libjpeg

WORKDIR /polytracker/examples/jpeg/libjpeg

RUN wget https://www.ijg.org/files/jpegsrc.v9c.tar.gz && tar -xzvf jpegsrc.v9c.tar.gz && rm jpegsrc.v9c.tar.gz

COPY Makefile example_libjpeg.c /polytracker/examples/jpeg/libjpeg/

RUN make

# Note, the /workdir directory is intended to be mounted at runtime
VOLUME ["/workdir"]
WORKDIR /workdir
