# Create a separate image with the latest source
FROM trailofbits/polytracker:latest
LABEL org.opencontainers.image.authors="lisa.overall@trailofbits.com"

RUN rm -rf /polytracker/examples/http/picohttpparser && mkdir -p /polytracker/examples/http/picohttpparser

WORKDIR /polytracker/examples/http/picohttpparser
RUN git clone https://github.com/h2o/picohttpparser.git
COPY Makefile example_picohttpparser.c /polytracker/examples/http/picohttpparser/

# Build and instrument
RUN polytracker build make -j$((`nproc`+1))
RUN polytracker instrument-targets --taint --ftrace example_picohttpparser
RUN mv example_picohttpparser.instrumented example_picohttpparser_track

# Note, the /workdir directory is intended to be mounted at runtime
VOLUME ["/workdir"]
WORKDIR /workdir
