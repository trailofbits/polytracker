FROM trailofbits/polytracker:latest
MAINTAINER Evan Sultanik <evan.sultanik@trailofbits.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV CC=""
ENV CXX=""

RUN mkdir -p /polytracker/build

WORKDIR /polytracker/build

COPY scripts/compile.sh /
