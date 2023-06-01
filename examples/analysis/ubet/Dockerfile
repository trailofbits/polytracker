FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive

# We just need the PolyTracker python analysis code to run eval_nitro.py, and not the PolyTracker llvm environment.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y clang g++ python3 python3-pip && \
    pip3 install polytracker

WORKDIR /polytracker/the_klondike/nitro/build/ubet