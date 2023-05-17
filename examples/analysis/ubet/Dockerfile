FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y clang g++ python3

WORKDIR /polytracker/the_klondike/nitro/build/ubet

# Pass additional arguments to this exec from entrypoint in run.sh,
# they will get appended to the build cmd hence to here
ENTRYPOINT [ "python3", "eval_nitro.py" ]