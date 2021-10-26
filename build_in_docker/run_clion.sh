#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# if [[ "$(docker images -q trailofbits/polytrackerbuilder 2> /dev/null)" == "" ]]; then
#    docker build -t trailofbits/polytrackerbuilder -f "${SCRIPTPATH}/Dockerfile" "${SCRIPTPATH}"
# fi
docker build -t trailofbits/polytrackerbuilder-clion -f "${SCRIPTPATH}/Dockerfile-clion" "${SCRIPTPATH}"

echo "Running the remote dev Docker container; ^C this process to end it."
# --mount type=bind,source="${SCRIPTPATH}/..",target=/tmp/polytracker
docker run -it --rm --cap-add sys_ptrace -p127.0.0.1:2222:22 --name polytracker_clion_remote_env trailofbits/polytrackerbuilder-clion
