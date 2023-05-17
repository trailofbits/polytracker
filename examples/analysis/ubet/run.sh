#!/usr/bin/env bash

# This script and the associated Dockerfiles are known to work on Debian and Ubuntu and have not been tested in other environments.

PASSTHROUGH_DOCKER_ARGS=""
DOCKERFILE="Dockerfile.nitro"
NO_CACHE="--no-cache"

while getopts bp: arg; do
    case "${arg}" in
        b)
            echo "(Re)building ${DOCKERFILE} container before running..."
            docker build "${NO_CACHE}" -t ub-container -f "${DOCKERFILE}" .
            ;;
        p)
            PASSTHROUGH_DOCKER_ARGS=${OPTARG}
            ;;
        *)
            echo "== run.sh: run UB Docker container-as-executable =="
            echo "Optional: -b (builds the ub-container image first from ${DOCKERFILE} with --no-cache)"
            echo "Required: -p \"passthrough Docker executable arguments to hand to eval script, in quotes\", c.f.:"
            python3 eval_nitro.py --help
            exit 1
            ;;
    esac
done

INTERNAL="/polytracker/the_klondike/nitro/build/ubet"
echo "run.sh: using $(pwd) as the volume attached to container internal location ${INTERNAL}"

docker run -it --rm --volume "$(pwd)":"${INTERNAL}" ub-container /usr/bin/bash ${PASSTHROUGH_DOCKER_ARGS}