#!/usr/bin/env bash

# This script and the associated Dockerfiles are known to work on Debian and Ubuntu and have not been tested in other environments.

PASSTHROUGH_DOCKER_ARGS=""
DOCKERFILE="Dockerfile.nitro"
NO_CACHE="--no-cache"
IMAGE_NAME="ub-container"

while getopts bp: arg; do
    case "${arg}" in
        b)
            echo "(Re)building ${DOCKERFILE} container and saving as ${IMAGE_NAME} before running..."
            docker build "${NO_CACHE}" -t "${IMAGE_NAME}" -f "${DOCKERFILE}" .
            ;;
        p)
            PASSTHROUGH_DOCKER_ARGS=${OPTARG}
            ;;
        *)
            echo "== run.sh: run UB Docker container-as-executable =="
            echo "Optional: -b (builds the ${IMAGE_NAME} image first from ${DOCKERFILE})"
            echo "Optional: -p \"passthrough Docker executable arguments, in quotes\", c.f.:"
            python3 eval_nitro.py --help
            exit 1
            ;;
    esac
done

INTERNAL="/polytracker/the_klondike/nitro/build/ubet"
echo "run.sh: using $(pwd) as the volume attached to ${IMAGE_NAME} container internal location ${INTERNAL}"

docker run -it --rm --volume "$(pwd)":"${INTERNAL}" ub-container /usr/bin/bash ${PASSTHROUGH_DOCKER_ARGS}