#!/usr/bin/env bash

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
            echo "Required: -p \"passthrough Docker executable arguments to hand to eval.py, in quotes\", c.f.:"
            python3 eval_nitro.py --help
            exit 1
            ;;
    esac
done

#echo "Running last build of ub-container: eval_nitro.py with args '${PASSTHROUGH_DOCKER_ARGS}'..."

INTERNAL="/polytracker/the_klondike/nitro/build/ubet"
echo "Using $(pwd) as the volume attached to ${INTERNAL}"

docker run -it --rm --volume "$(pwd)":"${INTERNAL}" ub-container /usr/bin/bash ${PASSTHROUGH_DOCKER_ARGS}
