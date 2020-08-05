#!/usr/bin/env bash

if [[ $# -gt 0 && $(realpath "$1") != $PWD/* ]]; then
  echo "Error: $0 can only be run on files that are in a subdirectory of \$PWD!"
  echo "Try \`cd\`ing to $(dirname "$1") and running this script from there."
  exit 1
fi

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker ..
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-jq 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo-jq -f Dockerfile-jq.demo .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-jq:latest jq . "$1"
