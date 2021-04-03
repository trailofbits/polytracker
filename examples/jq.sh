#!/usr/bin/env bash

set -e

if [[ $# -gt 0 && $(realpath "$1") != $PWD/* ]]; then
  echo "Error: $0 can only be run on files that are in a subdirectory of \$PWD!"
  echo "Try \`cd\`ing to $(dirname "$1") and running this script from there."
  exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker -f "${SCRIPTPATH}/../Dockerfile" "${SCRIPTPATH}/.."
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-jq 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo-jq -f "${SCRIPTPATH}/Dockerfile-jq.demo" "${SCRIPTPATH}"
fi

rm -f $1.db
docker run --read-only -ti --rm -e POLYTRACE="1" -e POLYPATH="$1" -e POLYDB="$1.db" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-jq:latest jq . "$1"
echo trace saved to $1.db
