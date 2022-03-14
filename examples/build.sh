#!/bin/bash
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
POLYTRACKER_ROOT="$( cd "$SCRIPTPATH"/.. >/dev/null 2>&1 ; pwd -P )"
IMG_BASE="trailofbits/polytracker-demo-"
DOCKERFILE_BASE="$SCRIPTPATH/Dockerfile-"
IMAGES=("mupdf" "openjpeg" "libjpeg")

for img in "${IMAGES[@]}"; do
  docker build -t "$IMG_BASE$img" -f "$DOCKERFILE_BASE$img.demo" $POLYTRACKER_ROOT
done

