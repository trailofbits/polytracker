#!/usr/bin/env bash

set -e

if [ "$(uname)" == "Darwin" ]; then
  # MacOS readlink doesn't support -f
  if ! command -v greadlink &> /dev/null
  then
      echo "\`greadlink\` could not be found."
      echo "Try installing it with \`brew install coreutils\`"
      exit 1
  fi
  READLINK="greadlink"
else
  READLINK="readlink"
fi

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

make -C "${SCRIPTPATH}" "bin/mutool_track_no_control_flow"

cavities(){
  INPUT_PDF="$1"
  RESULT_DIR="$2"
  TIMEOUT="$3"
  BASENAME="${INPUT_PDF%.pdf}"
  BASENAME="${BASENAME##*/}"

  echo "Detecting file cavities in ${BASENAME}.pdf ..."

  cp "${INPUT_PDF}" "${RESULT_DIR}/${BASENAME}.pdf"
  
  if docker run -it --rm \
    --mount type=bind,source="${SCRIPTPATH}/bin",target=/sources/bin \
    --mount type=bind,source="${RESULT_DIR}",target=/workdir \
    --workdir /workdir \
    trailofbits/polytrackerbuilder-mupdf /usr/bin/bash -c \
    "timeout ${TIMEOUT} /sources/bin/mutool_track_no_control_flow info ${BASENAME}.pdf" \
    > "${RESULT_DIR}/${BASENAME}.mutool.log" 2>&1
  then
    # mv -f "${RESULT_DIR}/output.png" "${RESULT_DIR}/${BASENAME}.png"
    mv -f "${RESULT_DIR}/polytracker.db" "${RESULT_DIR}/${BASENAME}.db"
    rm -f "${RESULT_DIR}/${BASENAME}.pdf"
  else
    retcode=$?
    if [ $retcode -eq 124 ]; then
      echo "\`mutool draw ${BASENAME}.pdf\` timed out after ${TIMEOUT} seconds"
      echo "${BASENAME}.pdf,-1,-1" >> "${RESULT_DIR}/cavities.csv"
    else
      echo "\`mutool draw ${BASENAME}.pdf\` exited with code ${retcode}"
      echo "see ${RESULT_DIR}/${BASENAME}.mutool.log"
      echo "${BASENAME}.pdf,-3,-3" >> "${RESULT_DIR}/cavities.csv"
    fi
    return
  fi

  if timeout "${TIMEOUT}" python3 cavities.py "${RESULT_DIR}/${BASENAME}.db" > .result.csv \
      2> "${RESULT_DIR}/${BASENAME}.cavities.log"; then
    cat .result.csv >> "${RESULT_DIR}/cavities.csv"
  else
    retcode=$?
    if [ $retcode -eq 124 ]; then
      echo "python3 cavities.py \"${RESULT_DIR}/${BASENAME}.db\" timed out after ${TIMEOUT} seconds"
      echo "${BASENAME}.pdf,-2,-2" >> "${RESULT_DIR}/cavities.csv"
    else
      echo "python3 cavities.py \"${RESULT_DIR}/${BASENAME}.db\" exited with code ${retcode}"
      echo "see ${RESULT_DIR}/${BASENAME}.cavities.log"
      echo "${BASENAME}.pdf,-4,-4" >> "${RESULT_DIR}/cavities.csv"
    fi
  fi

  rm -f .result.csv

  return
}

if [[ -f "results/cavities.csv" ]]
then
  echo "results/cavities.csv already exists!"
  echo "Move or delete it and try again."
  exit 1
elif [[ ! -d "results" ]]
then
  mkdir "results"
fi

for file in "$@"; do
  cavities "$(${READLINK} -f ${file})" "$(pwd)/results" 100
done

# TODO(surovic): Add printing of the below stats
#
# command: info
# timeout: 10s
# # of total cases: 100
# # of tracing timeouts:  41
# # of cavity detection timeouts: 0
# run artifact size (dbs and cavity file):  169mb
# runtime: 15m12s
