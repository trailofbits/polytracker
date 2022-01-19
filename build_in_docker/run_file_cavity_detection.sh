#!/usr/bin/env bash

cavities(){
  INPUT_PDF="$1"
  RESULT_DIR="$2"
  TIMEOUT="$3"
  BASENAME="${INPUT_PDF%.pdf}"
  BASENAME="${BASENAME##*/}"
  SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

  make -C "${SCRIPTPATH}" "bin/mutool_track_no_control_flow"

  cp "${INPUT_PDF}" "${RESULT_DIR}/${BASENAME}.pdf"
  
  docker run -it --rm \
    --mount type=bind,source="${SCRIPTPATH}/bin",target=/sources/bin \
    --mount type=bind,source="${RESULT_DIR}",target=/workdir \
    trailofbits/polytrackerbuilder-mupdf /usr/bin/bash -c \
    "cd /workdir && timeout ${TIMEOUT} /sources/bin/mutool_track_no_control_flow draw -o output.png ${BASENAME}.pdf; if [ \$? -eq 124 ]; then touch ${BASENAME}.timeout; fi"

  mv -f "${RESULT_DIR}/output.png" "${RESULT_DIR}/${BASENAME}.png"
  mv -f "${RESULT_DIR}/polytracker.db" "${RESULT_DIR}/${BASENAME}.db"
  rm -f "${RESULT_DIR}/${BASENAME}.pdf"
  
  if [[ -f "${RESULT_DIR}/${BASENAME}.timeout" ]]
  then
    echo "${BASENAME}.pdf,-1,-1" >> "${RESULT_DIR}/cavities.csv"
    rm -f "${RESULTS_DIR}/${BASENAME}.timeout"
    return
  fi
  
  timeout "${TIMEOUT}" python3 cavities.py "${RESULT_DIR}/${BASENAME}.db" >> "${RESULT_DIR}/cavities.csv"
  
  if [ $? -eq 124 ]
  then
    echo "${BASENAME}.pdf,-2,-2" >> "${RESULT_DIR}/cavities.csv"
  fi

  return
}

if [[ ! -d "results" ]]
then
  mkdir "results"
fi

for file in "$@"; do
  cavities "$(readlink -f ${file})" "$(pwd)/results" 100
done