#!/bin/bash

# This script runs the mutool cavity detection evaluation.
# It is intended to be run on a clean system, such as a cloud instance.
# In order to run the evaluation the following (rough) steps are performed:
# 1. Clone the taint-dag branch of the polytracker repository
# 2. Do a full build of the polytracker docker image from the taint-dag branch
# 3. Build the examples images using the build.sh script in the examples dir
# 4. Download the govdocs pdf-corpus, at least many files as the user specified
#    or the DEFAULT_SAMPLE_SIZE. If the destination already contains the required
#    number this step is skipped.
# 5. Run the file cavity detection on the corpus, store results
# 6. Run the verification of detected cavities

# Pre-requisites:
# git python3.9 docker

######## Configuration ########################################################

# Default directory for evaluation, used if not overriden by user
DEFAULT_ROOT="/tmp/polytracker-eval"

# Default number of pdf-files to at least run the evaluation on
DEFAULT_SAMPLE_SIZE=3000

# URL to govdocs zip-files
GOVDOCS_URL="https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles"

# URL to the Polytracker repo
POLYTRACKER_URL="https://github.com/trailofbits/polytracker.git"

# Final component in the path to polytracker repo
POLYTRACKER_DIR="polytracker"

# Name of polytracker docker image
POLYTRACKER_IMAGE="trailofbits/polytracker"

# Name of taint-dag branch
TAINTDAG_BRANCH="taint-dag"

# Final component in path to input corpus
CORPUS_DIR="corpus"

# Final component in path to results
RESULTS_DIR="results"

# Path segments after polytracker dir to get the examples build.sh
EXAMPLES_BUILDSH="examples/build.sh"

# Path to logfile from builds/git etc.
LOGFILE="/tmp/polytracker-eval-log"

# Name of python binary
PYTHON_BIN=python3

# Method used to mutate files during verification
MUTATION_TYPE="flip"

# File cavitiy detection type, currently all cavity bytes, one at a time
# and a sampled subset of the remaining bytes.
VERIFICATION_TYPE="singlebyte"

######## Pre-requisites #######################################################
# Will install prerequisites if on the Ubuntu platform
function install_prerequisites_ubuntu() {
	echo "Installing pre-requisites"
	(apt-get update && apt-get install -y git docker.io python3 python3-numpy unzip) || fail "Failed to install pre-requisites."
	groupadd docker
	usermod -aG docker "${SUDO_USER}" || fail "Failed to add user ${SUDO_USER} to group docker."
	echo "Either logout and login again or run 'newgrp docker' as user ${SUDO_USER} to activate docker group."
	exit 0
}

######## Subtasks #############################################################

# 1. Clones polytracker git repository, taint-dag branch
# args:
#  - polytracker directory
function clone_taintdag() {
	(git clone --branch="$TAINTDAG_BRANCH" "$POLYTRACKER_URL" "${1}" >>"$LOGFILE" 2>&1) ||
		fail "Failed to clone repository from ${POLYTRACKER_URL} to ${1}."
}

# 2. Builds the polytracker docker image
# args:
#  - polytracker directory
function build_polytracker_docker_image() {
	echo "Build image"
	(cd "${1}" && docker build -t "$POLYTRACKER_IMAGE" . >>"$LOGFILE" 2>&1) || fail "Failed to build polytracker image."
	echo "Done"
}

# 3. Build the example images
# args:
#  - polytracker directory
function build_example_images() {
	build_script="${1}/$EXAMPLES_BUILDSH"
	echo "Build example images"
	"$build_script" >>"$LOGFILE" 2>&1 || fail "Failed to build example images."
	echo "Done"
}

# 4. Download the corpus
# args:
#  - corpus directory
#  - target number of files
function download_govdocs_pdf_corpus() {
	echo "download corpus to ${1}. At least ${2} files"
	corpus_dir=${1}
	sample_size=${2}
	# While there is less than target number of files, download
	i=0
	while [[ $(find "${corpus_dir}" -name '*.pdf' | wc -l) -lt "${sample_size}" ]]; do

		base=$(printf '%03d' "$i")
		if [ ! -d "${corpus_dir}/${base}" ]; then
			fname=$base.zip
			tmpname=$corpus_dir/$fname.tmp
			dstname=$corpus_dir/$fname

			# Download zip, store as tmpname and rename on completion
			wget -O "$tmpname" "$GOVDOCS_URL/$fname" >>"$LOGFILE" 2>&1 || fail "Failed to download ${fname} from ${GOVDOCS_URL}"
			mv "$tmpname" "$dstname" || fail "Failed to create file ${dstname}"

			unzip "${dstname}" -d "${corpus_dir}" >>"$LOGFILE" 2>&1 || fail "Failed to unzip ${dstname}"

			# Remove all non-pdfs (need to add write permission to do so), and the zipfile
			chmod -R u+w "${corpus_dir}/${base}"
			find "${corpus_dir}/${base}" -type f | grep -P '.*(?<!.pdf)$' | xargs rm
			rm "$dstname"
		fi

		i=$((i + 1))
	done
}

# 5. Run file cavity detection
# args:
#  - polytracker directory
#  - corpus directory
#  - results directory
#  - sample_size
function file_cavity_detection() {
	polytracker_dir=${1}
	corpus_dir=${2}
	results_dir=${3}
	sample_size=${4}

	echo "Run file cavity detection"
	# Drop any old cavities.csv, otherwise we will append to it and
	# things won't work as expected.
	cavcsv="${results_dir}/cavities.csv"
	[ -f "$cavcsv" ] && rm "$cavcsv"

	find "$corpus_dir" -type f | head -n "${sample_size}" | $PYTHON_BIN -u "${polytracker_dir}/build_in_docker/file_cavity_detection.py" \
		--tool mutool --output-dir "${results_dir}" --drop-tdag - 2>&1 | tee "${LOGFILE}" || fail "File cavity detection failed."

	echo "Done"
}

# 6. Verify detected cavities
function verify_detected_cavities() {
	polytracker_dir=${1}
	corpus_dir=${2}
	results_dir=${3}
	sample_size=${4}

	echo "Verify cavities"
	find "$corpus_dir" -type f | head -n "${sample_size}" | "${PYTHON_BIN}" -u "${polytracker_dir}/build_in_docker/verify_cavities.py" \
		--results "${results_dir}" --method=${MUTATION_TYPE} --type=${VERIFICATION_TYPE} --tool mutool - | tee "${LOGFILE}" ||
		fail "File cavity verification failed."

	echo "Done"
}

######## Main Operation #######################################################

function help() {
	echo "eval_mutool.sh - a tool do run mutool file cavity detection."
	echo "Corpus is from govdocs, only pdfs are choosen."
	echo "Usage:"
	echo "./eval_mutool.sh [-h] [-d directory] [-n filecount] [-s stepno] [-p]"
	echo " -d target directory, where all content is stored"
	echo " -n number of pdf-files to process"
	echo " -s step number:"
	echo "    1: clone polytracker taint-dag repo"
	echo "    2: build polytracker docker image"
	echo "    3: build example docker images"
	echo "    4: download corpus"
	echo "    5: run file cavity detection"
	echo "    6: verify detected cavities"
	echo " -p install prerequisites, use sudo to install."
	exit 0
}

function fail() {
	echo "Script failed: ${1}"
	exit 1
}

function create_directories() {
	for path in "$@"; do
		if [ ! -d "${path}" ]; then
			echo "Creating directory ${path}"
			mkdir "${path}" || fail "Failed to create directory ${path}"
		fi
	done
}

function main() {

	# Drop any old logfiles
	rm -f $LOGFILE

	first_step=1
	last_step=6

	target_dir=${DEFAULT_ROOT}
	sample_size=${DEFAULT_SAMPLE_SIZE}
	while getopts hd:n:s:p flag; do
		case "${flag}" in
		d) target_dir=${OPTARG} ;;
		n) sample_size=${OPTARG} ;;
		s)
			first_step=${OPTARG}
			last_step=${first_step}
			;;
		p) install_prerequisites_ubuntu ;;
		h) help ;;
		*) help ;;
		esac
	done

	echo "targetdir ${target_dir}"
	echo "sample_size ${sample_size}"
	echo "steps ${first_step}-${last_step}"

	[[ ${first_step} -gt 0 ]] || fail "Step must be >0."
	[[ ${last_step} -lt 7 ]] || fail "Step must be <=6."
	[[ ${sample_size} -gt 0 ]] || fail "Sample size must be >0."
	if [ -d "${target_dir}" ]; then
		read -pr "Directory ${target_dir} exists. Files might be overwritten. Use? [y/n]" prompt
		[[ $prompt == "y" ]] || fail "Target directory ${target_dir} shouldn't be used."
	fi

	# Defines the directories used in processing
	polytracker_dir=${target_dir}/${POLYTRACKER_DIR}
	corpus_dir=${target_dir}/${CORPUS_DIR}
	results_dir=${target_dir}/${RESULTS_DIR}

	create_directories "$target_dir" "$polytracker_dir" "$corpus_dir" "$results_dir"

	step=${first_step}
	# Step 1 clone polytracker
	[[ ${step} -eq 1 ]] && [[ ${step} -le ${last_step} ]] && clone_taintdag "${polytracker_dir}" && step=$((step + 1))

	# Step 2 build docker image
	[[ ${step} -eq 2 ]] && [[ ${step} -le ${last_step} ]] && build_polytracker_docker_image "${polytracker_dir}" &&
		step=$((step + 1))

	# Step 3 build example images
	[[ ${step} -eq 3 ]] && [[ ${step} -le ${last_step} ]] && build_example_images "${polytracker_dir}" &&
		step=$((step + 1))

	# Step 4 download govdocs corpus
	[[ ${step} -eq 4 ]] && [[ ${step} -le ${last_step} ]] && download_govdocs_pdf_corpus "${corpus_dir}" \
		"${sample_size}" && step=$((step + 1))

	# Step 5 file cavity detection
	[[ ${step} -eq 5 ]] && [[ ${step} -le ${last_step} ]] && file_cavity_detection "${polytracker_dir}" "${corpus_dir}" \
		"${results_dir}" "${sample_size}" && step=$((step + 1))

	# Step 6 verification of cavities
	[[ ${step} -eq 6 ]] && [[ ${step} -le ${last_step} ]] && verify_detected_cavities "${polytracker_dir}" "${corpus_dir}" \
		"${results_dir}" "${sample_size}" && step=$((step + 1))
	echo "STEP is ${step}"
}

main "$@"
