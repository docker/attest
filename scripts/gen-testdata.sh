#!/bin/bash

#   Copyright Docker attest authors

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set -eo pipefail

echo "Starting the process to generate testdata..."

# Define functions
function check_command () {
    command -v "$1" >/dev/null 2>&1 || { echo >&2 "This script requires $1 but it's not installed.  Aborting."; exit 1; }
}

function cleanup_testdata () {
    echo "Cleaning up existing testdata..."
    rm -rf "${TESTDATA_PATH:?}/${UNSIGNED_INDEX_DIR:?}"
    rm -rf "${TESTDATA_PATH:?}/${NO_PROVENANCE_INDEX_DIR:?}"
    rm -rf "${TESTDATA_PATH:?}/${UNSIGNED_IMAGE_DIR:?}"
}

function build_unsigned_index () {
    echo "Building $UNSIGNED_INDEX_DIR..."
    docker buildx build "$TEST_INDEX_DOCKERFILE_PATH" --sbom true --provenance true --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_INDEX_REPO:$TEST_INDEX_TAG",dest="$TESTDATA_PATH/$UNSIGNED_INDEX_DIR"
}

function build_no_provenance_index () {
    echo "Building unsigned $NO_PROVENANCE_INDEX_DIR..."
    docker buildx build "$TEST_INDEX_DOCKERFILE_PATH" --sbom true --provenance false --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_INDEX_REPO:$TEST_INDEX_TAG",dest="$TESTDATA_PATH/$NO_PROVENANCE_INDEX_DIR"
}

function build_image () {
    echo "Building $UNSIGNED_IMAGE_DIR..."
    docker buildx build "$TEST_INDEX_DOCKERFILE_PATH" --sbom false --provenance false --platform linux/amd64 \
      --output type=oci,tar=false,name="$TEST_INDEX_REPO:$TEST_INDEX_TAG",dest="$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR"
}

# Check required commands
check_command docker

TESTDATA_PATH="../test/testdata"
TEST_INDEX_DOCKERFILE_PATH="../test"
TEST_INDEX_REPO="test-image"
TEST_INDEX_TAG="test"
UNSIGNED_INDEX_DIR="unsigned-index"
NO_PROVENANCE_INDEX_DIR="no-provenance-index"
UNSIGNED_IMAGE_DIR="unsigned-image"
ATTESTATION_PAYLOADTYPE="application/vnd.in-toto+json"

# Run steps
cleanup_testdata
build_unsigned_index
build_no_provenance_index
build_image

echo "Process completed successfully."
