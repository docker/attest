#!/bin/bash
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
    rm -rf "${TESTDATA_PATH:?}/${NO_SBOM_NO_PROVENANCE_INDEX_DIR:?}"
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
    echo "Building $NO_SBOM_NO_PROVENANCE_INDEX_DIR..."
    docker buildx build "$TEST_INDEX_DOCKERFILE_PATH" --sbom false --provenance false --platform linux/amd64 \
      --output type=oci,tar=false,name="$TEST_INDEX_REPO:$TEST_INDEX_TAG",dest="$TESTDATA_PATH/$NO_SBOM_NO_PROVENANCE_INDEX_DIR"
}

# Check required commands
check_command docker

TESTDATA_PATH="../test/testdata"
TEST_INDEX_DOCKERFILE_PATH="../test"
TEST_INDEX_REPO="test-index"
TEST_INDEX_TAG="test"
UNSIGNED_INDEX_DIR="unsigned-index"
NO_PROVENANCE_INDEX_DIR="no-provenance-index"
NO_SBOM_NO_PROVENANCE_INDEX_DIR="no-sbom-no-provenance-index"
ATTESTATION_PAYLOADTYPE="application/vnd.in-toto+json"

# Run steps
cleanup_testdata
build_unsigned_index
build_no_provenance_index
build_image

echo "Process completed successfully."
