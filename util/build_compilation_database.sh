#!/usr/bin/env bash

set -e

BASE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}/" )/.." &> /dev/null && pwd )

TMP_DIR=`mktemp -d`
echo ${TMP_DIR}
AWS_LC_BUILD="${TMP_DIR}/AWS-LC-BUILD"
AWS_LC_INSTALL=${TMP_DIR}/AWS-LC-INSTALL

for arg in "$@"; do
  if [[ "$arg" == -G* ]]; then
    echo
    echo "################"
    echo "####    WARNING: Currently CMake only supports compilation database creation using the Ninja and Makefile generators: $arg"
    echo "################"
    echo
  fi
done

MY_CMAKE_FLAGS=("-GNinja" "-DCMAKE_BUILD_TYPE=Debug" "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" "-DCMAKE_INSTALL_PREFIX=${AWS_LC_INSTALL}")

set -ex

mkdir -p "${AWS_LC_BUILD}"
mkdir -p "${AWS_LC_INSTALL}"

cmake "${BASE_DIR}" -B "${AWS_LC_BUILD}" ${MY_CMAKE_FLAGS[@]} "${@}"
cmake --build "${AWS_LC_BUILD}" --target install

cp "${AWS_LC_BUILD}"/compile_commands.json "${BASE_DIR}"/
