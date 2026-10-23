#!/usr/bin/env bash
set -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
source tests/ci/common_posix_setup.sh

# This test file is designed to replicate the internal FIPS callback build defined in the build-glue package

# This should follow AWS-LC-Build-GLue/bin/fips_tests.sh maybe_run_fips_tests
function maybe_run_fips_tests() {
  expect_fips_mode=1
  module_status=$("${BUILD_ROOT}/tool/bssl" isfips)
  [[ "${expect_fips_mode}" == "${module_status}" ]] || {
    echo >&2 "FIPS Mode validation failed."
    exit 1
  }
  # Mainline AWS-LC does not have the CAVP tests anymore so only run the test_fips branch
  "${BUILD_ROOT}/util/fipstools/test_fips"
}

# This should follow AWS-LC-Build-GLue/bin/fips_tests.sh maybe_run_fips_break_tests
function maybe_run_fips_break_tests() {
  break_kat_executable="${BUILD_ROOT}/break-kat"
  pushd "${SRC_ROOT}"
  go build -o "$break_kat_executable" "./util/fipstools/break-kat.go"
  "$break_kat_executable" -list-tests

  working_bssl="${BUILD_ROOT}/tool/bssl"
    broken_bssl="${BUILD_ROOT}/tool/brokenbssl"
  "$working_bssl" isfips

  # This breaks a local copy of bssl that will not be included in the build artifacts
  "$break_kat_executable" "$working_bssl" DRBG >"$broken_bssl"
  chmod +x "$broken_bssl"
  if ! ("$broken_bssl" isfips 2>&1 >/dev/null || true) |
    grep -q "DRBG"; then
    echo "Broken bssl did not mention DRBG failure in startup"
    exit 1
  fi
  popd
}

# run_broken_test runs $1 (a crypto_test binary) with the FIPSCallback tests and
# the given expected failure name. The test asserts that the module reported
# the failure through the callback, failed the triggering operation, and then
# stayed in the error state without aborting.
function run_broken_test() {
  local test_binary="$1"
  local expected_failure="$2"
  FIPS_CALLBACK_TEST_EXPECTED_FAILURE="${expected_failure}" \
    "${test_binary}" --gtest_filter="FIPSCallback.*"
}

# expect_fatal_failure runs $1 and checks that the process invoked the FIPS
# failure callback with each of the remaining arguments and then aborted
# (SIGABRT, exit status 134) rather than continuing. This is the required
# behaviour for integrity failures even when a callback is linked.
function expect_fatal_failure() {
  local test_binary="$1"
  shift
  local output status expected_message
  set +e
  output=$("${test_binary}" --gtest_filter="FIPSCallback.*" 2>&1 >/dev/null)
  status=$?
  set -e
  echo "${output}"
  if [[ "${status}" -ne 134 ]]; then
    echo "Expected ${test_binary} to abort with SIGABRT (134) but it exited with ${status}"
    exit 1
  fi
  for expected_message in "$@"; do
    if ! echo "${output}" | grep -q "AWS_LC_fips_failure_callback: ${expected_message}"; then
      echo "Callback was not invoked with '${expected_message}' before the abort"
      exit 1
    fi
  done
  if ! echo "${output}" | grep -q "AWS-LC FIPS failure caused by:"; then
    echo "Fatal failure was not reported on stderr before the abort"
    exit 1
  fi
}

function run_all_break_tests() {
  original_test="${BUILD_ROOT}/crypto/crypto_test"
  broken_test="${BUILD_ROOT}/crypto/crypto_test_broken"

  # By default the test should pass and the callback must never be invoked
  $original_test --gtest_filter="FIPSCallback.*"

  # Break the tests
  KATS=$(go run "${SRC_ROOT}/util/fipstools/break-kat.go" --list-tests)
  for kat in $KATS; do
    go run "${SRC_ROOT}/util/fipstools/break-kat.go" "$original_test" "$kat" > "$broken_test"
    chmod +x "$broken_test"
    case "$kat" in
      SHA-256|HMAC-SHA-256)
        # These are the CASTs that guard the integrity test. Breaking them
        # fails the integrity test, which is fatal regardless of the callback.
        expect_fatal_failure "$broken_test" "${kat} KAT failed." "Integrity test failed"
        ;;
      *)
        # When a callback is defined AWS-LC does not abort; the module enters
        # the error state and the test checks the post-failure behaviour.
        run_broken_test "$broken_test" "$kat"
        ;;
    esac
  done

  for TEST in RSA_PWCT EC_PWCT EDDSA_PWCT MLKEM_PWCT MLDSA_PWCT; do
      export BORINGSSL_FIPS_BREAK_TEST="${TEST}"
      run_broken_test "$original_test" "${TEST}"
      unset BORINGSSL_FIPS_BREAK_TEST
  done

}

# run_integrity_break_test corrupts the FIPS module inside crypto_test with
# break-hash.go so that the real integrity hash check fails at power-on, and
# checks that the callback is invoked and the process still aborts. This needs
# a build without BORINGSSL_FIPS_BREAK_TESTS, where the hash check is enforced.
function run_integrity_break_test() {
  original_test="${BUILD_ROOT}/crypto/crypto_test"
  broken_test="${BUILD_ROOT}/crypto/crypto_test_broken_hash"

  go run "${SRC_ROOT}/util/fipstools/break-hash.go" "$original_test" "$broken_test"
  chmod +x "$broken_test"
  expect_fatal_failure "$broken_test" "FIPS integrity test failed." "Integrity test failed"
}

echo "Testing AWS-LC static breakable build with custom callback and Jitter enabled"
build_and_test -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DFIPS=1 \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_INCLUDEDIR=include \
  -DCMAKE_INSTALL_BINDIR=bin \
  -DCMAKE_C_FLAGS="-ggdb -DBORINGSSL_FIPS_BREAK_TESTS -DAWSLC_FIPS_FAILURE_CALLBACK" \
  -DCMAKE_CXX_FLAGS="-DAWSLC_FIPS_FAILURE_CALLBACK" \
  -DBUILD_TESTING=ON -DBUILD_LIBSSL=ON \
  -DENABLE_FIPS_ENTROPY_CPU_JITTER=1

maybe_run_fips_tests
maybe_run_fips_break_tests
run_all_break_tests

echo "Testing AWS-LC static build with custom callback and Jitter enabled"
build_and_test -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DFIPS=1 \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_INCLUDEDIR=include \
  -DCMAKE_INSTALL_BINDIR=bin \
  -DCMAKE_C_FLAGS="-ggdb -DAWSLC_FIPS_FAILURE_CALLBACK" \
  -DCMAKE_CXX_FLAGS="-DAWSLC_FIPS_FAILURE_CALLBACK" \
  -DBUILD_TESTING=ON -DBUILD_LIBSSL=ON \
  -DENABLE_FIPS_ENTROPY_CPU_JITTER=1

maybe_run_fips_tests
# Can't run maybe_run_fips_break_tests or run_all_break_tests since they require BORINGSSL_FIPS_BREAK_TESTS
run_integrity_break_test
