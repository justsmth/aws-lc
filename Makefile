# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

init-submodules:
	git submodule update --init --recursive

deinit-submodules:
	git submodule deinit --all -f

update-s2n-bignum:
	git submodule update --init --remote --checkout -- third-party/s2n-bignum

.PHONY: init-submodules deinit-submodules update-s2n-bignum
