#!/usr/bin/env zsh

# Quick-and-dirty build against all available SSL libraries

export CODE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." && pwd -P)"
export BUILD_TYPE=debug
export SHMEM=true

for S in mbedtls openssl gnutls; do
	cd ${CODE_DIR}
	rm -rf build-${S} && \
	cmake -Bbuild-${S} -DSSL=${S} \
		-DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
		-DCMAKE_RULE_MESSAGES=ON \
		-DUSE_SHAREDMEMORY_API=${SHMEM} \
		&& \
	cmake --build build-${S} && \
	ctest --test-dir build-${S} --output-on-failure -V && \
	cd -
done
