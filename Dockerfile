# Stage 1: Build
FROM gcc:latest AS build

ARG SSL=mbedtls
ARG BUILD_TYPE=debug
ARG SHMEM=true

RUN \
	apt update && \
	apt install -y \
		cmake \
		libconfig-dev \
		libprotobuf-c-dev

# Build and install Mbed TLS 3.x from source
WORKDIR /mbedtls
RUN \
	curl -o mbedtls.tar.bz2 -L https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2 && \
	tar -jxvf mbedtls.tar.bz2 && \
	cd mbedtls-* && \
	cmake -Bbuild -H. && \
        cmake --build build && \
        cmake --install build

WORKDIR /umurmur

COPY CMakeLists.txt .
COPY umurmur.conf.example .
COPY cmake cmake
COPY src src

RUN \
	cmake -Bbuild -H. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_SHAREDMEMORY_API=${SHMEM} -DSSL=${SSL} && \
        cmake --build build

# Stage 2: Runtime
FROM debian:unstable-slim

RUN \
	apt update && \
	apt install -y \
		libconfig9 libprotobuf-c1 libssl3 && \
	rm -rf /var/lib/apt/lists/*

# # Copy the compiled binary from the build stage
COPY --from=build /usr/local/lib/ /usr/local/lib
COPY --from=build /umurmur/build/bin/umurmurd /usr/local/sbin/umurmurd
COPY --from=build /umurmur/umurmur.conf.example /usr/local/etc/umurmur/umurmur.conf

EXPOSE 64738

ENTRYPOINT ["/usr/local/sbin/umurmurd", "-d"]

