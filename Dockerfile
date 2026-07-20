# Slim multi-platform build for libparcagpucupti.so
# Uses pre-built CUDA header images instead of full CUDA development images
# This significantly reduces build time and disk space requirements
#
# Thanks to Proton's dynamic CUPTI loading, we only need to build once
# and the library works with any CUDA version at runtime.

# CUDA header image (can be overridden at build time)
ARG CUDA_HEADERS=ghcr.io/parca-dev/cuda-headers:12

# Import CUDA headers
FROM ${CUDA_HEADERS} AS cuda-headers

# Build stage — use Ubuntu 20.04 for glibc 2.31 compatibility.
# The .so must run on older CUDA container images (based on Ubuntu 20.04/18.04)
# which have older glibc versions. Building on 24.04 produces a .so that requires
# GLIBC_2.38 and won't load on those containers.
FROM ubuntu:20.04 AS builder

# Install build tools (no CUDA toolkit needed).
# Ubuntu 20.04 ships CMake 3.16, but we need 3.18+. Download a newer CMake
# binary directly from GitHub releases rather than using a PPA.
RUN apt-get update && apt-get install -y \
    wget \
    ca-certificates \
    make \
    g++ \
    systemtap-sdt-dev \
    && wget -q https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.tar.gz -O /tmp/cmake.tar.gz \
    && tar -C /usr/local --strip-components=1 -xzf /tmp/cmake.tar.gz \
    && rm /tmp/cmake.tar.gz \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy CUDA headers from header image
COPY --from=cuda-headers /usr/local/cuda /usr/local/cuda

# Copy parcagpu source files and proton submodule
COPY src /build/src
COPY proton /build/proton
COPY CMakeLists.txt /build/

# Build the library (disable tests for Docker build)
RUN mkdir -p build && \
    cd build && \
    cmake -DCUDA_INCLUDE_DIR=/usr/local/cuda/include -DBUILD_TESTS=OFF .. && \
    make -j$(nproc)

# Export stage for extracting the library (used by Makefile and release binaries)
FROM scratch AS export
COPY --from=builder /build/build/lib/libparcagpucupti.so /

# Runtime image (for container registry)
FROM busybox:latest AS runtime
COPY --from=builder /build/build/lib/libparcagpucupti.so /usr/lib/libparcagpucupti.so
