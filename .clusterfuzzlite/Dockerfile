# ClusterFuzzLite build image: the OSS-Fuzz builder, the libraries the node
# links, and secp256k1 and RandomX at the commits the top-level Makefile pins.
FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install -y --no-install-recommends \
        make cmake git pkg-config autoconf automake libtool patchelf zip \
        libssl-dev libdb5.3++-dev libsodium-dev nlohmann-json3-dev \
        libboost-system-dev libsqlite3-dev
# The pinned dependencies first, from the Makefile alone, so a source change
# does not rebuild them.
COPY Makefile $SRC/bitflash/Makefile
WORKDIR $SRC/bitflash
# Plain flags: the image's own CXXFLAGS ask for libc++, and the fuzz targets
# link libstdc++ (see build.sh).
RUN CFLAGS= CXXFLAGS= make deps-secp256k1 deps-randomx NPROC=4
COPY . $SRC/bitflash
COPY .clusterfuzzlite/build.sh $SRC/
