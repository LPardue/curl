<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HTTP/3 over QMux

## What is QMux?

QMux ([draft-ietf-quic-qmux-01](https://datatracker.ietf.org/doc/draft-ietf-quic-qmux/))
provides QUIC's stream multiplexing over reliable byte streams (TCP+TLS)
instead of UDP datagrams. This enables HTTP/3 to run over TCP+TLS, using the
ALPN token `h3qx-01`.

## Status

HTTP/3 over QMux support in curl is **EXPERIMENTAL**. It requires a fork of
quiche with QMux support.

## Prerequisites

 - Rust toolchain (for building quiche)
 - CMake 3.22+
 - A C compiler

## Build quiche with QMux support

Clone the quiche fork with QMux support and build with the `ffi` and `qmux`
features:

     % git clone --recursive -b qmux-support https://github.com/LPardue/quiche
     % cd quiche
     % cargo build --package quiche --release --features ffi,qmux

Note the paths to the build artifacts:

     QUICHE_DIR=$PWD
     QUICHE_LIB=$QUICHE_DIR/target/release
     BSSL_INCLUDE=$QUICHE_DIR/quiche/deps/boringssl/src/include
     BSSL_LIB=$(dirname $(find $QUICHE_LIB -name libssl.a -path '*/quiche-*/out/*' | head -1))

## Build curl with QMux support

Clone curl and configure with CMake, pointing at the quiche build:

     % git clone -b curl-qmux-integration https://github.com/LPardue/curl
     % cd curl
     % mkdir build && cd build
     % cmake .. \
         -DUSE_QUICHE=ON \
         -DQUICHE_INCLUDE_DIR=$QUICHE_DIR/quiche/include \
         -DQUICHE_LIBRARY=$QUICHE_LIB/libquiche.a \
         -DOPENSSL_INCLUDE_DIR=$BSSL_INCLUDE \
         -DOPENSSL_CRYPTO_LIBRARY=$BSSL_LIB/libcrypto.a \
         -DOPENSSL_SSL_LIBRARY=$BSSL_LIB/libssl.a \
         -DCURL_USE_LIBPSL=OFF
     % cmake --build . -j$(nproc)

## Usage

Use `--http3-qmux` to make a request over QMux. The server must support TLS
with ALPN `h3qx-01`:

     % curl --http3-qmux -k https://127.0.0.1:4433/

There is no fallback. If the QMux connection fails, the request fails.

## Testing with the qmux-demo server

The quiche fork includes a demo server for testing:

     % cd $QUICHE_DIR
     % cargo run -p qmux-demo --bin qmux-server -- \
         --listen 127.0.0.1:4433 \
         --cert quiche/examples/cert.crt \
         --key quiche/examples/cert.key \
         --root /path/to/serve

Then in another terminal:

     % curl --http3-qmux -k https://127.0.0.1:4433/

## How it works

QMux reuses QUIC's stream multiplexing and HTTP/3 framing, but replaces
the UDP transport with a reliable byte stream (TCP+TLS). The curl
connection filter chain is:

    QMux (H3 framing) -> SSL (TLS 1.3, ALPN h3qx-01) -> TCP

The QMux filter uses quiche in "QMux mode" (`quiche_config_enable_qmux`),
which bypasses QUIC's packet layer, loss recovery, and congestion control
since the TCP+TLS carrier handles those concerns.

## Limitations

 - No fallback to HTTP/2 or HTTP/1.1 (use `--http3-qmux` only)
 - No happy eyeballing
 - No proxy support
 - No 0-RTT / early data
 - Requires quiche built with the `qmux` cargo feature
