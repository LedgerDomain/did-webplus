################################################################
# Builder Image                                                #
################################################################
FROM rust:1.90 AS builder
WORKDIR /workdir

# Install deps/reqs
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    rustup component add rustfmt && \
    apt-get update && \
    apt-get -y install lld clang ssh-tools

# Grab Cargo files for layer caching purposes
ADD Cargo.lock .
ADD Cargo.toml .

# Install all files now
ADD . .

# This is either "release" or "debug"
ARG RELEASE_TYPE="debug"
ARG CARGO_BUILD_ARGS=""

# Build for release or debug, and make sure it builds...
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    if [ "$RELEASE_TYPE" = "release" ]; then \
        SQLX_OFFLINE=true cargo build --package did-webplus-cli --bin did-webplus --all-features --release; \
        mv /workdir/target/release/did-webplus /usr/local/bin/did-webplus; \
    else \
        SQLX_OFFLINE=true cargo build --package did-webplus-cli --bin did-webplus --all-features; \
        mv /workdir/target/debug/did-webplus /usr/local/bin/did-webplus; \
    fi

# If we are release then also shrink our app's size to make our final container smaller
RUN if [ "$RELEASE_TYPE" = "release" ]; then \
    objcopy --only-keep-debug /usr/local/bin/did-webplus /usr/local/bin/did-webplus.debug && \
    objcopy --strip-debug --strip-unneeded /usr/local/bin/did-webplus && \
    objcopy --add-gnu-debuglink=/usr/local/bin/did-webplus.debug /usr/local/bin/did-webplus; \
fi


################################################################
# Runner Image                                                 #
################################################################
# Latest as of Aug 19, 2023
FROM debian:bookworm-slim AS runtime

# OpenSSL is needed for root certs.
# Install some other utilities for debugging purposes.
# nmap: port scanner
# curl: HTTP request tool
# jq: JSON parser
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl nmap curl jq
# TEMP HACK: don't apt-get clear or delete the lists, so that it's possible to
# apt-get install more packages that are useful for development/debugging.  The
# production docker image will clean and delete, and maybe not include nmap, curl, jq, etc.
#    \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/*

# Then copy in our pre-built app
COPY --from=builder /usr/local/bin/did-webplus /usr/local/bin/

# Our standard entrypoint
ENTRYPOINT ["/usr/local/bin/did-webplus"]
