################################################################
# Builder Image                                                #
################################################################
FROM rust:1.90.0-slim AS builder
WORKDIR /workdir

# Install deps/reqs
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    rustup component add rustfmt && \
    apt-get update && \
    apt-get -y install lld clang libssl-dev openssl pkg-config ssh-tools

# Grab Cargo files for layer caching purposes
ADD Cargo.lock .
ADD Cargo.toml .

# Install all files now
ADD . .

# This is either "release" or "debug"
ARG RELEASE_TYPE="release"
ARG CARGO_BUILD_ARGS=""

# Build for release or debug, and make sure it builds...
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    if [ "$RELEASE_TYPE" = "release" ]; then \
        SQLX_OFFLINE=true cargo build --package did-webplus-urd --bin did-webplus-urd --features postgres,sqlite --release; \
        mv /workdir/target/release/did-webplus-urd /usr/local/bin/did-webplus-urd; \
    else \
        SQLX_OFFLINE=true cargo build --package did-webplus-urd --bin did-webplus-urd --features postgres,sqlite; \
        mv /workdir/target/debug/did-webplus-urd /usr/local/bin/did-webplus-urd; \
    fi

# If we are release then also shrink our app's size to make our final container smaller
RUN if [ "$RELEASE_TYPE" = "release" ]; then \
    objcopy --only-keep-debug /usr/local/bin/did-webplus-urd /usr/local/bin/did-webplus-urd.debug && \
    objcopy --strip-debug --strip-unneeded /usr/local/bin/did-webplus-urd && \
    objcopy --add-gnu-debuglink=/usr/local/bin/did-webplus-urd.debug /usr/local/bin/did-webplus-urd; \
fi


################################################################
# Runner Image                                                 #
################################################################

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.authors="LedgerDomain <didwebplus@ledgerdomain.com>"

# We listen on standard port 80
EXPOSE 80

# OpenSSL is needed for root certs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Then copy in our pre-built app
COPY --from=builder /usr/local/bin/did-webplus-urd /usr/local/bin/

ENV RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/did-webplus-urd"]
