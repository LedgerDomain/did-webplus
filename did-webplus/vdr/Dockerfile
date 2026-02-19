################################################################
# Builder Image                                                #
################################################################
FROM rust:1.90 AS builder
WORKDIR /workdir

# Install deps/reqs (cached layer)
RUN rustup component add rustfmt && \
    apt-get update && \
    apt-get -y install lld clang ssh-tools && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency files first for better caching
COPY Cargo.lock Cargo.toml ./
COPY did-webplus/vdg/Cargo.toml ./did-webplus/vdg/
COPY did-webplus/vdr/Cargo.toml ./did-webplus/vdr/
COPY did-webplus/core/Cargo.toml ./did-webplus/core/
COPY did-webplus/cli/Cargo.toml ./did-webplus/cli/
COPY did-webplus/cli-lib/Cargo.toml ./did-webplus/cli-lib/
COPY did-key/Cargo.toml ./did-key/

# Create dummy source files to build dependencies only
RUN mkdir -p did-webplus/vdg/src && echo "fn main() {}" > did-webplus/vdg/src/main.rs && \
    mkdir -p did-webplus/vdr/src && echo "fn main() {}" > did-webplus/vdr/src/main.rs && \
    mkdir -p did-webplus/core/src && echo "" > did-webplus/core/src/lib.rs && \
    mkdir -p did-webplus/cli/src && echo "fn main() {}" > did-webplus/cli/src/main.rs && \
    mkdir -p did-webplus/cli-lib/src && echo "" > did-webplus/cli-lib/src/lib.rs && \
    mkdir -p did-key/src && echo "" > did-key/src/lib.rs

# Build dependencies only (this layer will be cached)
ARG RELEASE_TYPE="release"
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    if [ "$RELEASE_TYPE" = "release" ]; then \
        cargo build --package did-webplus-vdr --bin did-webplus-vdr --features postgres --release || true; \
    else \
        cargo build --package did-webplus-vdr --bin did-webplus-vdr --features postgres || true; \
    fi

# Now copy the actual source code
COPY . .

# Build the actual application
ARG CARGO_BUILD_ARGS=""
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=/workdir/target \
    if [ "$RELEASE_TYPE" = "release" ]; then \
        SQLX_OFFLINE=true cargo build --package did-webplus-vdr --bin did-webplus-vdr --features postgres --release; \
        mv /workdir/target/release/did-webplus-vdr /usr/local/bin/did-webplus-vdr; \
    else \
        SQLX_OFFLINE=true cargo build --package did-webplus-vdr --bin did-webplus-vdr --features postgres; \
        mv /workdir/target/debug/did-webplus-vdr /usr/local/bin/did-webplus-vdr; \
    fi

# If we are release then also shrink our app's size to make our final container smaller
RUN if [ "$RELEASE_TYPE" = "release" ]; then \
    objcopy --only-keep-debug /usr/local/bin/did-webplus-vdr /usr/local/bin/did-webplus-vdr.debug && \
    objcopy --strip-debug --strip-unneeded /usr/local/bin/did-webplus-vdr && \
    objcopy --add-gnu-debuglink=/usr/local/bin/did-webplus-vdr.debug /usr/local/bin/did-webplus-vdr; \
fi


################################################################
# Runner Image                                                 #
################################################################
# Latest as of Aug 19, 2023
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.authors="LedgerDomain <didwebplus@ledgerdomain.com>"

# We listen on standard port 80
EXPOSE 80

# Curl is needed for docker-compose healthcheck.
# OpenSSL is needed for root certs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Then copy in our pre-built app
COPY --from=builder /usr/local/bin/did-webplus-vdr /usr/local/bin/

ENV RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/did-webplus-vdr"]
