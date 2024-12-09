################################################################
# Builder Image                                                #
################################################################
FROM rust:1.75 as builder
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
FROM debian:bookworm-slim as runtime

# We listen on standard port 80
EXPOSE 80

# Curl is needed for docker-compose healthcheck.
# OpenSSL is needed for root certs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Then copy in our pre-built app
COPY --from=builder /usr/local/bin/did-webplus-vdr /usr/local/bin/

ENV RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/did-webplus-vdr"]
