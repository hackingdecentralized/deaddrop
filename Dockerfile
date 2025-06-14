# ── 1) Base off the Foundry image ───────────────────────────────────────
FROM aztecprotocol/foundry:25f24e677a6a32a62512ad4f561995589ac2c7dc-arm64

# ── 2) Install rustup & toolchain ────────────────────────────────────
USER root
RUN apt-get update \
 && apt-get install -y curl build-essential ca-certificates jq \
 && rm -rf /var/lib/apt/lists/* \
 # install rustup non-interactive, set up stable toolchain
 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain=stable \
 # ensure cargo is on PATH
 && ln -s /root/.cargo/bin/rustc /usr/local/bin/rustc \
 && ln -s /root/.cargo/bin/cargo /usr/local/bin/cargo

ENV PATH=/root/.cargo/bin:$PATH

# ── 3) Set up your app directory ───────────────────────────────────────
WORKDIR /app
# if you want fast rebuilds you can mount your project at runtime;
# for a fully self-contained image, COPY your code instead:
COPY ./deadbug .

# ── 4) Build your Rust crate ──────────────────────────────────────────
RUN cargo build --release --target-dir ./build

# ── 5) Default to running your submitter ──────────────────────────────
#ENTRYPOINT ["./deaddrop/deadbug/build/release/submitter"]
#CMD ["a","a","a"]
