# ── (keep the FROM and Rust/toolchain steps) ────────────────────────
FROM aztecprotocol/foundry:25f24e677a6a32a62512ad4f561995589ac2c7dc-arm64

USER root
RUN apt-get update \
 && apt-get install -y curl build-essential ca-certificates jq python3 \
 && rm -rf /var/lib/apt/lists/* \
 # install rustup non-interactive, set up stable toolchain
 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain=stable \
 && ln -s /root/.cargo/bin/rustc /usr/local/bin/rustc \
 && ln -s /root/.cargo/bin/cargo /usr/local/bin/cargo

ENV PATH=/root/.cargo/bin:$PATH

# ── 3) Install Python3, venv support, and Dstack SDK ─────────────────────
RUN apt-get update \
 && apt-get install -y \
      python3 \
      python3-full \
      python3-venv \
      curl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 \
 # create a virtualenv at /opt/venv and upgrade its pip
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 \
 # install the Dstack Python SDK into that venv
 && /opt/venv/bin/pip install --no-cache-dir dstack-sdk

# ensure all python invocations use the venv
ENV PATH="/opt/venv/bin:${PATH}"

# ── Your app build steps ─────────────────────────────────────────────
WORKDIR /app
COPY ./deadbug .

RUN cargo build --release --target-dir ./build