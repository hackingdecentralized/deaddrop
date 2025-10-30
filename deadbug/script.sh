#!/usr/bin/env bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup update stable
apt-get ins
apt-get update

apt-get install -y \
      python3 \
      python3-venv \
      python3-distutils \
      curl \
      ca-certificates && \
rm -rf /var/lib/apt/lists/*

PATH="/opt/venv/bin:${PATH}"

python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip

cd submitter
ls
cargo run