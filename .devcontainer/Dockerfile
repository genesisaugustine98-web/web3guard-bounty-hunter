ARG VARIANT=3.11
FROM mcr.microsoft.com/devcontainers/python:${VARIANT}

# Install Web3Guard with dev extras (pytest, ruff, mypy) at build time
# so every Codespaces launch starts with a fully provisioned toolchain.
COPY . /workspaces/web3guard-bounty-hunter
RUN cd /workspaces/web3guard-bounty-hunter \
    && python -m pip install --upgrade pip \
    && python -m pip install -e ".[dev]"

WORKDIR /workspaces/web3guard-bounty-hunter
