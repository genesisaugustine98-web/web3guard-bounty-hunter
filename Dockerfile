# Web3Guard — multi-language Web3 vulnerability scanner.
# Build: docker build -t web3guard .
# Run:   docker run --rm -e NIM_API_KEY=... -v $PWD/output:/output web3guard \
#            python -m web3guard.cli scan https://github.com/owner/repo|max

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# System dependencies.
# - git: clone target repos.
# - curl, wget: download Foundry.
# - build-essential, libffi-dev: for some Python deps.
# - solc-select: optional, for Solidity version management.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ca-certificates \
        build-essential \
        libffi-dev \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Foundry (Solidity / Vyper test runner).
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup --install nightly
ENV PATH="/root/.foundry/bin:${PATH}"

# Optional: cargo (for aderyn, echidna, soteria).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Install Python deps first for better Docker layer caching.
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the package.
COPY . .

# Install the package itself.
RUN pip install -e .

# Default workdir for output; mount with -v $PWD/output:/output
RUN mkdir -p /output
WORKDIR /output

# Default: show the version.
ENTRYPOINT ["python", "-m", "web3guard.cli"]
CMD ["version"]
