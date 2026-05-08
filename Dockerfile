FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV VIRTUAL_ENV="/opt/venv"
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt"

RUN apt-get update && apt-get install -y --no-install-recommends \
    # General utilities
    git \
    wget \
    curl \
    ca-certificates \
    file \
    nano \
    attr \
    libcap2-bin \
    shellcheck \
    # Firmware analysis
    binutils \
    binwalk \
    python3 \
    python3-magic \
    python3-pyelftools \
    python3-matplotlib \
    python3-numpy \
    # Filesystem extraction
    squashfs-tools \
    mtd-utils \
    e2fsprogs \
    # Compression
    lzma \
    xz-utils \
    p7zip-full \
    lzop \
    cabextract \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Only tools not available in apt
RUN uv venv /opt/venv && \
    uv pip install --no-cache \
    jefferson \
    ubi_reader

COPY carve.py    /opt/carve.py
COPY analyze.py  /opt/analyze.py
COPY analyzers/  /opt/analyzers/

WORKDIR /workspace

# /input  — mount your firmware directory here (read-only recommended)
# /output — mount your extraction target here
VOLUME ["/input", "/output"]

CMD ["/bin/bash"]
