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

COPY firmware_analysis/extraction/carve.py   /opt/carve.py
COPY firmware_analysis/analysis/analyze.py   /opt/analyze.py
COPY firmware_analysis/analysis/analyzers/   /opt/analyzers/

WORKDIR /workspace

# Pre-create output subdirectories with open permissions so the container can
# run as any user (--user flag in docker run) without permission errors.
RUN mkdir -p /input /output/carved /output/extracted /output/analysis \
    && chmod -R 777 /input /output

# /input  — mount your firmware directory here (read-only recommended)
# /output — mount your extraction target here
VOLUME ["/input", "/output"]

CMD ["/bin/bash"]
