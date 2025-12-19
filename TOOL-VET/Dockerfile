FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        build-essential \
        ca-certificates \
        nodejs \
        npm && \
    pip install --upgrade pip && \
    pip install mitmproxy requests pyyaml && \
    rm -rf /var/lib/apt/lists/*

ARG GO_VERSION=1.23.3
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
        x86_64) GO_ARCH="amd64" ;; \
        aarch64) GO_ARCH="arm64" ;; \
        arm64) GO_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

COPY . /app

# output 디렉토리 생성 및 권한 설정
RUN mkdir -p /app/output /app/temp_env && \
    chmod -R 777 /app/output /app/temp_env

# mitmproxy CA 생성 및 시스템 신뢰 저장소에 등록
RUN mkdir -p /tmp/mitmproxy && \
    (mitmdump --quiet --set confdir=/tmp/mitmproxy --listen-host 127.0.0.1 --listen-port 0 & pid=$!; \
     sleep 2; \
     kill $pid || true; \
     wait $pid || true) && \
    cp /tmp/mitmproxy/mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy.crt && \
    update-ca-certificates && \
    rm -rf /tmp/mitmproxy

ENTRYPOINT ["python", "main.py"]

