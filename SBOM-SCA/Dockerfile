FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul \
    GOPATH=/root/go \
    GOROOT=/usr/local/go \
    VIRTUAL_ENV=/opt/venv \
    GOTOOLCHAIN=auto \
    PATH=/usr/local/go/bin:/root/go/bin:/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl gnupg \
    git curl ca-certificates tzdata \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g pnpm \
 && rm -rf /var/lib/apt/lists/*

# Install Go 1.25.1
RUN curl -fsSL https://go.dev/dl/go1.25.1.linux-amd64.tar.gz -o /tmp/go.tar.gz \
 && rm -rf /usr/local/go \
 && tar -C /usr/local -xzf /tmp/go.tar.gz \
 && rm /tmp/go.tar.gz

RUN python3 -m venv "${VIRTUAL_ENV}"

WORKDIR /app

COPY SBOM/requirements.txt ./SBOM/requirements.txt
RUN pip install --no-cache-dir -r SBOM/requirements.txt \
 && rm -rf /root/.cache/pip

COPY SCA/callGraph/npm/package.json SCA/callGraph/npm/package-lock.json ./SCA/callGraph/npm/
RUN npm ci --prefix SCA/callGraph/npm \
 && npm cache clean --force

COPY . .

RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
 && rm -rf /root/go/pkg /root/go/src

ENTRYPOINT ["python3", "main.py"]

