# syntax=docker/dockerfile:1.4

FROM python:3.12-slim

RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL https://go.dev/dl/go1.21.5.linux-${ARCH}.tar.gz | tar -C /usr/local -xzf - && \
    ln -s /usr/local/go/bin/go /usr/bin/go

ARG APP_USER=appuser
RUN useradd --create-home --shell /bin/bash ${APP_USER}
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN cd /app/scanner/analyzers/rules/parsers && \
    npm install

RUN cd /app/scanner/analyzers/rules/parsers && \
    go build -o go_parser go_parser.go go_types.go && \
    chmod +x go_parser

RUN chown -R ${APP_USER}:${APP_USER} /app
USER ${APP_USER}

ENTRYPOINT ["python", "-m", "scanner.cli"]