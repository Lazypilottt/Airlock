# Airlock on python:3.12-slim, running as a non-root user.
# Build: docker build -t airlock .
# See docs/docker.md for running it in front of remote MCP servers.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 airlock
WORKDIR /app
COPY --chown=airlock:airlock . /src
RUN pip install /src && rm -rf /src

USER airlock
ENV HOME=/home/airlock
# data_dir defaults to ~/.config/airlock; mount a volume there to keep the
# audit log, registry and honeytokens.
VOLUME ["/home/airlock/.config/airlock"]

ENTRYPOINT ["airlock"]
CMD ["--help"]
