# Docker

The image runs Airlock as a non-root user (`uid 10001`) on `python:3.12-slim`.

```bash
docker build -t airlock .
docker run --rm airlock --help
```

## Remote MCP servers (`airlock serve`)

Inside a container Airlock must listen on the container's interface so the
published port reaches it; publish it on the host's loopback only:

```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v airlock-data:/home/airlock/.config/airlock \
  airlock serve --upstream https://mcp.example.com/mcp --listen 0.0.0.0:8765 --name example
```

Airlock warns when it listens on anything but 127.0.0.1; here the
`-p 127.0.0.1:8765:8765` mapping is what keeps it private. Point the client at
`http://127.0.0.1:8765/mcp`.

## stdio servers (`airlock wrap`)

A client starts stdio servers itself, so wrapping them in Docker means the
server runs in the container too:

```bash
docker run --rm -i -v airlock-data:/home/airlock/.config/airlock \
  airlock wrap --name fetch -- python -m my_mcp_server
```

(the image needs the server installed; extend it with your own `FROM airlock`).

## Data

Mount `/home/airlock/.config/airlock` to keep the audit log, tool registry,
honeytokens and policy between runs. Put an `airlock.yaml` there to configure
it.

## Status

The Dockerfile has not been built in this repository's development
environment yet (kept off a nearly full disk); CI does not build it.
