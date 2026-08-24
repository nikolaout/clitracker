# Architecture

## Overview

CLI Tracker combines three parts in one process:

1. FastAPI serves the dashboard and JSON endpoints.
2. A mitmproxy `DumpMaster` instance runs in-process as a local HTTPS proxy.
3. The browser UI subscribes to live updates over WebSocket.

## Runtime Flow

1. `python run.py` starts `uvicorn` and loads `app.main:app`.
2. FastAPI startup creates an async task that runs the mitmproxy server.
3. A client terminal points `HTTP_PROXY` / `HTTPS_PROXY` at `http://127.0.0.1:8080`.
4. The mitmproxy addon inspects each request and decides whether it should be captured.
5. Matching requests are stored in `WiretapState` and broadcast to connected UI clients.
6. The browser receives history and live deltas over `WS /ws`.
7. The frontend renders request list items, detail blocks, diagnostics, and raw JSON views.

## Request Matching Rules

Traffic is captured when either condition is true:

- the request is `POST`, the host is in the allowlist, and the path matches a tracked path fragment
- the request is `POST`, the host is in the allowlist, and catch-all mode is enabled

The addon also records diagnostics:

- rejected hosts
- rejected paths
- all observed POST targets

## Response Parsing

The proxy addon handles three main response shapes:

- regular JSON response bodies
- non-JSON bodies, stored as raw text only
- `text/event-stream` bodies, parsed as SSE events

For SSE responses it reconstructs:

- Anthropic-style message streams
- OpenAI-style chat completion streams

The reconstructed assistant payload is then rendered in the same UI shape as non-streaming responses.

## State Model

`WiretapState` owns:

- captured requests in an ordered in-memory store
- active WebSocket connections
- allowlist / tracked path configuration
- diagnostics counters

Captured requests are capped (`max_requests=200`) and older entries are evicted first.

## Frontend Model

The UI is intentionally build-free:

- `index.html` provides a single page shell
- `index.js` renders all request content directly in the browser
- `index.css` contains all layout and component styling

Notable UI behaviors:

- sticky header and side panels
- expandable message blocks
- per-block raw JSON toggle
- global raw JSON mode
- settings editing from the right-hand panel

## Persistence

Allowlist, tracked paths, and catch-all mode are persisted:

- stored in `app/data/allowed_hosts.json`

Captured requests are not persisted.
