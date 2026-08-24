from __future__ import annotations

import asyncio
import json
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import WebSocket

from .models import CapturedRequest


class WiretapState:
    def __init__(
        self,
        max_requests: int = 200,
        allowed_hosts: list[str] | None = None,
        tracked_paths: list[str] | None = None,
        config_path: str | Path | None = None,
        catch_all_mode: bool = True,
    ) -> None:
        self._requests: "OrderedDict[str, CapturedRequest]" = OrderedDict()
        self._sockets: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._max_requests = max_requests
        self._config_lock = threading.Lock()
        self._config_path = Path(config_path) if config_path else None
        self._allowed_hosts = self._normalize_hosts(allowed_hosts or [])
        self._tracked_paths = self._normalize_paths(tracked_paths or [])
        self._rejected_hosts: "OrderedDict[str, int]" = OrderedDict()
        self._max_rejected_hosts = 200
        self._rejected_paths: "OrderedDict[str, int]" = OrderedDict()
        self._max_rejected_paths = 200
        self._seen_post_targets: "OrderedDict[str, int]" = OrderedDict()
        self._max_seen_post_targets = 300
        self._catch_all_mode = catch_all_mode
        self._load_allowed_hosts()
        if self._config_path is not None and not self._config_path.exists():
            with self._config_lock:
                self._save_allowed_hosts_locked()

    @staticmethod
    def _trim_ordered_dict(
        items: "OrderedDict[str, Any]",
        max_size: int,
    ) -> None:
        while len(items) > max_size:
            items.popitem(last=False)

    def _record_counter(
        self,
        items: "OrderedDict[str, int]",
        key: str,
        max_size: int,
    ) -> None:
        count = items.get(key, 0) + 1
        items[key] = count
        items.move_to_end(key)
        self._trim_ordered_dict(items, max_size)

    def _counter_snapshot(
        self,
        items: "OrderedDict[str, int]",
        value_key: str,
    ) -> list[dict[str, Any]]:
        pairs = list(items.items())
        pairs.reverse()
        return [{value_key: value, "count": count} for value, count in pairs]

    async def add_socket(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._sockets.add(websocket)
            history = [item.to_dict() for item in self._requests.values()]

        await websocket.send_text(
            json.dumps({"type": "history_sync", "requests": history})
        )

    async def remove_socket(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._sockets.discard(websocket)

    async def upsert_request(self, request: CapturedRequest) -> None:
        async with self._lock:
            self._requests[request.request_id] = request
            self._requests.move_to_end(request.request_id)
            self._trim_ordered_dict(self._requests, self._max_requests)

    async def get_request(self, request_id: str) -> CapturedRequest | None:
        async with self._lock:
            return self._requests.get(request_id)

    async def clear(self) -> None:
        async with self._lock:
            self._requests.clear()
        await self.broadcast({"type": "clear_all"})

    async def stats(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "requests": len(self._requests),
                "clients": len(self._sockets),
            }

    def _normalize_hosts(self, hosts: list[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for host in hosts:
            cleaned = host.strip().lower()
            if not cleaned:
                continue
            if cleaned.startswith("http://"):
                cleaned = cleaned[7:]
            if cleaned.startswith("https://"):
                cleaned = cleaned[8:]
            cleaned = cleaned.split("/", 1)[0].strip(".")
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            result.append(cleaned)
        return result

    def _normalize_paths(self, paths: list[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for path in paths:
            cleaned = path.strip()
            if not cleaned:
                continue
            if "://" in cleaned:
                cleaned = "/" + cleaned.split("://", 1)[1].split("/", 1)[1] if "/" in cleaned.split("://", 1)[1] else "/"
            if not cleaned.startswith("/"):
                cleaned = "/" + cleaned
            if cleaned in seen:
                continue
            seen.add(cleaned)
            result.append(cleaned)
        return result

    def is_allowed_host(self, host: str) -> bool:
        current = host.strip().lower()
        if not current:
            return False
        with self._config_lock:
            return any(
                current == allowed or current.endswith("." + allowed)
                for allowed in self._allowed_hosts
            )

    def get_allowed_hosts(self) -> list[str]:
        with self._config_lock:
            return list(self._allowed_hosts)

    def get_tracked_paths(self) -> list[str]:
        with self._config_lock:
            return list(self._tracked_paths)

    def get_catch_all_mode(self) -> bool:
        with self._config_lock:
            return self._catch_all_mode

    def set_catch_all_mode(self, enabled: bool) -> bool:
        with self._config_lock:
            self._catch_all_mode = bool(enabled)
            self._save_allowed_hosts_locked()
            return self._catch_all_mode

    def set_allowed_hosts(self, hosts: list[str]) -> list[str]:
        normalized = self._normalize_hosts(hosts)
        with self._config_lock:
            self._allowed_hosts = normalized
            self._save_allowed_hosts_locked()
        return normalized

    def set_tracked_paths(self, paths: list[str]) -> list[str]:
        normalized = self._normalize_paths(paths)
        with self._config_lock:
            self._tracked_paths = normalized
            self._save_allowed_hosts_locked()
        return normalized

    def _load_allowed_hosts(self) -> None:
        if self._config_path is None or not self._config_path.exists():
            return
        try:
            payload = json.loads(self._config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        hosts = payload.get("allowed_hosts")
        if isinstance(hosts, list):
            self._allowed_hosts = self._normalize_hosts([str(item) for item in hosts])
        tracked_paths = payload.get("tracked_paths")
        if isinstance(tracked_paths, list):
            self._tracked_paths = self._normalize_paths([str(item) for item in tracked_paths])
        catch_all_mode = payload.get("catch_all_mode")
        if isinstance(catch_all_mode, bool):
            self._catch_all_mode = catch_all_mode

    def _save_allowed_hosts_locked(self) -> None:
        if self._config_path is None:
            return
        payload = {
            "allowed_hosts": list(self._allowed_hosts),
            "tracked_paths": list(self._tracked_paths),
            "catch_all_mode": self._catch_all_mode,
        }
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            self._config_path.write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
        except OSError:
            return

    def record_rejected_host(self, host: str) -> None:
        cleaned = host.strip().lower()
        if not cleaned:
            return
        with self._config_lock:
            self._record_counter(self._rejected_hosts, cleaned, self._max_rejected_hosts)

    def get_rejected_hosts(self) -> list[dict[str, Any]]:
        with self._config_lock:
            return self._counter_snapshot(self._rejected_hosts, "host")

    def clear_rejected_hosts(self) -> None:
        with self._config_lock:
            self._rejected_hosts.clear()

    def record_rejected_path(self, path: str) -> None:
        cleaned = path.strip()
        if not cleaned:
            return
        with self._config_lock:
            self._record_counter(self._rejected_paths, cleaned, self._max_rejected_paths)

    def get_rejected_paths(self) -> list[dict[str, Any]]:
        with self._config_lock:
            return self._counter_snapshot(self._rejected_paths, "path")

    def clear_rejected_paths(self) -> None:
        with self._config_lock:
            self._rejected_paths.clear()

    def record_seen_post_target(self, host: str, path: str) -> None:
        cleaned_host = host.strip().lower()
        cleaned_path = path.strip()
        if not cleaned_host:
            return
        label = f"{cleaned_host}{cleaned_path}" if cleaned_path else cleaned_host
        with self._config_lock:
            self._record_counter(self._seen_post_targets, label, self._max_seen_post_targets)

    def is_tracked_path(self, path: str) -> bool:
        current = path.strip()
        if not current:
            return False
        with self._config_lock:
            return any(candidate in current for candidate in self._tracked_paths)

    def get_seen_post_targets(self) -> list[dict[str, Any]]:
        with self._config_lock:
            return self._counter_snapshot(self._seen_post_targets, "target")

    def clear_seen_post_targets(self) -> None:
        with self._config_lock:
            self._seen_post_targets.clear()

    def clear_diagnostics(self) -> None:
        with self._config_lock:
            self._rejected_hosts.clear()
            self._rejected_paths.clear()
            self._seen_post_targets.clear()

    def diagnostics_snapshot(self) -> dict[str, Any]:
        return {
            "rejected_hosts": self.get_rejected_hosts(),
            "rejected_paths": self.get_rejected_paths(),
            "seen_post_targets": self.get_seen_post_targets(),
        }

    async def broadcast(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, default=str)
        async with self._lock:
            sockets = list(self._sockets)

        stale: list[WebSocket] = []
        for socket in sockets:
            try:
                await socket.send_text(payload)
            except Exception:
                stale.append(socket)

        if stale:
            async with self._lock:
                for socket in stale:
                    self._sockets.discard(socket)
