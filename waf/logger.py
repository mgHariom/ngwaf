"""
Asynchronous audit logger – ECS-aligned JSON events to Elasticsearch.

Blocked requests produce structured events that are enqueued into a
bounded in-memory queue and bulk-indexed by a background task.  Request
handling never awaits Elasticsearch.  Events are also written to stdout
as a fallback so nothing is lost even when ES is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("waf.logger")

# Fields whose values are redacted before logging
_REDACT_FIELDS = frozenset({
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "authorization", "cookie", "session",
})

_MAX_PAYLOAD_EXCERPT = 512
_MAX_URL_LOG = 2048

# Elasticsearch index template for daily indices
_INDEX_TEMPLATE = {
    "index_patterns": ["waf-logs-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "@timestamp":             {"type": "date"},
                "event.category":         {"type": "keyword"},
                "event.action":           {"type": "keyword"},
                "source.ip":              {"type": "ip"},
                "http.request.method":    {"type": "keyword"},
                "url.original":           {"type": "keyword"},
                "user_agent.original":    {"type": "text"},
                "rule.id":                {"type": "keyword"},
                "rule.category":          {"type": "keyword"},
                "waf.module":             {"type": "keyword"},
                "waf.fingerprint":        {"type": "keyword"},
                "waf.source":             {"type": "keyword"},
                "waf.request_id":         {"type": "keyword"},
                "waf.payload_excerpt":    {"type": "text"},
            },
        },
    },
}


class AuditLogger:
    """Non-blocking, queue-backed audit logger targeting Elasticsearch."""

    def __init__(
        self,
        es_url: str,
        queue_size: int = 10_000,
        batch_size: int = 50,
    ):
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._es = AsyncElasticsearch(es_url)
        self._batch_size = batch_size
        self._drop_count: int = 0
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create the index template and start the background flush loop."""
        try:
            await self._es.indices.put_index_template(
                name="waf-logs",
                body=_INDEX_TEMPLATE,
            )
            logger.info("Elasticsearch index template created/updated")
        except Exception:
            logger.warning(
                "Could not create ES index template – will retry on first write",
                exc_info=True,
            )
        self._running = True
        self._task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Drain remaining events and shut down."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Final drain
        await self._drain_queue()
        await self._es.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log_block(
        self,
        *,
        request_id: str,
        client_ip: str,
        method: str,
        url: str,
        user_agent: str = "",
        rule_id: str,
        rule_category: str,
        module: str,
        fingerprint: str = "",
        source: str = "",
        payload_excerpt: str = "",
    ) -> None:
        """Enqueue a blocked-request event.

        This method never blocks the caller.  If the queue is full the
        event is dropped and a counter is incremented.
        """
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event.category": "intrusion_detection",
            "event.action": "blocked",
            "source.ip": client_ip,
            "http.request.method": method,
            "url.original": url[:_MAX_URL_LOG],
            "user_agent.original": user_agent,
            "rule.id": rule_id,
            "rule.category": rule_category,
            "waf.module": module,
            "waf.fingerprint": fingerprint,
            "waf.source": source,
            "waf.request_id": request_id,
            "waf.payload_excerpt": self._redact_excerpt(payload_excerpt)[
                :_MAX_PAYLOAD_EXCERPT
            ],
        }

        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._drop_count += 1
            if self._drop_count % 100 == 1:
                logger.error(
                    "Audit log queue full – dropped %d events total",
                    self._drop_count,
                )

        # Stdout fallback – always write
        try:
            print(json.dumps(event, default=str), file=sys.stdout, flush=True)
        except Exception:
            pass

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def drop_count(self) -> int:
        return self._drop_count

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _redact_excerpt(self, text: str) -> str:
        """Mask values of sensitive-looking fields in the payload excerpt."""
        if not text:
            return text
        for field_name in _REDACT_FIELDS:
            if field_name.lower() in text.lower():
                # Simple redaction – replace anything after '=' up to '&' or end
                import re
                pattern = re.compile(
                    rf"({re.escape(field_name)}\s*=\s*)([^&\s]+)",
                    re.IGNORECASE,
                )
                text = pattern.sub(r"\1[REDACTED]", text)
        return text

    async def _flush_loop(self) -> None:
        """Background coroutine that batches and bulk-indexes events."""
        while self._running:
            try:
                batch: list[dict] = []
                # Wait for at least one event (with timeout so we can check _running)
                try:
                    event = await asyncio.wait_for(
                        self._queue.get(), timeout=5.0
                    )
                    batch.append(event)
                except asyncio.TimeoutError:
                    continue

                # Drain up to batch_size
                while len(batch) < self._batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                await self._bulk_index(batch)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Error in audit log flush loop")
                await asyncio.sleep(1.0)

    async def _drain_queue(self) -> None:
        """Index any remaining events in the queue."""
        batch: list[dict] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if batch:
            await self._bulk_index(batch)

    async def _bulk_index(self, events: list[dict]) -> None:
        """Bulk-index a batch of events into the daily index."""
        if not events:
            return

        index_name = (
            f"waf-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
        )
        body: list[dict] = []
        for event in events:
            body.append({"index": {"_index": index_name}})
            body.append(event)

        try:
            resp = await self._es.bulk(body=body)
            if resp.get("errors"):
                error_count = sum(
                    1 for item in resp.get("items", [])
                    if item.get("index", {}).get("error")
                )
                logger.warning(
                    "ES bulk index: %d/%d items had errors",
                    error_count, len(events),
                )
        except Exception:
            # Fail open – events were already printed to stdout
            logger.warning(
                "ES bulk index failed for %d events (stdout fallback active)",
                len(events),
                exc_info=True,
            )
