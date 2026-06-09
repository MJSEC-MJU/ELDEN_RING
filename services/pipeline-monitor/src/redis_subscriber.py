from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable

import redis.asyncio as redis

logger = logging.getLogger(__name__)


CHANNELS = (
    "elden:phase2:context",
    "elden:phase3:validate",
    "elden:phase4:promote",
    "elden:phase4:deployed",
    "elden:phase2:retry",
)


class RedisSubscriber:
    def __init__(self, url: str, on_message: Callable[[str, dict], Awaitable[None]]) -> None:
        self.url = url
        self.on_message = on_message

    async def run(self) -> None:
        backoff = 1
        while True:
            try:
                client = redis.from_url(self.url, decode_responses=True)
                pubsub = client.pubsub()
                await pubsub.subscribe(*CHANNELS)
                logger.info("subscribed to %s", CHANNELS)
                backoff = 1
                async for msg in pubsub.listen():
                    if msg.get("type") != "message":
                        continue
                    try:
                        payload = json.loads(msg["data"])
                    except Exception:
                        logger.warning("non-json message on %s", msg.get("channel"))
                        continue
                    await self.on_message(msg["channel"], payload)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("redis subscribe error: %s — retry in %ss", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
