"""Shared async utilities: retry, subprocess wrapper, concurrency helpers, rate limiting."""

from __future__ import annotations

import asyncio
import logging
import random
import sys
import time
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")

logger = logging.getLogger("hostprobe")


# ---------------------------------------------------------------------------
# User-Agent rotation
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def random_user_agent() -> str:
    """Return a random realistic browser User-Agent string."""
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Async token-bucket rate limiter.

    Allows *rate* operations per second with optional burst capacity.
    """

    def __init__(self, rate: float = 10.0, burst: int = 0):
        self._rate = rate
        self._burst = burst or int(rate)
        self._tokens = float(self._burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            wait = (1.0 - self._tokens) / self._rate
            self._tokens = 0.0

        await asyncio.sleep(wait)

    @property
    def rate(self) -> float:
        return self._rate


# Global rate limiter — initialised from Config before scan starts
_global_limiter: RateLimiter | None = None


def init_rate_limiter(rate: float, burst: int = 0) -> RateLimiter:
    """Create and set the global rate limiter."""
    global _global_limiter
    _global_limiter = RateLimiter(rate=rate, burst=burst)
    return _global_limiter


def get_rate_limiter() -> RateLimiter | None:
    """Return the global rate limiter (may be None if rate-limiting is off)."""
    return _global_limiter


# ---------------------------------------------------------------------------
# Retry with exponential backoff
# ---------------------------------------------------------------------------

async def retry_with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    exceptions: tuple[type[BaseException], ...] = (
        asyncio.TimeoutError,
        OSError,
        ConnectionError,
    ),
) -> T:
    """Call *coro_factory()* with exponential backoff on transient errors.

    *coro_factory* must be a zero-arg callable that **returns a new coroutine**
    each time (not a bare coroutine object), so that retries create fresh work.
    """
    last_exc: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            return await coro_factory()
        except exceptions as exc:
            last_exc = exc
            if attempt < retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                logger.debug(
                    "Retry %d/%d after %.1fs – %s: %s",
                    attempt + 1, retries, delay,
                    type(exc).__name__, exc,
                )
                await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

async def run_subprocess(
    cmd: list[str],
    timeout: float = 10.0,
) -> tuple[int, str, str]:
    """Run *cmd* asynchronously and return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
        return (
            proc.returncode or 0,
            stdout_b.decode(errors="replace"),
            stderr_b.decode(errors="replace"),
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()  # type: ignore[possibly-undefined]
        except ProcessLookupError:
            pass
        return (-1, "", "timeout")
    except FileNotFoundError:
        return (-1, "", f"command not found: {cmd[0]}")


# ---------------------------------------------------------------------------
# Concurrency helper
# ---------------------------------------------------------------------------

async def gather_with_semaphore(
    sem: asyncio.Semaphore,
    coros: list[Awaitable[T]],
) -> list[T]:
    """Run coroutines concurrently, bounded by *sem*."""

    async def _wrap(coro: Awaitable[T]) -> T:
        async with sem:
            return await coro

    return await asyncio.gather(*[_wrap(c) for c in coros], return_exceptions=True)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    """Configure logging: DEBUG to stderr when verbose, else WARNING."""
    level = logging.DEBUG if verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root = logging.getLogger("hostprobe")
    root.setLevel(level)
    root.addHandler(handler)
