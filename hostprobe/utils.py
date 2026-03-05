"""Shared async utilities: retry, subprocess wrapper, concurrency helpers."""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")

logger = logging.getLogger("hostprobe")


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
