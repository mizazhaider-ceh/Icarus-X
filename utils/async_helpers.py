"""
ICARUS-X Async Helpers
======================
Utilities for high-performance async operations.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from typing import Any, Callable, Coroutine, TypeVar

T = TypeVar("T")

# Global thread pool for blocking operations
_thread_pool: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=10)


async def run_in_thread(func: Callable[..., T], *args, **kwargs) -> T:
    """
    Run a blocking function in a thread pool.
    
    Use this for I/O-bound operations that don't support async.
    
    Args:
        func: Blocking function to run
        *args, **kwargs: Arguments to pass to function
        
    Returns:
        Function result
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _thread_pool,
        lambda: func(*args, **kwargs)
    )


class RateLimiter:
    """
    Async rate limiter using semaphore.
    
    Usage:
        limiter = RateLimiter(100)  # 100 concurrent
        async with limiter:
            await do_something()
    """
    
    def __init__(self, max_concurrent: int):
        self._semaphore = asyncio.Semaphore(max_concurrent)
    
    async def __aenter__(self):
        await self._semaphore.acquire()
        return self
    
    async def __aexit__(self, *args):
        self._semaphore.release()


async def gather_with_concurrency(
    tasks: list[Coroutine],
    max_concurrent: int = 100,
    return_exceptions: bool = True,
) -> list[Any]:
    """
    Run tasks with limited concurrency.
    
    Args:
        tasks: List of coroutines to run
        max_concurrent: Maximum concurrent tasks
        return_exceptions: Return exceptions instead of raising
        
    Returns:
        List of results (or exceptions if return_exceptions=True)
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_task(task):
        async with semaphore:
            return await task
    
    return await asyncio.gather(
        *[limited_task(t) for t in tasks],
        return_exceptions=return_exceptions,
    )


async def retry_async(
    func: Callable[..., Coroutine],
    *args,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    **kwargs,
) -> Any:
    """
    Retry an async function with exponential backoff.
    
    Args:
        func: Async function to retry
        max_retries: Maximum retry attempts
        delay: Initial delay between retries (seconds)
        backoff: Backoff multiplier
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries fail
    """
    last_exception = None
    current_delay = delay
    
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                await asyncio.sleep(current_delay)
                current_delay *= backoff
    
    raise last_exception


class AsyncBatcher:
    """
    Batch async calls to reduce overhead.
    
    Collects items and processes them in batches.
    """
    
    def __init__(
        self,
        process_func: Callable[[list], Coroutine],
        batch_size: int = 50,
        max_wait: float = 0.1,
    ):
        self.process_func = process_func
        self.batch_size = batch_size
        self.max_wait = max_wait
        self._items: list = []
        self._results: dict = {}
        self._lock = asyncio.Lock()
        self._event = asyncio.Event()
    
    async def add(self, item: Any) -> Any:
        """Add item to batch and wait for result."""
        async with self._lock:
            item_id = id(item)
            self._items.append((item_id, item))
            
            if len(self._items) >= self.batch_size:
                await self._process_batch()
        
        # Wait for result
        await self._event.wait()
        return self._results.get(item_id)
    
    async def _process_batch(self):
        """Process current batch."""
        items = self._items
        self._items = []
        
        results = await self.process_func([item for _, item in items])
        
        for (item_id, _), result in zip(items, results):
            self._results[item_id] = result
        
        self._event.set()
        self._event.clear()


def timeout(seconds: float):
    """
    Decorator to add timeout to async functions.
    
    Usage:
        @timeout(5.0)
        async def slow_operation():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=seconds,
            )
        return wrapper
    return decorator
