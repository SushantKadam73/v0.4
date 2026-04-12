from __future__ import annotations

import time
import tracemalloc
from typing import Any, Callable


def measure_operation(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float, float]:
    tracemalloc.start()
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_kb = peak / 1024.0
    return result, elapsed_ms, peak_kb
