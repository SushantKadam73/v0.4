"""Performance measurement utilities.

Uses time.perf_counter for wall-clock timing and psutil for RAM measurement.
psutil gives accurate OS-level RSS measurements, unlike tracemalloc which
only tracks Python-level allocations.
"""

from __future__ import annotations

import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Callable

try:
    import os as _os

    import psutil

    _PROC = psutil.Process(_os.getpid())
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


@dataclass
class OperationMetrics:
    result: Any
    elapsed_ms: float
    ram_kb: float
    throughput_kbps: float  # input KB / elapsed seconds


@dataclass
class MultiIterationMetrics:
    results: list[Any]
    mean_ms: float
    std_ms: float
    mean_ram_kb: float
    std_ram_kb: float
    mean_throughput_kbps: float
    std_throughput_kbps: float
    iterations: int


def _get_ram_kb() -> float:
    if _PSUTIL_AVAILABLE:
        return _PROC.memory_info().rss / 1024.0
    return 0.0


def memory_backend() -> str:
    return "psutil_rss" if _PSUTIL_AVAILABLE else "tracemalloc_peak"


def measure_operation(
    fn: Callable[..., Any], *args: Any, input_size_bytes: int = 0, **kwargs: Any
) -> OperationMetrics:
    """Measure a single operation's time and RAM."""
    if _PSUTIL_AVAILABLE:
        ram_before = _get_ram_kb()
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        ram_after = _get_ram_kb()
        ram_kb = max(0.0, ram_after - ram_before)
    else:
        tracemalloc.start()
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        ram_kb = peak / 1024.0

    elapsed_s = elapsed_ms / 1000.0
    if elapsed_s > 0 and input_size_bytes > 0:
        throughput_kbps = (input_size_bytes / 1024.0) / elapsed_s
    else:
        throughput_kbps = 0.0

    return OperationMetrics(
        result=result,
        elapsed_ms=round(elapsed_ms, 4),
        ram_kb=round(ram_kb, 3),
        throughput_kbps=round(throughput_kbps, 2),
    )


def measure_multi(
    fn: Callable[..., Any],
    *args: Any,
    iterations: int = 3,
    input_size_bytes: int = 0,
    **kwargs: Any,
) -> MultiIterationMetrics:
    """Run fn N times and return mean/std statistics."""
    import math

    all_ms: list[float] = []
    all_ram: list[float] = []
    all_tp: list[float] = []
    results: list[Any] = []

    for _ in range(iterations):
        m = measure_operation(fn, *args, input_size_bytes=input_size_bytes, **kwargs)
        all_ms.append(m.elapsed_ms)
        all_ram.append(m.ram_kb)
        all_tp.append(m.throughput_kbps)
        results.append(m.result)

    def _mean(lst: list[float]) -> float:
        return sum(lst) / len(lst) if lst else 0.0

    def _std(lst: list[float]) -> float:
        if len(lst) < 2:
            return 0.0
        m = _mean(lst)
        return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))

    return MultiIterationMetrics(
        results=results,
        mean_ms=round(_mean(all_ms), 4),
        std_ms=round(_std(all_ms), 4),
        mean_ram_kb=round(_mean(all_ram), 3),
        std_ram_kb=round(_std(all_ram), 3),
        mean_throughput_kbps=round(_mean(all_tp), 2),
        std_throughput_kbps=round(_std(all_tp), 2),
        iterations=iterations,
    )


def throughput_kbps(data_size_bytes: int, elapsed_ms: float) -> float:
    """Compute throughput in KB/s given data size and elapsed time in ms."""
    if elapsed_ms <= 0:
        return 0.0
    return round((data_size_bytes / 1024.0) / (elapsed_ms / 1000.0), 2)
