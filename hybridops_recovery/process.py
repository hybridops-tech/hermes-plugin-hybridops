"""Bounded subprocess execution without an ambient environment or shell."""

from __future__ import annotations

import os
import pwd
import signal
import subprocess
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

MAX_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    interrupted: bool


def child_environment(executable: Path) -> dict[str, str]:
    standard_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    env = {
        "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
        "PATH": f"{executable.parent}:{standard_path}",
        "NO_COLOR": "1",
    }
    for key in ("LANG", "LC_ALL", "LC_CTYPE"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _read_stream(stream, limit: int, result: dict[str, object], key: str) -> None:  # type: ignore[no-untyped-def]
    content = bytearray()
    truncated = False
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            remaining = limit - len(content)
            if remaining > 0:
                content.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
    finally:
        stream.close()
        result[key] = bytes(content)
        result[f"{key}_truncated"] = truncated


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGTERM)

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)

    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)


def run_process(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> ProcessResult:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    captured: dict[str, object] = {}
    readers = [
        threading.Thread(
            target=_read_stream,
            args=(process.stdout, MAX_STDOUT_BYTES, captured, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=_read_stream,
            args=(process.stderr, MAX_STDERR_BYTES, captured, "stderr"),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    interrupted = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _stop_process_group(process)
    except KeyboardInterrupt:
        interrupted = True
        _stop_process_group(process)
    finally:
        for reader in readers:
            reader.join(timeout=3)
        if any(reader.is_alive() for reader in readers):
            _stop_process_group(process)
            process.stdout.close()
            process.stderr.close()
            for reader in readers:
                reader.join(timeout=1)

    return ProcessResult(
        returncode=process.poll(),
        stdout=captured.get("stdout", b""),  # type: ignore[arg-type]
        stderr=captured.get("stderr", b""),  # type: ignore[arg-type]
        stdout_truncated=bool(captured.get("stdout_truncated", False)),
        stderr_truncated=bool(captured.get("stderr_truncated", False)),
        timed_out=timed_out,
        interrupted=interrupted,
    )
