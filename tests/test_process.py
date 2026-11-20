from __future__ import annotations

import os
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path

from .support import PACKAGE_NAME, write_private

process = __import__(f"{PACKAGE_NAME}.process", fromlist=["process"])


class ProcessTests(unittest.TestCase):
    def test_environment_is_an_allowlist(self) -> None:
        executable = Path("/usr/bin/true")
        os.environ["FAKE_PROVIDER_TOKEN"] = "secret"
        try:
            child = process.child_environment(executable)
        finally:
            os.environ.pop("FAKE_PROVIDER_TOKEN", None)
        self.assertNotIn("FAKE_PROVIDER_TOKEN", child)
        self.assertNotIn("SSH_AUTH_SOCK", child)
        self.assertNotIn("PYTHONPATH", child)
        self.assertEqual(child["NO_COLOR"], "1")

    def test_output_is_bounded_and_drained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            script = write_private(
                base / "emit",
                "#!/usr/bin/python3\nimport sys\nsys.stdout.write('x' * (2 * 1024 * 1024))\n",
                mode=0o700,
            )
            result = process.run_process(
                [str(script)],
                cwd=base,
                env=process.child_environment(script),
                timeout=5,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout_truncated)
            self.assertEqual(len(result.stdout), process.MAX_STDOUT_BYTES)

    def test_timeout_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            script = write_private(
                base / "sleep",
                "#!/usr/bin/python3\nimport time\ntime.sleep(30)\n",
                mode=0o700,
            )
            started = time.monotonic()
            result = process.run_process(
                [str(script)],
                cwd=base,
                env=process.child_environment(script),
                timeout=1,
            )
            self.assertTrue(result.timed_out)
            self.assertIsNotNone(result.returncode)
            self.assertLess(time.monotonic() - started, 6)

    def test_timeout_kills_descendant_that_ignores_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pid_file = base / "descendant.pid"
            descendant = (
                "import os, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"open({str(pid_file)!r}, 'w', encoding='utf-8').write(str(os.getpid()))\n"
                "time.sleep(30)\n"
            )
            script = write_private(
                base / "parent",
                "#!/usr/bin/python3\n"
                "import subprocess, sys, time\n"
                f"subprocess.Popen([sys.executable, '-c', {descendant!r}])\n"
                "time.sleep(30)\n",
                mode=0o700,
            )
            result = process.run_process(
                [str(script)],
                cwd=base,
                env=process.child_environment(script),
                timeout=1,
            )
            self.assertTrue(result.timed_out)
            self.assertTrue(pid_file.exists())
            descendant_pid = int(pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            terminated = False
            process_root = Path(f"/proc/{descendant_pid}")
            while time.monotonic() < deadline:
                if not process_root.exists():
                    terminated = True
                    break
                try:
                    status = (process_root / "stat").read_text(encoding="utf-8")
                except FileNotFoundError:
                    terminated = True
                    break
                if status.split()[2] == "Z":
                    terminated = True
                    break
                time.sleep(0.05)
            self.assertTrue(terminated, "descendant process survived timeout cleanup")

    def test_interrupt_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pid_file = base / "child.pid"
            script = write_private(
                base / "sleep",
                "#!/usr/bin/python3\n"
                "import os, time\n"
                f"open({str(pid_file)!r}, 'w', encoding='utf-8').write(str(os.getpid()))\n"
                "time.sleep(30)\n",
                mode=0o700,
            )
            interrupt = threading.Timer(0.5, os.kill, args=(os.getpid(), signal.SIGINT))
            interrupt.start()
            try:
                result = process.run_process(
                    [str(script)],
                    cwd=base,
                    env=process.child_environment(script),
                    timeout=10,
                )
            finally:
                interrupt.cancel()
                interrupt.join()

            self.assertTrue(result.interrupted)
            self.assertIsNotNone(result.returncode)
            self.assertTrue(pid_file.exists())
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            self.assertFalse(Path(f"/proc/{child_pid}").exists())


if __name__ == "__main__":
    unittest.main()
