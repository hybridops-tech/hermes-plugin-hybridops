from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "hermes_hybridops_test"


def load_plugin():
    existing = sys.modules.get(PACKAGE_NAME)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        PACKAGE_NAME,
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE_NAME] = module
    spec.loader.exec_module(module)
    return module


PLUGIN = load_plugin()


class Settings:
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def write_private(path: Path, content: str, mode: int = 0o600) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return path


def make_layout(base: Path, *, mutations: bool = False) -> tuple[Settings, dict[str, Path]]:
    root = base / "runtime"
    module_root = base / "modules"
    module_dir = module_root / "platform" / "linux" / "containerlab-recovery"
    root.mkdir(parents=True)
    module_dir.mkdir(parents=True)
    write_private(module_dir / "spec.yml", "module_ref: platform/linux/containerlab-recovery\n")
    export_inputs = write_private(
        base / "export.yml",
        "containerlab_recovery_action: export\n"
        "containerlab_recovery_mode: rebuild\n"
        "containerlab_recovery_additional_paths: []\n",
    )
    import_inputs = write_private(
        base / "import.yml",
        "containerlab_recovery_action: import\n"
        "containerlab_recovery_mode: rebuild\n"
        f"containerlab_recovery_archive_path: {base / 'retained-recovery.tar.gz'}\n"
        f"containerlab_recovery_expected_sha256: {'c' * 64}\n"
        "containerlab_recovery_additional_paths: []\n",
    )
    state_file = base / "fake-state.json"
    calls_file = base / "fake-calls.jsonl"
    env_file = base / "fake-env.json"
    executable = base / "hyops"
    script = f"""#!/usr/bin/python3
import json
import os
from pathlib import Path
import re
import sys

state_file = Path({str(state_file)!r})
calls_file = Path({str(calls_file)!r})
env_file = Path({str(env_file)!r})
args = sys.argv[1:]
with calls_file.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
env_file.write_text(json.dumps(dict(os.environ)), encoding="utf-8")
if args == ["--version"]:
    print("0.1.6")
    raise SystemExit(0)
if args[:2] == ["show", "module"]:
    if not state_file.exists():
        print("missing", file=sys.stderr)
        raise SystemExit(2)
    print(state_file.read_text(encoding="utf-8"))
    raise SystemExit(0)
if args and args[0] == "apply":
    input_path = Path(args[args.index("--inputs") + 1])
    text = input_path.read_text(encoding="utf-8")
    match = re.search(r"^containerlab_recovery_action:\\s*(\\w+)", text, re.MULTILINE)
    action = match.group(1) if match else ""
    run_number = 1
    if state_file.exists():
        previous = json.loads(state_file.read_text(encoding="utf-8"))
        run_number = int(previous.get("sequence", 0)) + 1
    evidence = state_file.parent / f"evidence-{{run_number}}"
    evidence.mkdir()
    recovery = state_file.parent / f"recovery-{{run_number}}.tgz"
    recovery.write_bytes(b"recovery")
    instance = args[args.index("--state-instance") + 1] if "--state-instance" in args else ""
    state = {{
        "module_ref": "platform/linux/containerlab-recovery",
        "state_instance": instance,
        "status": "ok",
        "run_id": f"apply-test-{{run_number}}",
        "updated_at": "2026-11-20T12:00:00Z",
        "evidence_dir": str(evidence),
        "sequence": run_number,
        "outputs": {{
            "containerlab_recovery_action": action,
            "containerlab_recovery_mode": "rebuild",
            "containerlab_recovery_path": str(recovery),
            "containerlab_recovery_sha256": "a" * 64,
            "containerlab_recovery_topology_sha256": "b" * 64,
            "containerlab_recovery_latest_path": "",
            "containerlab_recovery_safe_for_host_destroy": action == "export",
        }},
    }}
    state_file.write_text(json.dumps(state), encoding="utf-8")
    print("provider-token-from-child", file=sys.stderr)
    raise SystemExit(0)
raise SystemExit(64)
"""
    write_private(executable, script, mode=0o700)
    settings = Settings(
        {
            "hyops_executable": str(executable),
            "mutations_enabled": mutations,
            "timeout_seconds": 30,
            "targets": {
                "lab": {
                    "root": str(root),
                    "module_root": str(module_root),
                    "state_instance": "lab_instance",
                    "export_inputs": str(export_inputs),
                    "import_inputs": str(import_inputs),
                }
            },
        }
    )
    return settings, {
        "root": root,
        "module_root": module_root,
        "export_inputs": export_inputs,
        "import_inputs": import_inputs,
        "executable": executable,
        "state_file": state_file,
        "calls_file": calls_file,
        "env_file": env_file,
    }


def read_calls(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def parse_result(value: str) -> dict[str, Any]:
    result = json.loads(value)
    assert isinstance(result, dict)
    return result


def mutation_args(service: Any, operation: str = "export") -> dict[str, str]:
    inspected = parse_result(service.inspect({"target": "lab", "operation": operation}))
    assert inspected["ok"], inspected
    return {
        "target": "lab",
        "expected_inputs_sha256": inspected["inputs_sha256"],
        "expected_contract_sha256": inspected["contract_sha256"],
    }


def set_secret_environment() -> tuple[str, str | None]:
    key = "FAKE_PROVIDER_TOKEN"
    previous = os.environ.get(key)
    os.environ[key] = "do-not-forward"
    return key, previous


def restore_environment(key: str, previous: str | None) -> None:
    if previous is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = previous
