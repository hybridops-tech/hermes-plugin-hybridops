"""Hermes tool handlers for the fixed HybridOps recovery module."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .contract import (
    MODULE_REF,
    ContractError,
    Target,
    ValidatedInput,
    load_target,
    mutations_enabled,
    resolve_executable,
    timeout_seconds,
    validate_expected_digest,
    validate_input,
)
from .process import child_environment, run_process

TOOL_INSPECT = "hybridops_recovery_inspect"
TOOL_EXPORT = "hybridops_recovery_export"
TOOL_IMPORT = "hybridops_recovery_import"
MUTATING_TOOLS = {TOOL_EXPORT: "export", TOOL_IMPORT: "import"}
MINIMUM_HYOPS_VERSION = (0, 1, 6)
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?$")


def _schema(
    name: str, description: str, properties: dict[str, Any], required: list[str]
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


_TARGET = {
    "type": "string",
    "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$",
    "description": "Operator-configured recovery target name.",
}
_DIGEST = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
    "description": "Input SHA-256 returned by hybridops_recovery_inspect.",
}
_CONTRACT_DIGEST = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
    "description": "Execution contract SHA-256 returned by hybridops_recovery_inspect.",
}

INSPECT_SCHEMA = _schema(
    TOOL_INSPECT,
    "Validate a named Containerlab recovery target and report its current "
    "HybridOps state and input digest.",
    {
        "target": _TARGET,
        "operation": {
            "type": "string",
            "enum": ["export", "import"],
            "description": "Recovery input document to inspect.",
        },
    },
    ["target", "operation"],
)
EXPORT_SCHEMA = _schema(
    TOOL_EXPORT,
    "Export a configured Containerlab recovery set with HybridOps.",
    {
        "target": _TARGET,
        "expected_inputs_sha256": _DIGEST,
        "expected_contract_sha256": _CONTRACT_DIGEST,
    },
    ["target", "expected_inputs_sha256", "expected_contract_sha256"],
)
IMPORT_SCHEMA = _schema(
    TOOL_IMPORT,
    "Import a retained Containerlab recovery set with HybridOps.",
    {
        "target": _TARGET,
        "expected_inputs_sha256": _DIGEST,
        "expected_contract_sha256": _CONTRACT_DIGEST,
    },
    ["target", "expected_inputs_sha256", "expected_contract_sha256"],
)


def _json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _error(operation: str, target: str, error: ContractError) -> str:
    return _json(
        {
            "ok": False,
            "operation": operation,
            "target": target[:64],
            "error": {"code": error.code, "message": error.message[:512]},
        }
    )


def _operation_from_args(args: Mapping[str, Any], fallback: str) -> str:
    value = args.get("operation", fallback)
    return value if isinstance(value, str) else fallback


def _target_from_args(args: Mapping[str, Any]) -> str:
    value = args.get("target", "")
    return value if isinstance(value, str) else ""


def _state_string(value: Any, field: str, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ContractError("invalid_state", f"HybridOps state field '{field}' is not a string")
    if len(value) > limit:
        raise ContractError("invalid_state", f"HybridOps state field '{field}' is too long")
    return value


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _execution_contract_digest(
    target: Target,
    validated: ValidatedInput,
    executable: Path,
    timeout: int,
) -> str:
    payload = {
        "executable": str(executable),
        "inputs_path": str(target.inputs_path(validated.operation)),
        "inputs_sha256": validated.digest,
        "module_ref": MODULE_REF,
        "module_root": str(target.module_root),
        "operation": validated.operation,
        "root": str(target.root),
        "state_instance": target.state_instance,
        "target": target.name,
        "timeout_seconds": timeout,
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class HybridOpsRecoveryService:
    def __init__(self, get_config: Callable[[str, Any], Any]) -> None:
        self._get_config = get_config

    def _runtime(
        self, target_name: str, operation: str
    ) -> tuple[Target, ValidatedInput, Path, int, str]:
        target = load_target(self._get_config, target_name)
        validated = validate_input(target, operation)
        executable = resolve_executable(self._get_config)
        timeout = timeout_seconds(self._get_config)
        self._check_version(executable, target)
        contract_digest = _execution_contract_digest(target, validated, executable, timeout)
        return target, validated, executable, timeout, contract_digest

    def _check_version(self, executable: Path, target: Target) -> None:
        result = run_process(
            [str(executable), "--version"],
            cwd=target.root,
            env=child_environment(executable),
            timeout=10,
        )
        if (
            result.timed_out
            or result.interrupted
            or result.returncode != 0
            or result.stdout_truncated
        ):
            raise ContractError("version_check_failed", "the HybridOps version check failed")
        value = result.stdout.decode("utf-8", errors="replace").strip()
        match = _VERSION_RE.fullmatch(value)
        if not match or tuple(int(part) for part in match.groups()) < MINIMUM_HYOPS_VERSION:
            raise ContractError("unsupported_version", "HybridOps Core 0.1.6 or later is required")

    def pre_tool_call(
        self, tool_name: str = "", args: Any = None, **_: Any
    ) -> dict[str, str] | None:
        operation = MUTATING_TOOLS.get(tool_name)
        if operation is None:
            return None
        values = args if isinstance(args, Mapping) else {}
        target_name = _target_from_args(values)
        try:
            if not mutations_enabled(self._get_config):
                raise ContractError(
                    "mutations_disabled", "HybridOps recovery mutations are disabled"
                )
            target, validated, executable, _timeout, contract_digest = self._runtime(
                target_name, operation
            )
            expected_inputs = validate_expected_digest(values.get("expected_inputs_sha256"))
            expected_contract = validate_expected_digest(
                values.get("expected_contract_sha256"), "expected_contract_sha256"
            )
            if validated.digest != expected_inputs:
                raise ContractError(
                    "stale_digest",
                    "the configured input file has changed since inspection",
                )
            if contract_digest != expected_contract:
                raise ContractError(
                    "stale_contract",
                    "the configured recovery execution contract has changed since inspection",
                )
        except ContractError as exc:
            return {"action": "block", "message": f"BLOCKED: {exc.message}"}
        except Exception:  # noqa: BLE001
            return {"action": "block", "message": "BLOCKED: recovery approval validation failed"}
        message = (
            f"Run HybridOps recovery {operation} for target '{target.name}' at runtime root "
            f"'{target.root}' using executable '{executable}', module '{MODULE_REF}', input "
            f"SHA-256 {validated.digest}, and execution contract SHA-256 {contract_digest}."
        )
        return {
            "action": "approve",
            "message": message,
            "rule_key": f"{tool_name}:{target.name}:{contract_digest}",
        }

    def inspect(self, args: Any, **_: Any) -> str:
        values = args if isinstance(args, Mapping) else {}
        target_name = _target_from_args(values)
        operation = _operation_from_args(values, "inspect")
        try:
            if operation not in {"export", "import"}:
                raise ContractError("invalid_operation", "operation must be export or import")
            target, validated, executable, _timeout, contract_digest = self._runtime(
                target_name, operation
            )
            state = self._show_state(executable, target, required=False)
            return _json(
                {
                    "ok": True,
                    "operation": "inspect",
                    "target": target.name,
                    "selected_operation": operation,
                    "inputs_sha256": validated.digest,
                    "contract_sha256": contract_digest,
                    "mutations_enabled": mutations_enabled(self._get_config),
                    "state_available": state is not None,
                    "state": state,
                }
            )
        except ContractError as exc:
            return _error("inspect", target_name, exc)
        # Tool handlers return stable JSON without exposing unexpected exception text.
        except Exception:  # noqa: BLE001
            return _error(
                "inspect",
                target_name,
                ContractError("internal_error", "recovery inspection failed"),
            )

    def export(self, args: Any, **_: Any) -> str:
        return self._mutate("export", args)

    def import_(self, args: Any, **_: Any) -> str:
        return self._mutate("import", args)

    def _mutate(self, operation: str, args: Any) -> str:
        values = args if isinstance(args, Mapping) else {}
        target_name = _target_from_args(values)
        try:
            if not mutations_enabled(self._get_config):
                raise ContractError(
                    "mutations_disabled", "HybridOps recovery mutations are disabled"
                )
            expected = validate_expected_digest(values.get("expected_inputs_sha256"))
            expected_contract = validate_expected_digest(
                values.get("expected_contract_sha256"), "expected_contract_sha256"
            )
            target, validated, executable, timeout, contract_digest = self._runtime(
                target_name, operation
            )
            if validated.digest != expected:
                raise ContractError(
                    "stale_digest",
                    "the configured input file has changed since approval",
                )
            if contract_digest != expected_contract:
                raise ContractError(
                    "stale_contract",
                    "the configured recovery execution contract has changed since approval",
                )
            with _target_lock(target):
                before = self._show_state(executable, target, required=False)
                previous_run_id = str((before or {}).get("run_id") or "")
                with tempfile.TemporaryDirectory(prefix="hermes-hybridops-") as directory:
                    staged = Path(directory) / "inputs.yml"
                    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        _write_all(descriptor, validated.content)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    if hashlib.sha256(staged.read_bytes()).hexdigest() != expected:
                        raise ContractError(
                            "staging_failed",
                            "the staged recovery input failed integrity validation",
                        )
                    result = run_process(
                        self._apply_argv(executable, target, staged),
                        cwd=target.root,
                        env=child_environment(executable),
                        timeout=timeout,
                    )
                if result.timed_out:
                    raise ContractError(
                        "operation_timeout",
                        "the HybridOps recovery operation timed out",
                    )
                if result.interrupted:
                    raise ContractError(
                        "operation_interrupted",
                        "the HybridOps recovery operation was interrupted",
                    )
                if result.returncode != 0:
                    raise ContractError(
                        "operation_failed", "the HybridOps recovery operation failed"
                    )
                state = self._show_state(executable, target, required=True)
                if state is None:
                    raise ContractError(
                        "state_unavailable", "HybridOps did not publish recovery state"
                    )
                if previous_run_id and state.get("run_id") == previous_run_id:
                    raise ContractError(
                        "stale_state",
                        "HybridOps did not publish state for the completed operation",
                    )
                if (
                    state.get("status") != "ok"
                    or not state.get("run_id")
                    or not state.get("evidence_dir")
                ):
                    raise ContractError(
                        "inconsistent_state",
                        "HybridOps did not publish a complete successful state",
                    )
                outputs = state.get("outputs") if isinstance(state.get("outputs"), Mapping) else {}
                if outputs.get("action") != operation:
                    raise ContractError(
                        "inconsistent_state",
                        "HybridOps published an unexpected recovery action",
                    )
                recovery_digest = outputs.get("recovery_sha256") or ""
                topology_digest = outputs.get("topology_sha256") or ""
                if (
                    not re.fullmatch(r"[0-9a-f]{64}", recovery_digest)
                    or not re.fullmatch(r"[0-9a-f]{64}", topology_digest)
                    or not outputs.get("recovery_path")
                ):
                    raise ContractError(
                        "inconsistent_state",
                        "HybridOps did not publish complete recovery evidence",
                    )
                if operation == "export" and outputs.get("safe_for_host_destroy") is not True:
                    raise ContractError(
                        "unsafe_export",
                        "HybridOps did not confirm off-host recovery retention",
                    )
                return _json(
                    {
                        "ok": True,
                        "operation": operation,
                        "target": target.name,
                        "inputs_sha256": expected,
                        "contract_sha256": expected_contract,
                        "output_truncated": result.stdout_truncated or result.stderr_truncated,
                        "state": state,
                    }
                )
        except ContractError as exc:
            return _error(operation, target_name, exc)
        # Tool handlers return stable JSON without exposing unexpected exception text.
        except Exception:  # noqa: BLE001
            return _error(
                operation,
                target_name,
                ContractError("internal_error", "recovery operation failed"),
            )

    @staticmethod
    def _apply_argv(executable: Path, target: Target, inputs: Path) -> list[str]:
        argv = [
            str(executable),
            "apply",
            "--root",
            str(target.root),
            "--module",
            MODULE_REF,
            "--module-root",
            str(target.module_root),
            "--inputs",
            str(inputs),
        ]
        if target.state_instance:
            argv.extend(["--state-instance", target.state_instance])
        return argv

    def _show_state(
        self, executable: Path, target: Target, *, required: bool
    ) -> dict[str, Any] | None:
        result = run_process(
            [
                str(executable),
                "show",
                "module",
                target.module_state_ref,
                "--root",
                str(target.root),
                "--json",
            ],
            cwd=target.root,
            env=child_environment(executable),
            timeout=30,
        )
        if result.timed_out or result.interrupted or result.stdout_truncated:
            raise ContractError(
                "state_unavailable", "HybridOps recovery state could not be read safely"
            )
        if result.returncode != 0:
            if required:
                raise ContractError("state_unavailable", "HybridOps recovery state is unavailable")
            return None
        try:
            raw = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ContractError(
                "invalid_state", "HybridOps returned invalid recovery state"
            ) from exc
        if not isinstance(raw, Mapping) or raw.get("module_ref") != MODULE_REF:
            raise ContractError(
                "invalid_state", "HybridOps returned state for an unexpected module"
            )
        raw_state_instance = raw.get("state_instance")
        if raw_state_instance is not None and not isinstance(raw_state_instance, str):
            raise ContractError("invalid_state", "HybridOps returned an invalid state instance")
        state_instance = raw_state_instance or None
        if state_instance != target.state_instance:
            raise ContractError(
                "invalid_state", "HybridOps returned state for an unexpected instance"
            )
        outputs = raw.get("outputs")
        if outputs is None:
            outputs = {}
        elif not isinstance(outputs, Mapping):
            raise ContractError("invalid_state", "HybridOps returned invalid recovery outputs")
        safe_for_host_destroy = outputs.get("containerlab_recovery_safe_for_host_destroy")
        if safe_for_host_destroy is not None and not isinstance(safe_for_host_destroy, bool):
            raise ContractError(
                "invalid_state", "HybridOps returned an invalid recovery safety flag"
            )
        return {
            "module_ref": MODULE_REF,
            "state_instance": target.state_instance,
            "status": _state_string(raw.get("status"), "status", 32),
            "run_id": _state_string(raw.get("run_id"), "run_id", 128),
            "updated_at": _state_string(raw.get("updated_at"), "updated_at", 64),
            "evidence_dir": _state_string(raw.get("evidence_dir"), "evidence_dir", 4096),
            "outputs": {
                "action": _state_string(
                    outputs.get("containerlab_recovery_action"), "outputs.action", 16
                ),
                "mode": _state_string(
                    outputs.get("containerlab_recovery_mode"), "outputs.mode", 32
                ),
                "recovery_path": _state_string(
                    outputs.get("containerlab_recovery_path"), "outputs.recovery_path", 4096
                ),
                "recovery_sha256": _state_string(
                    outputs.get("containerlab_recovery_sha256"), "outputs.recovery_sha256", 64
                ),
                "topology_sha256": _state_string(
                    outputs.get("containerlab_recovery_topology_sha256"),
                    "outputs.topology_sha256",
                    64,
                ),
                "latest_path": _state_string(
                    outputs.get("containerlab_recovery_latest_path"), "outputs.latest_path", 4096
                ),
                "safe_for_host_destroy": safe_for_host_destroy is True,
            },
        }


@contextmanager
def _target_lock(target: Target) -> Iterator[None]:
    identity = f"{target.root}\0{target.module_state_ref}".encode()
    digest = hashlib.sha256(identity).hexdigest()
    lock_root = Path("/tmp") / f"hermes-hybridops-{os.geteuid()}"
    try:
        lock_root.mkdir(mode=0o700, exist_ok=True)
        root_info = lock_root.lstat()
    except OSError as exc:
        raise ContractError(
            "lock_unavailable", "the recovery operation lock is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
        or root_info.st_mode & 0o077
    ):
        raise ContractError("lock_unavailable", "the recovery operation lock directory is unsafe")
    lock_path = lock_root / f"{digest}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ContractError(
            "lock_unavailable", "the recovery operation lock file is unavailable"
        ) from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise ContractError("lock_unavailable", "the recovery operation lock file is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise ContractError(
            "operation_in_progress",
            "another recovery operation is already running for this target",
        ) from exc
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
