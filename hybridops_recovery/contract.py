"""Configuration and input validation for the HybridOps recovery contract."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MODULE_REF = "platform/linux/containerlab-recovery"
ROLE_FQCN = "hybridops.app.containerlab_recovery"
MAX_INPUT_BYTES = 1024 * 1024
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_EXECUTABLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
ALLOWED_INPUT_KEYS = frozenset(
    {
        "target_host",
        "local_execution",
        "target_state_ref",
        "target_vm_key",
        "inventory_groups",
        "inventory_state_ref",
        "inventory_vm_groups",
        "target_user",
        "target_port",
        "ssh_private_key_file",
        "ssh_access_mode",
        "ssh_proxy_jump_auto",
        "ssh_proxy_jump_host",
        "ssh_proxy_jump_user",
        "ssh_proxy_jump_port",
        "gcp_iap_instance",
        "gcp_iap_project_id",
        "gcp_iap_zone",
        "become",
        "become_user",
        "connectivity_check",
        "connectivity_timeout_s",
        "connectivity_wait_s",
        "execution_timeout_s",
        "required_env",
        "required_env_destroy",
        "load_vault_env",
        "containerlab_recovery_role_fqcn",
        "containerlab_recovery_action",
        "containerlab_recovery_mode",
        "containerlab_recovery_topology_path",
        "containerlab_recovery_source_root",
        "containerlab_recovery_topology_relpath",
        "containerlab_recovery_image_refs",
        "containerlab_recovery_labdir_base",
        "containerlab_recovery_controller_dir",
        "containerlab_recovery_latest_path",
        "containerlab_recovery_path",
        "containerlab_recovery_archive_path",
        "containerlab_recovery_expected_sha256",
        "containerlab_recovery_overwrite",
        "containerlab_recovery_save_configs",
        "containerlab_recovery_save_configs_required",
        "containerlab_recovery_snapshot_timeout",
        "containerlab_recovery_snapshot_node_filter",
        "containerlab_recovery_include_lab_dir",
        "containerlab_recovery_lab_dir",
        "containerlab_recovery_additional_paths",
        "containerlab_recovery_disable_version_check",
    }
)


class ContractError(Exception):
    """A safe, user-facing contract failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Target:
    name: str
    root: Path
    module_root: Path
    state_instance: str | None
    export_inputs: Path
    import_inputs: Path

    @property
    def module_state_ref(self) -> str:
        if self.state_instance:
            return f"{MODULE_REF}#{self.state_instance}"
        return MODULE_REF

    def inputs_path(self, operation: str) -> Path:
        return self.export_inputs if operation == "export" else self.import_inputs


@dataclass(frozen=True)
class ValidatedInput:
    content: bytes
    digest: str
    operation: str


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects aliases and duplicate mapping keys."""

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not supported")
        return super().compose_node(parent, index)


def _construct_mapping(loader, node, deep=False):  # type: ignore[no-untyped-def]
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.YAMLError("mapping keys must be scalar") from exc
        if duplicate:
            raise yaml.YAMLError(f"duplicate mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_NoAliasSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _path_value(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError("invalid_target", f"{field} must be a non-empty absolute path")
    if len(value) > 4096 or any(ord(character) < 32 for character in value):
        raise ContractError("invalid_target", f"{field} contains unsupported characters")
    return value


def _absolute_path(value: Any, field: str) -> Path:
    path = Path(_path_value(value, field))
    if not path.is_absolute():
        raise ContractError("invalid_target", f"{field} must be an absolute path")
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise ContractError("invalid_target", f"{field} could not be resolved") from exc


def _input_path(value: Any, field: str) -> Path:
    path = Path(_path_value(value, field))
    if not path.is_absolute() or ".." in path.parts:
        raise ContractError(
            "invalid_target",
            f"{field} must be an absolute path without parent traversal",
        )
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ContractError("invalid_target", f"{field} parent directory is unavailable") from exc
    if not parent.is_dir():
        raise ContractError("invalid_target", f"{field} parent is not a directory")
    return parent / path.name


def _target_mapping(settings: Any, name: str) -> Mapping[str, Any]:
    if not _NAME_RE.fullmatch(name):
        raise ContractError("invalid_target", "target must match [a-z0-9][a-z0-9_-]{0,63}")
    if not isinstance(settings, Mapping):
        raise ContractError("invalid_configuration", "targets must be a mapping")
    value = settings.get(name)
    if not isinstance(value, Mapping):
        raise ContractError("unknown_target", f"recovery target '{name}' is not configured")
    allowed = {
        "root",
        "module_root",
        "state_instance",
        "export_inputs",
        "import_inputs",
    }
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise ContractError(
            "invalid_target",
            f"target '{name}' has unsupported settings: {', '.join(unknown)}",
        )
    return value


def load_target(get_config: Callable[[str, Any], Any], name: str) -> Target:
    raw = _target_mapping(get_config("targets", {}), name)
    state_instance = raw.get("state_instance")
    if state_instance is not None and not isinstance(state_instance, str):
        raise ContractError("invalid_target", f"target '{name}' has an invalid state_instance")
    state_instance_value = (state_instance or "").strip().lower()
    if state_instance_value and not _INSTANCE_RE.fullmatch(state_instance_value):
        raise ContractError("invalid_target", f"target '{name}' has an invalid state_instance")

    root = _absolute_path(raw.get("root"), "root")
    module_root = _absolute_path(raw.get("module_root"), "module_root")
    if not root.is_dir():
        raise ContractError("invalid_target", f"target '{name}' root is not a directory")
    if not module_root.is_dir():
        raise ContractError("invalid_target", f"target '{name}' module_root is not a directory")
    spec_path = module_root / "platform" / "linux" / "containerlab-recovery" / "spec.yml"
    if not spec_path.is_file():
        raise ContractError(
            "invalid_target",
            f"target '{name}' does not contain the fixed recovery module",
        )

    return Target(
        name=name,
        root=root,
        module_root=module_root,
        state_instance=state_instance_value or None,
        export_inputs=_input_path(raw.get("export_inputs"), "export_inputs"),
        import_inputs=_input_path(raw.get("import_inputs"), "import_inputs"),
    )


def timeout_seconds(get_config: Callable[[str, Any], Any]) -> int:
    value = get_config("timeout_seconds", 1800)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError("invalid_configuration", "timeout_seconds must be an integer")
    if value < 30 or value > 14400:
        raise ContractError("invalid_configuration", "timeout_seconds must be between 30 and 14400")
    return value


def mutations_enabled(get_config: Callable[[str, Any], Any]) -> bool:
    value = get_config("mutations_enabled", False)
    if not isinstance(value, bool):
        raise ContractError("invalid_configuration", "mutations_enabled must be a boolean")
    return value


def resolve_executable(get_config: Callable[[str, Any], Any]) -> Path:
    value = get_config("hyops_executable", "hyops")
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(ord(character) < 32 for character in value)
    ):
        raise ContractError(
            "invalid_executable",
            "hyops_executable must be a command name or absolute path",
        )
    raw = value.strip()
    path = Path(raw)
    if path.is_absolute():
        candidate = path.resolve(strict=False)
    else:
        if not _EXECUTABLE_RE.fullmatch(raw):
            raise ContractError(
                "invalid_executable",
                "hyops_executable must not contain arguments or relative paths",
            )
        found = shutil.which(raw)
        if not found:
            raise ContractError(
                "executable_unavailable",
                "the configured HybridOps executable was not found",
            )
        candidate = Path(found).resolve(strict=False)
    try:
        info = candidate.stat()
    except OSError as exc:
        raise ContractError(
            "executable_unavailable",
            "the configured HybridOps executable is unavailable",
        ) from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(candidate, os.X_OK):
        raise ContractError(
            "invalid_executable",
            "the configured HybridOps executable is not an executable file",
        )
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ContractError(
            "unsafe_executable",
            "the configured HybridOps executable has unsafe ownership or permissions",
        )
    return candidate


def validate_expected_digest(value: Any, field: str = "expected_inputs_sha256") -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ContractError(
            "invalid_digest",
            f"{field} must be 64 lowercase hexadecimal characters",
        )
    return value


def _read_secure_file(path: Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(
            "unsafe_input_file", "the configured input file could not be opened safely"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(
                "unsafe_input_file", "the configured input path is not a regular file"
            )
        if before.st_uid not in {0, os.geteuid()}:
            raise ContractError(
                "unsafe_input_file",
                "the configured input file has an unsupported owner",
            )
        if before.st_mode & 0o022:
            raise ContractError(
                "unsafe_input_file",
                "the configured input file is writable by group or others",
            )
        if before.st_nlink != 1:
            raise ContractError(
                "unsafe_input_file",
                "the configured input file must have exactly one hard link",
            )
        if before.st_size > MAX_INPUT_BYTES:
            raise ContractError("input_too_large", "the configured input file exceeds 1 MiB")
        content = bytearray()
        while len(content) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if len(content) > MAX_INPUT_BYTES:
            raise ContractError("input_too_large", "the configured input file exceeds 1 MiB")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ContractError(
                "input_changed", "the configured input file changed while it was read"
            )
        return bytes(content)
    finally:
        os.close(descriptor)


def validate_input(target: Target, operation: str) -> ValidatedInput:
    if operation not in {"export", "import"}:
        raise ContractError("invalid_operation", "operation must be export or import")
    content = _read_secure_file(target.inputs_path(operation))
    try:
        document = yaml.load(content, Loader=_NoAliasSafeLoader)
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ContractError(
            "invalid_inputs", "the configured input file is not valid restricted YAML"
        ) from exc
    if not isinstance(document, Mapping):
        raise ContractError("invalid_inputs", "the configured input document must be a mapping")
    unknown = sorted(str(key) for key in document if key not in ALLOWED_INPUT_KEYS)
    if unknown:
        raise ContractError(
            "unsupported_inputs",
            f"the configured input document has unsupported keys: {', '.join(unknown)}",
        )
    if document.get("containerlab_recovery_action") != operation:
        raise ContractError(
            "wrong_action",
            f"the configured input document does not declare action '{operation}'",
        )
    role = document.get("containerlab_recovery_role_fqcn")
    if role is not None and role != ROLE_FQCN:
        raise ContractError("role_override", "containerlab_recovery_role_fqcn cannot be overridden")
    additional_paths = document.get("containerlab_recovery_additional_paths")
    if additional_paths not in (None, []):
        raise ContractError(
            "additional_paths",
            "additional recovery paths are not supported by this plugin",
        )
    if operation == "import":
        archive_path = document.get("containerlab_recovery_archive_path")
        if (
            not isinstance(archive_path, str)
            or not archive_path.strip()
            or not Path(archive_path).is_absolute()
            or ".." in Path(archive_path).parts
        ):
            raise ContractError(
                "invalid_archive_path",
                "containerlab_recovery_archive_path must be an absolute path "
                "without parent traversal",
            )
        validate_expected_digest(
            document.get("containerlab_recovery_expected_sha256"),
            "containerlab_recovery_expected_sha256",
        )
    return ValidatedInput(
        content=content,
        digest=hashlib.sha256(content).hexdigest(),
        operation=operation,
    )
