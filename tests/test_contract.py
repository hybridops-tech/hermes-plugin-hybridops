from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from .support import PACKAGE_NAME, make_layout

contract = __import__(f"{PACKAGE_NAME}.contract", fromlist=["contract"])


class ContractTests(unittest.TestCase):
    def test_valid_input_is_bound_to_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            target = contract.load_target(settings.get, "lab")
            validated = contract.validate_input(target, "export")
            self.assertEqual(validated.operation, "export")
            self.assertRegex(validated.digest, r"^[0-9a-f]{64}$")

    def test_final_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            settings, paths = make_layout(base)
            link = base / "export-link.yml"
            link.symlink_to(paths["export_inputs"])
            settings.values["targets"]["lab"]["export_inputs"] = str(link)
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "opened safely"):
                contract.validate_input(target, "export")

    def test_group_writable_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            paths["export_inputs"].chmod(0o620)
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "writable by group"):
                contract.validate_input(target, "export")

    def test_wrong_action_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            paths["export_inputs"].write_text(
                "containerlab_recovery_action: import\n",
                encoding="utf-8",
            )
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "does not declare action"):
                contract.validate_input(target, "export")

    def test_duplicate_keys_and_aliases_are_rejected(self) -> None:
        documents = (
            "containerlab_recovery_action: export\ncontainerlab_recovery_action: export\n",
            "value: &value export\ncontainerlab_recovery_action: *value\n",
        )
        for document in documents:
            with (
                self.subTest(document=document),
                tempfile.TemporaryDirectory() as directory,
            ):
                settings, paths = make_layout(Path(directory))
                paths["export_inputs"].write_text(document, encoding="utf-8")
                target = contract.load_target(settings.get, "lab")
                with self.assertRaisesRegex(contract.ContractError, "restricted YAML"):
                    contract.validate_input(target, "export")

    def test_role_override_and_additional_paths_are_rejected(self) -> None:
        documents = (
            "containerlab_recovery_action: export\ncontainerlab_recovery_role_fqcn: other.role\n",
            "containerlab_recovery_action: export\n"
            "containerlab_recovery_additional_paths: [/etc]\n",
        )
        for document in documents:
            with (
                self.subTest(document=document),
                tempfile.TemporaryDirectory() as directory,
            ):
                settings, paths = make_layout(Path(directory))
                paths["export_inputs"].write_text(document, encoding="utf-8")
                target = contract.load_target(settings.get, "lab")
                with self.assertRaises(contract.ContractError):
                    contract.validate_input(target, "export")

    def test_unknown_input_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            paths["export_inputs"].write_text(
                "containerlab_recovery_action: export\n_hyops_requested_action: import\n",
                encoding="utf-8",
            )
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "unsupported keys"):
                contract.validate_input(target, "export")

    def test_import_requires_archive_path_and_expected_checksum(self) -> None:
        documents = (
            "containerlab_recovery_action: import\n",
            "containerlab_recovery_action: import\n"
            "containerlab_recovery_archive_path: /tmp/recovery.tar.gz\n",
            "containerlab_recovery_action: import\n"
            "containerlab_recovery_archive_path: relative/recovery.tar.gz\n"
            f"containerlab_recovery_expected_sha256: {'a' * 64}\n",
        )
        for document in documents:
            with (
                self.subTest(document=document),
                tempfile.TemporaryDirectory() as directory,
            ):
                settings, paths = make_layout(Path(directory))
                paths["import_inputs"].write_text(document, encoding="utf-8")
                target = contract.load_target(settings.get, "lab")
                with self.assertRaises(contract.ContractError):
                    contract.validate_input(target, "import")

    def test_oversized_input_is_rejected_before_yaml_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            with paths["export_inputs"].open("wb") as stream:
                stream.truncate(contract.MAX_INPUT_BYTES + 1)
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "exceeds 1 MiB"):
                contract.validate_input(target, "export")

    def test_executable_arguments_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            settings.values["hyops_executable"] = "hyops --unsafe"
            with self.assertRaisesRegex(contract.ContractError, "must not contain arguments"):
                contract.resolve_executable(settings.get)

    def test_input_parent_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            value = str(paths["root"] / ".." / "export.yml")
            settings.values["targets"]["lab"]["export_inputs"] = value
            with self.assertRaisesRegex(contract.ContractError, "without parent traversal"):
                contract.load_target(settings.get, "lab")

    def test_control_characters_in_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            settings.values["targets"]["lab"]["root"] += "\nsecond-line"
            with self.assertRaisesRegex(contract.ContractError, "unsupported characters"):
                contract.load_target(settings.get, "lab")

    def test_state_instance_must_be_a_string(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            settings.values["targets"]["lab"]["state_instance"] = 42
            with self.assertRaisesRegex(contract.ContractError, "invalid state_instance"):
                contract.load_target(settings.get, "lab")

    def test_timeout_must_be_an_integer(self) -> None:
        for value in (True, 30.5, "30"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                settings, _paths = make_layout(Path(directory))
                settings.values["timeout_seconds"] = value
                with self.assertRaisesRegex(contract.ContractError, "must be an integer"):
                    contract.timeout_seconds(settings.get)

    def test_hard_link_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            os.link(paths["export_inputs"], Path(directory) / "second-link.yml")
            target = contract.load_target(settings.get, "lab")
            with self.assertRaisesRegex(contract.ContractError, "exactly one hard link"):
                contract.validate_input(target, "export")

    def test_non_regular_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for kind in ("directory", "fifo"):
                with self.subTest(kind=kind):
                    settings, _paths = make_layout(base / kind)
                    candidate = base / f"{kind}-input"
                    if kind == "directory":
                        candidate.mkdir()
                    else:
                        os.mkfifo(candidate)
                    settings.values["targets"]["lab"]["export_inputs"] = str(candidate)
                    target = contract.load_target(settings.get, "lab")
                    with self.assertRaisesRegex(contract.ContractError, "not a regular file"):
                        contract.validate_input(target, "export")

    def test_foreign_owned_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            target = contract.load_target(settings.get, "lab")
            real_fstat = os.fstat

            def foreign_stat(descriptor: int) -> SimpleNamespace:
                value = real_fstat(descriptor)
                return SimpleNamespace(
                    st_mode=value.st_mode,
                    st_uid=os.geteuid() + 1,
                    st_nlink=value.st_nlink,
                    st_size=value.st_size,
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_mtime_ns=value.st_mtime_ns,
                )

            with (
                mock.patch.object(contract.os, "fstat", side_effect=foreign_stat),
                self.assertRaisesRegex(contract.ContractError, "unsupported owner"),
            ):
                contract.validate_input(target, "export")


if __name__ == "__main__":
    unittest.main()
