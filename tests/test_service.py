from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from .support import (
    PACKAGE_NAME,
    PLUGIN,
    make_layout,
    mutation_args,
    parse_result,
    read_calls,
    restore_environment,
    set_secret_environment,
)

contract = __import__(f"{PACKAGE_NAME}.contract", fromlist=["contract"])
service_module = __import__(f"{PACKAGE_NAME}.service", fromlist=["service"])


class ServiceTests(unittest.TestCase):
    def test_inspect_returns_digest_without_existing_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.inspect({"target": "lab", "operation": "export"}))
            expected = hashlib.sha256(paths["export_inputs"].read_bytes()).hexdigest()
            self.assertTrue(result["ok"])
            self.assertEqual(result["inputs_sha256"], expected)
            self.assertFalse(result["state_available"])

    def test_mutation_hook_blocks_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            result = service.pre_tool_call(
                tool_name=service_module.TOOL_EXPORT,
                args=args,
            )
            self.assertEqual(result["action"], "block")

    def test_mutation_hook_binds_approval_to_target_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            result = service.pre_tool_call(
                tool_name=service_module.TOOL_EXPORT,
                args=args,
            )
            self.assertEqual(result["action"], "approve")
            self.assertEqual(
                result["rule_key"],
                f"{service_module.TOOL_EXPORT}:lab:{args['expected_contract_sha256']}",
            )
            self.assertIn(args["expected_inputs_sha256"], result["message"])
            self.assertIn(args["expected_contract_sha256"], result["message"])

    def test_mutation_hook_rejects_stale_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            args["expected_inputs_sha256"] = "0" * 64
            result = service.pre_tool_call(
                tool_name=service_module.TOOL_EXPORT,
                args=args,
            )
            self.assertEqual(result["action"], "block")
            self.assertIn("changed since inspection", result["message"])

    def test_configuration_change_invalidates_approval_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            settings.values["timeout_seconds"] = 31

            hook_result = service.pre_tool_call(
                tool_name=service_module.TOOL_EXPORT,
                args=args,
            )
            self.assertEqual(hook_result["action"], "block")
            self.assertIn("execution contract has changed", hook_result["message"])

            handler_result = parse_result(service.export(args))
            self.assertFalse(handler_result["ok"])
            self.assertEqual(handler_result["error"]["code"], "stale_contract")
            self.assertFalse(any(call[0] == "apply" for call in read_calls(paths["calls_file"])))

    def test_input_change_after_approval_never_starts_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            hook_result = service.pre_tool_call(
                tool_name=service_module.TOOL_EXPORT,
                args=args,
            )
            self.assertEqual(hook_result["action"], "approve")
            with paths["export_inputs"].open("a", encoding="utf-8") as stream:
                stream.write("containerlab_recovery_save_configs_required: true\n")

            result = parse_result(service.export(args))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "stale_digest")
            self.assertFalse(any(call[0] == "apply" for call in read_calls(paths["calls_file"])))

    def test_prerelease_does_not_satisfy_stable_minimum_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            script = paths["executable"].read_text(encoding="utf-8")
            paths["executable"].write_text(
                script.replace('print("0.1.6")', 'print("0.1.6-rc1")'),
                encoding="utf-8",
            )
            paths["executable"].chmod(0o700)
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.inspect({"target": "lab", "operation": "export"}))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "unsupported_version")

    def test_export_uses_fixed_argv_and_minimal_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            key, previous = set_secret_environment()
            try:
                result = parse_result(service.export(args))
            finally:
                restore_environment(key, previous)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["state"]["outputs"]["action"], "export")
            self.assertTrue(result["state"]["outputs"]["safe_for_host_destroy"])
            self.assertNotIn("provider-token-from-child", json.dumps(result))
            child_env = json.loads(paths["env_file"].read_text(encoding="utf-8"))
            self.assertNotIn(key, child_env)
            self.assertNotIn("SSH_AUTH_SOCK", child_env)
            apply_call = next(
                call for call in read_calls(paths["calls_file"]) if call[0] == "apply"
            )
            self.assertIn("platform/linux/containerlab-recovery", apply_call)
            self.assertNotIn("destroy", apply_call)
            staged = Path(apply_call[apply_call.index("--inputs") + 1])
            self.assertFalse(staged.exists())

    def test_import_reports_verified_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "import")
            result = parse_result(service.import_(args))
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["state"]["outputs"]["action"], "import")
            self.assertFalse(result["state"]["outputs"]["safe_for_host_destroy"])

    def test_stale_digest_never_starts_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            args["expected_inputs_sha256"] = "0" * 64
            result = parse_result(service.export(args))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "stale_digest")
            self.assertFalse(any(call[0] == "apply" for call in read_calls(paths["calls_file"])))

    def test_nonzero_apply_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            script = paths["executable"].read_text(encoding="utf-8")
            marker = 'if args and args[0] == "apply":'
            replacement = 'if args and args[0] == "apply":\n    raise SystemExit(9)\nif False:'
            paths["executable"].write_text(
                script.replace(marker, replacement),
                encoding="utf-8",
            )
            paths["executable"].chmod(0o700)
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.export(mutation_args(service, "export")))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "operation_failed")

    def test_missing_post_apply_state_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            script = paths["executable"].read_text(encoding="utf-8")
            marker = 'if args and args[0] == "apply":'
            replacement = 'if args and args[0] == "apply":\n    raise SystemExit(0)\nif False:'
            paths["executable"].write_text(
                script.replace(marker, replacement),
                encoding="utf-8",
            )
            paths["executable"].chmod(0o700)
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.export(mutation_args(service, "export")))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "state_unavailable")

    def test_malformed_existing_state_blocks_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            paths["state_file"].write_text("not-json\n", encoding="utf-8")
            result = parse_result(service.export(args))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "invalid_state")
            self.assertFalse(any(call[0] == "apply" for call in read_calls(paths["calls_file"])))

    def test_non_scalar_state_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            paths["state_file"].write_text(
                json.dumps(
                    {
                        "module_ref": "platform/linux/containerlab-recovery",
                        "state_instance": "lab_instance",
                        "status": "ok",
                        "run_id": "run-1",
                        "updated_at": "2026-11-20T12:00:00Z",
                        "evidence_dir": {"unexpected": "value"},
                        "outputs": {},
                    }
                ),
                encoding="utf-8",
            )
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.inspect({"target": "lab", "operation": "export"}))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "invalid_state")

    def test_oversized_state_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory))
            paths["state_file"].write_text(
                json.dumps(
                    {
                        "module_ref": "platform/linux/containerlab-recovery",
                        "state_instance": "lab_instance",
                        "status": "ok",
                        "run_id": "run-1",
                        "updated_at": "2026-11-20T12:00:00Z",
                        "evidence_dir": "/tmp/evidence",
                        "outputs": {
                            "containerlab_recovery_sha256": "a" * 65,
                        },
                    }
                ),
                encoding="utf-8",
            )
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.inspect({"target": "lab", "operation": "export"}))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "invalid_state")

    def test_success_requires_topology_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            script = paths["executable"].read_text(encoding="utf-8")
            paths["executable"].write_text(
                script.replace(
                    '"containerlab_recovery_topology_sha256": "b" * 64,',
                    '"containerlab_recovery_topology_sha256": "",',
                ),
                encoding="utf-8",
            )
            paths["executable"].chmod(0o700)
            service = service_module.HybridOpsRecoveryService(settings.get)
            result = parse_result(service.export(mutation_args(service, "export")))
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "inconsistent_state")

    def test_stale_published_state_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service, "export")
            first = parse_result(service.export(args))
            self.assertTrue(first["ok"])
            script = paths["executable"].read_text(encoding="utf-8")
            marker = 'if args and args[0] == "apply":'
            replacement = 'if args and args[0] == "apply":\n    raise SystemExit(0)\nif False:'
            paths["executable"].write_text(script.replace(marker, replacement), encoding="utf-8")
            paths["executable"].chmod(0o700)
            second = parse_result(service.export(args))
            self.assertFalse(second["ok"])
            self.assertEqual(second["error"]["code"], "stale_state")

    def test_registration_exposes_only_recovery_tools(self) -> None:
        class Context:
            def __init__(self) -> None:
                self.tools: list[str] = []
                self.hooks: list[str] = []

            @staticmethod
            def get_config(key, default=None):
                return default

            def register_tool(self, name, **_kwargs):
                self.tools.append(name)

            def register_hook(self, name, _handler):
                self.hooks.append(name)

        context = Context()
        PLUGIN.register(context)
        self.assertEqual(
            context.tools,
            [
                service_module.TOOL_INSPECT,
                service_module.TOOL_EXPORT,
                service_module.TOOL_IMPORT,
            ],
        )
        self.assertEqual(context.hooks, ["pre_tool_call"])

    def test_services_do_not_share_profile_targets(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_directory,
            tempfile.TemporaryDirectory() as second_directory,
        ):
            first, _first_paths = make_layout(Path(first_directory))
            second, _second_paths = make_layout(Path(second_directory))
            first.values["targets"]["first"] = first.values["targets"].pop("lab")
            second.values["targets"]["second"] = second.values["targets"].pop("lab")
            first_service = service_module.HybridOpsRecoveryService(first.get)
            second_service = service_module.HybridOpsRecoveryService(second.get)

            first_result = parse_result(
                first_service.inspect({"target": "first", "operation": "export"})
            )
            second_result = parse_result(
                second_service.inspect({"target": "second", "operation": "export"})
            )
            cross_result = parse_result(
                first_service.inspect({"target": "second", "operation": "export"})
            )
            self.assertTrue(first_result["ok"])
            self.assertTrue(second_result["ok"])
            self.assertFalse(cross_result["ok"])
            self.assertEqual(cross_result["error"]["code"], "unknown_target")

    def test_target_lock_refuses_a_second_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, _paths = make_layout(Path(directory))
            target = contract.load_target(settings.get, "lab")
            with (
                service_module._target_lock(target),
                self.assertRaisesRegex(contract.ContractError, "already running"),
                service_module._target_lock(target),
            ):
                self.fail("second lock unexpectedly acquired")


if __name__ == "__main__":
    unittest.main()
