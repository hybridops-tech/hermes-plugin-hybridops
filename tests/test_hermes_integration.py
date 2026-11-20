from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from hermes_cli import lifecycle, plugins
    from hermes_cli.plugin_dev import doctor_plugin
    from hermes_cli.plugin_validate import validate_plugin_dir
except ImportError:  # The dedicated integration job installs pinned Hermes.
    if os.environ.get("HERMES_INTEGRATION_REQUIRED") == "1":
        raise
    lifecycle = None
    plugins = None
    doctor_plugin = None
    validate_plugin_dir = None

from .support import PACKAGE_NAME, ROOT, make_layout, mutation_args, read_calls

service_module = __import__(f"{PACKAGE_NAME}.hybridops_recovery.service", fromlist=["service"])
EXPECTED_TOOLS = {
    service_module.TOOL_INSPECT,
    service_module.TOOL_EXPORT,
    service_module.TOOL_IMPORT,
}


@unittest.skipIf(lifecycle is None, "Hermes integration environment is not installed")
class HermesIntegrationTests(unittest.TestCase):
    def test_admission_validation(self) -> None:
        admission = validate_plugin_dir(ROOT)
        self.assertTrue(admission.ok, admission.failures)
        self.assertEqual(admission.warnings, [])

    def test_runtime_discovery(self) -> None:
        doctor = doctor_plugin(ROOT)
        self.assertTrue(doctor.ok, doctor.format_text())
        self.assertEqual(set(doctor.registered_tools), EXPECTED_TOOLS)
        self.assertEqual(doctor.registered_hooks, ("pre_tool_call",))

    def test_hermes_denial_blocks_export_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service)

            def invoke_hook(hook_name: str, **kwargs):
                return [service.pre_tool_call(**kwargs)] if hook_name == "pre_tool_call" else []

            with (
                patch.object(lifecycle, "invoke_hook", side_effect=invoke_hook),
                patch(
                    "tools.approval.request_tool_approval",
                    return_value={"approved": False, "message": "BLOCKED: approval denied"},
                ),
            ):
                blocked = plugins.resolve_pre_tool_block(service_module.TOOL_EXPORT, args)

            self.assertEqual(blocked, "BLOCKED: approval denied")
            self.assertFalse(
                any(call and call[0] == "apply" for call in read_calls(paths["calls_file"]))
            )

    def test_hermes_approval_failure_blocks_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings, paths = make_layout(Path(directory), mutations=True)
            service = service_module.HybridOpsRecoveryService(settings.get)
            args = mutation_args(service)

            def invoke_hook(hook_name: str, **kwargs):
                return [service.pre_tool_call(**kwargs)] if hook_name == "pre_tool_call" else []

            with (
                patch.object(lifecycle, "invoke_hook", side_effect=invoke_hook),
                patch(
                    "tools.approval.request_tool_approval",
                    side_effect=TimeoutError("approval timed out"),
                ),
            ):
                blocked = plugins.resolve_pre_tool_block(service_module.TOOL_EXPORT, args)

            self.assertEqual(
                blocked,
                f"BLOCKED: plugin approval gate failed for {service_module.TOOL_EXPORT}",
            )
            self.assertFalse(
                any(call and call[0] == "apply" for call in read_calls(paths["calls_file"]))
            )


if __name__ == "__main__":
    unittest.main()
