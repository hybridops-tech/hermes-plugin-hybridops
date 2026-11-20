# HybridOps for Hermes

This standalone plugin connects Hermes to the HybridOps
`platform/linux/containerlab-recovery` module. It provides three tools:

- `hybridops_recovery_inspect` validates a configured target and reads its
  current HybridOps state;
- `hybridops_recovery_export` creates and retains a recovery set; and
- `hybridops_recovery_import` restores a retained recovery set.

Archive creation, verification and restore remain in HybridOps and its
Containerlab recovery role. The plugin does not define another backup format.
Export and import are disabled by default and pass through the Hermes approval
gate when enabled.

See [Design](docs/design.md) and [Threat Model](docs/threat-model.md).

## Requirements

- Linux
- Hermes Agent 0.23.3 or later
- HybridOps Core 0.1.6 or later
- `hybridops.app` collection 0.1.14 or later

The plugin does not install HybridOps or its Ansible collections.

## Configuration

Add targets under `plugins.entries.hybridops.settings` in the active Hermes
profile:

```yaml
plugins:
  entries:
    hybridops:
      settings:
        hyops_executable: /usr/local/bin/hyops
        mutations_enabled: false
        timeout_seconds: 1800
        targets:
          lab:
            root: /srv/hybridops/runtime/lab
            module_root: /opt/hybridops/modules
            state_instance: containerlab_recovery
            export_inputs: /etc/hybridops/containerlab-export.yml
            import_inputs: /etc/hybridops/containerlab-import.yml
```

`root` is the HybridOps runtime root. The input files are chosen by the
operator. They must be regular files owned by root or the Hermes user and must
not be writable by group or others.

Inspection returns an input digest and an execution-contract digest. Export and
import require both values. The second digest covers the executable, runtime
root, module root, state instance, input path, operation and timeout, so a
configuration change invalidates an earlier inspection.

Input files may contain only inputs declared by the Containerlab recovery
module. Unknown keys and private Ansible variables are rejected. Imports also
require an absolute `containerlab_recovery_archive_path` and a lowercase
`containerlab_recovery_expected_sha256`. Additional recovery paths are not
accepted.

## Side Effects

- The plugin reads the configured input files and HybridOps module state.
- It runs the configured local `hyops` executable with fixed argument lists and
  never invokes a shell.
- HybridOps and Ansible may connect to the configured target, run Containerlab
  save or snapshot commands, and write recovery data on the target and
  controller. Import may replace the declared native lab directory after
  validation.
- The child process receives an allowlisted environment. HybridOps remains
  responsible for credentials selected by its runtime configuration.
- The plugin makes no direct network calls, starts no background process, sends
  no telemetry and does not update itself.

## License

MIT-0
