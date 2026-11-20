# Design

## Scope

The plugin exposes the existing HybridOps Containerlab recovery module to
Hermes. It supports Hermes Agent 0.23.3 or later, HybridOps Core 0.1.6 or later,
and one module reference:

```text
platform/linux/containerlab-recovery
```

Containerlab owns native configuration saves and supported vrnetlab snapshots.
HybridOps builds and verifies the recovery archive, retains it away from the
disposable host, and restores it. The plugin selects and invokes that workflow;
it does not interpret device state or create an archive format.

## Targets

Targets are defined in operator-managed plugin settings. Each target names a
HybridOps runtime root, module root, optional state instance, and separate input
files for export and import.

```yaml
root: /absolute/hybridops/runtime/root
module_root: /absolute/hybridops-core/modules
state_instance: optional-instance
export_inputs: /absolute/config/containerlab-recovery-export.yml
import_inputs: /absolute/config/containerlab-recovery-import.yml
```

Tool arguments contain only a target name, operation and inspection digests.
The model cannot supply executable paths, module references, input paths,
runtime roots, state instances, command-line arguments or environment
variables.

The plugin always uses `--root`; it does not combine `--root` with the mutually
exclusive HybridOps `--env` selector.

## Commands

Inspection reads state with a fixed command shape:

```text
hyops show module <module[#instance]> --root <root> --json
```

Export and import use:

```text
hyops apply --root <root> --module platform/linux/containerlab-recovery \
  --module-root <module-root> --inputs <private-staged-input>
```

The optional state instance is appended with `--state-instance`. There is no
destroy tool or `hyops destroy` command path. Host teardown remains a separate
operator action even when an export reports that retained recovery data is
safe.

## Approval

Inspection validates the selected input file and returns two SHA-256 values:

- the exact input bytes; and
- an execution contract containing the executable, target, runtime and module
  roots, state instance, input path, operation and timeout.

The export and import tools require both values. Their `pre_tool_call` hook
repeats validation before Hermes asks for approval. The handler repeats it after
approval, writes the validated bytes to a private temporary file, verifies that
copy, and then starts HybridOps.

The approval rule key contains the tool name, target and execution-contract
digest. Approval for one operation or configuration cannot be reused after an
input or target setting changes. Hermes denial or approval failure blocks the
call.

## Input Files

Input files must be regular files owned by root or the Hermes user, have one
hard link, and not be writable by group or others. They are opened without
following a final symlink and are checked again after reading. Files larger than
1 MiB are rejected.

YAML aliases, duplicate keys and keys outside the recovery module's public
input set are rejected. The role reference cannot be changed. Additional
recovery paths are excluded because they would widen the plugin's filesystem
read boundary. Import requires an absolute archive path without parent
traversal and a lowercase SHA-256 digest.

## Process Handling

Commands are passed as argument arrays with `shell=False`. The child environment
contains only `HOME`, a fixed executable search path, `NO_COLOR`, and available
locale fields. Parent credentials, `SSH_AUTH_SOCK` and `PYTHONPATH` are not
copied. HybridOps may read credentials from its own runtime configuration.

Standard output and error are drained concurrently and capped in memory. A
timeout or interruption terminates the complete process group. The plugin
returns normalized HybridOps state and short error records, never raw child
output or recovered configuration.

## State Checks

A mutation succeeds only when HybridOps exits with zero status and publishes a
new successful run for the configured module instance. The state must contain
the requested action, evidence directory, recovery path, archive digest and
topology digest. Export also requires
`containerlab_recovery_safe_for_host_destroy: true`.

Export and import for the same target are serialized with a non-blocking local
file lock. Calls for different targets use different locks.
