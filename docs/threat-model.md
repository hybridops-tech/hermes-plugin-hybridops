# Threat Model

## Assets

- Containerlab topology, configuration and native lab state
- retained archives and manifests
- HybridOps runtime state and credentials
- target and controller filesystems
- Hermes profile isolation
- operator approval

## Boundaries

1. Tool arguments from Hermes enter the plugin handler.
2. Plugin settings select an operator-defined target and input file.
3. The plugin starts the local HybridOps executable.
4. HybridOps and Ansible communicate with the target host.
5. Recovery data moves from the target to controller storage.

The plugin controls the first three boundaries. HybridOps controls target access
and archive transfer.

## Controls

| Risk | Control | Test coverage |
| --- | --- | --- |
| Arbitrary command execution | Fixed argument lists, fixed module reference and no shell | Unknown actions, arguments and input keys are rejected |
| Model-selected file access | Tool schemas accept target names, not paths | Undeclared targets fail validation |
| Input changes after inspection | Input and execution-contract digests are checked before and after approval | Input and configuration changes block `hyops apply` |
| Path substitution | Absolute paths, no-follow open and descriptor ownership, mode and type checks | Symlink, hard-link, FIFO, ownership and permission cases |
| Child environment leakage | New allowlisted environment instead of a copy of `os.environ` | Token-shaped variables and `SSH_AUTH_SOCK` are absent |
| Child output leakage | Bounded output capture and normalized responses | Token-shaped child output is not returned |
| Cross-profile target leakage | Configuration is read from the active plugin context with no global target cache | Services with separate settings cannot use each other's targets |
| Approval bypass | Mutations default off; Hermes hook approval and handler checks are both required | Disabled, denied and failed approvals do not dispatch export |
| Host destruction | No destroy tool or destroy command template | Registered tools and apply arguments are asserted |
| Wrong recovery archive | Import requires an absolute archive path and expected SHA-256; HybridOps verifies the archive and manifest | Missing, malformed and mismatched digest cases |
| Additional file capture | Non-empty `containerlab_recovery_additional_paths` is rejected | Input validation case |
| Hung child process | Deadline, bounded stream readers and process-group termination | Timeout, interruption and signal-resistant descendant cases |
| Concurrent target mutation | Non-blocking lock derived from runtime root and module instance | A second lock for the same target is refused |
| Stale or false success | New run ID, successful status, evidence path, action and recovery digests are required | Missing, malformed, stale and incomplete state cases |
| Dependency drift | CI pins the Hermes integration revision and test dependencies | Admission and discovery run against the pinned revision |

## Release Checks

Before release:

- run unit tests on every supported Python version;
- run Ruff and bytecode compilation;
- run admission, discovery and approval tests against the pinned Hermes
  revision;
- run `hermes plugins validate --install-deps` on the release commit; and
- exercise export and import with a disposable HybridOps runtime and inspect the
  retained archive and restored topology independently.

The system test must use the minimum supported HybridOps release or a newer
release explicitly recorded with the result. It must not use production lab
state.
