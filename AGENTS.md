# Maintainer Notes

This is a standalone Hermes plugin. Read `docs/design.md` and
`docs/threat-model.md` before changing its behavior. Check Hermes APIs against
the pinned integration revision and HybridOps behavior against the minimum
supported release.

Preserve these boundaries:

- only `platform/linux/containerlab-recovery` may be invoked;
- tool arguments must not expose commands, executable arguments, module
  references or file paths;
- export and import require local enablement and Hermes approval;
- child processes use fixed argument lists, no shell and an allowlisted
  environment;
- the plugin does not read credential files or return raw child output; and
- input files and published state are validated before use.

Add tests for any changed boundary and for both acceptance and rejection paths.
Before release, run the unit, Ruff and pinned Hermes integration suites, then
run `hermes plugins validate --install-deps` on the release commit. Review the
final diff and scanner output before submission.
