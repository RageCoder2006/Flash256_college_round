# Sandbox backends

| | `landlock` (default) | `gvisor` |
|---|---|---|
| Mechanism | `avhsol-sandbox`: Landlock filesystem + TCP port allowlist, seccomp denylist, rlimits | Docker with the `runsc` runtime, `--network none`, read-only root, caps dropped, pids/mem/cpu limits |
| Kernel | the host's | gVisor's user-space kernel (narrower host attack surface) |
| Needs | nothing (no root, no namespaces) | docker + gVisor registered as a runtime |
| Network | only the guard proxy and canary sink ports | none; those ports are **tunnelled over the container's stdio** (`internal/netmux`) to a host process that dials only the allowlist |
| Writable | the episode workspace | the episode workspace only |
| Is it a VM? | no | no (gVisor is not hardware virtualisation) |

Use `-isolation gvisor` on `campaign`, `hunt`, `validate`, `fork`, or `isolation: gvisor` in a target file. The host's `/usr` and the target's
`ro_paths` are mounted read-only over a base image (`debian:12` by default) so host-built agents (node, python) run unchanged; the host secret
used by the escape oracle is outside the workspace and simply not present in the container.

Verified here: a probe in gVisor reached the allowed port, could not reach the internet or read a host file, could write the workspace, and could
not write `/usr` (`TestGVisorConfinesTheAgentButReachesTheAllowedPort`); and a scripted agent got identical oracle results (10/14) under both backends.

Known limits: the tunnel is HTTP/TCP only; the simulated-tool harness's `bash` still runs under Landlock; images are not pulled automatically;
a micro-VM tier (QEMU is installed on the dev machine) is **not implemented**. The report states which isolation was used.
