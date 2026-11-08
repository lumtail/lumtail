<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Sandbox

Read this page to choose input paths and require a sandbox before inspecting untrusted logs.

```sh
lumtail --sandbox-status
lumtail --require-sandbox --agent --limit 20 app.log
lumtail --require-sandbox --sandbox-status
```

The CLI installs the available sandbox before loading rules, reading logs or
starting workers. `--sandbox-status` prints the active policy and exits.
An unexpected setup failure produces a diagnostic and status 1.

## Require a production policy

`--require-sandbox` accepts a complete OpenBSD `unveil`/`pledge`, Linux
Landlock/seccomp with `PR_SET_NO_NEW_PRIVS`, or FreeBSD Capsicum/fileargs policy.
It also requires disabled core dumps and a production build.

An unavailable policy causes status 1 before loading rule contents or reading
logs. With `--sandbox-status`, the report still prints and the same check
determines the exit status. Help, version and schema queries remain available.
Invalid arguments produce status 2.

## Platform choices

| System | Sandbox | Allowed access |
| --- | --- | --- |
| OpenBSD | `unveil`, `pledge` | Selected input/rule names, stdio, read paths and terminal queries; name-based rules support file replacement. |
| Linux | Landlock, seccomp BPF, `PR_SET_NO_NEW_PRIVS` | Selected read-only input inodes, I/O, allocation, signals and threads; follow mode allows the containing read hierarchy. |
| FreeBSD | Capsicum, Casper `fileargs` | Standard descriptors and a read-only broker for each selected input/rule name and I/O mode. |
| macOS | Deployment App Sandbox entitlement | Access follows the signed application's entitlements; local unsigned or ad-hoc builds report the filesystem/syscall policy unavailable. |
| NetBSD | Startup checks | Filesystem/syscall policy is reported unavailable. |

All targets check real/effective user and group IDs, close inherited descriptors
above stdin/stdout/stderr and set core-dump limits to zero.
Owned input descriptors are read-only and close-on-exec.

macOS applies deployment App Sandbox policy at launch. Lumtail loads the
entitlement inspection APIs when reporting or requiring a sandbox; ordinary
processing and discovery commands keep the startup checks above.

Linux selects Landlock rights supported by its headers and running kernel.
Seccomp checks the syscall ABI and synchronizes installation across threads;
new workers inherit the policy. Unknown syscalls return `ENOSYS` so libc can use
supported fallbacks. A foreign syscall ABI terminates the process.

FreeBSD uses one broker per path and I/O mode because `fileargs` prefetching opens other inputs early and caches metadata.
Broker processes and descriptors grow with the number of paths.
Allocation or service startup failure stops the command.

## Follow mode and path choice

Linux `--follow` allows read access to the selected file's parent directory so
replacement inodes remain readable. It also allows a pre-existing symlink's
resolved parent. Put followed logs in a dedicated directory when that read scope
matters. Finite reads use the selected inode.

OpenBSD and FreeBSD keep selected-name access across replacement.
Administrators control those paths and symlinks.
Use a pre-opened stdin stream and launcher-controlled output descriptors when
you need a smaller path boundary.

## Instrumented builds

Sanitizers, fuzzing and coverage use build-time exceptions for their runtimes.
The status report identifies those builds; `--require-sandbox` rejects them.
Production builds use the ordinary policy.
The [release checks](validation.md) list the corresponding test jobs.

## Limits

macOS entitlements and NetBSD startup checks fail `--require-sandbox`.
An App Sandbox deployment needs a signing identity, entitlements and access to
the selected logs; signing alone supplies a different boundary from the selected
paths on Linux or BSD.

Standard input, output and error remain available to the process.
Treat the launcher, arguments, environment, loaded libraries and input-directory
administration as trusted. Another process that can replace an allowed name or
symlink can change the file a path-based broker opens.
Replacing an entire allowed directory falls outside supported rotation.

Sandbox behavior depends on the OS and kernel.
The [safety rules](safety.md) describe input handling, source preservation and
failure behavior.
