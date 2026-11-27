# app-sandbox

The `app-sandbox` package installs the `app-sandbox` upatch, which puts
applications, pod workloads and autonomous LLM agents in sandboxes. A
sandbox restricts every task that executed one of its files (optionally
narrowed to specific Kubernetes Pod cgroup v2 IDs), and the tasks those
start, in:

- what it executes: its own files and those of the policies it names;
- which socket families it creates (`inet`, `inet6`, `unix`, `netlink`,
  `vsock`) and whether it may invoke `ptrace`;
- where it connects and sends: IPv4/IPv6 CIDR allow and deny lists,
  TCP/UDP destination port allow and deny lists, and UNIX domain socket
  path/name denylists;
- which files it creates, renames, opens for reading, opens for writing
  or truncates: none whose name matches a pattern it denies.

The package ships default web sandboxes in `sandbox.toml` for Apache
httpd and PHP-FPM, plus `llm-agent.toml` for autonomous LLM agent
runtimes. Replace or override them with sandboxes for your own
applications.

Its tree entry names the PHP2Shell advisories, CVE-2026-109618 and
CVE-2026-109619, as `fixes`, so that a backend that reads the tree
counts a node that loaded the upatch as shielded against them. The
sandboxes do not close the hole in PHP: a request can still run the
attacker's code in the application. They keep that code from leaving a
PHP file behind, from running another program and from connecting out.
Upgrade PHP as well.

A sandbox restricts and never grants: a task in it keeps every limit it
had. It is not a boundary against root outside the sandbox, and a file
replaced after the load is a new file without the label, see "Limits".

## Define a sandbox

A sandbox has two parts. The `Beefile` gives it a name, a policy bit and
the executables that put a task in it, as a `[[upatches.policy]]` table
(see `Documentation/reference/formats/beefile.rst`):

```toml
[[upatches.policy]]
id = "apache"
bit = 0x1
paths = ["/usr/sbin/apache2", "/usr/sbin/httpd"]
```

The last component of a path may be a pattern, as in
`/usr/sbin/php-fpm*` for the PHP-FPM of any version: the target labels
every regular file of the directory that matches it.

`sandbox.toml` (or an override such as `llm-agent.toml`) gives the rules
of the sandbox of that name:

```toml
[networks]
localnet = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[sandbox.apache]
exec = ["apache-helpers"]
families = ["inet", "inet6", "unix"]
network = ["@localnet", "192.0.2.10/32"]
ports = [80, 443, "tcp/3306", "udp/53"]
cgroup_ids = [4294967399]
deny_ptrace = true

[sandbox.apache.deny]
network = ["169.254.169.254/32"]
ports = [22, "tcp/25"]
unix = ["docker.sock", "*/docker.sock"]
create = ["*.php"]
rename = ["*.php"]
write = ["*.php"]
read = ["*.pem", "*credentials*"]
```

| Key | Without it | With it |
|---|---|---|
| `cgroup_ids` | Every task carrying the policy bit is confined. | Only tasks in one of the listed cgroups, or below one, are confined by this sandbox on a shared node. Each entry is the 64-bit ID of a cgroup v2 directory, a Pod's or a container's, which is its inode number (`stat -c %i /sys/fs/cgroup/<path>`). The task's own cgroup and its ancestors down to 12 levels below the root are compared; a task of this policy in no listed cgroup, or under one nested deeper than that, is **not** confined. The IDs are signed into the package and a cgroup gets a new one each time it is created, so a restarted Pod needs a package built with its new ID. |
| `exec` | The task executes anything. | It executes only files labeled with its own policy or with one of the policy IDs listed, each a `[[upatches.policy]]` table of the Beefile. `exec = []` allows its own files alone. |
| `families` | Socket families are not filtered (except raw/packet when IP/port rules apply). | `socket()` allows only the listed families (`inet`, `inet6`, `unix`, `netlink`, `vsock`). |
| `network` | The task connects to any IP address not in `deny.network`. | It connects and sends only to the networks listed, IPv4 or IPv6 in CIDR form, or `@<name>` for a list of `[networks]`. An IPv4 network also covers its IPv4-mapped IPv6 form. It creates no raw and no packet socket. `network = []` allows no IP peer. |
| `ports` | Any TCP/UDP destination port not in `deny.ports` is allowed. | `connect()` and `sendmsg()` allow only the listed ports or ranges (`443`, `"8000-8080"`, `"tcp/443"`, `"udp/53"`), mapping MPTCP to TCP and UDPLite to UDP and refusing other IP protocols. |
| `deny_ptrace` | `ptrace` keeps normal kernel checks. | When `true`, `lsm/ptrace_access_check` refuses `ptrace` from the sandbox. |
| `deny.network` | | Refuses `connect()` and `sendmsg()` to matching IPv4/IPv6 CIDRs (takes precedence over `network`) and blocks raw/packet sockets. |
| `deny.ports` | | Refuses `connect()` and `sendmsg()` to matching TCP/UDP destination ports or ranges (takes precedence over `ports`), mapping MPTCP to TCP and UDPLite to UDP and refusing other IP protocols. |
| `deny.unix` | | Refuses `unix_stream_connect` and `unix_may_send` to UNIX sockets matching a basename pattern (no `/`) or full path/abstract `@name` pattern (with `/`). |
| `deny.create` | | It creates no file, directory, device, symbolic link or hard link with a matching name. |
| `deny.rename` | | It renames no file from or to a matching name. |
| `deny.write` | | It opens no file with a matching name for writing, does not truncate one, and creates no hard link to one. |
| `deny.read` | | It opens no file with a matching name for reading (`FMODE_READ`) and creates no hard link to one, gated by `read_enforced` so sandboxes without `deny.read` exit immediately on read opens. |

A file pattern is matched against the last component of the path. It is
the name itself, `prefix*suffix` with at most one `*` and up to 32 bytes
on each side, or `*substring*` (up to 32 bytes, matched within the first
64 bytes of the name), with `?` matching any one byte.

A script is executed with its interpreter, and the kernel asks for
both: a sandbox with `exec` runs a script only when the script and its
interpreter are each labeled with a policy the sandbox allows.

The package holds up to 32 sandboxes, 32 pod cgroup IDs, 128 network
entries, 64 port rules and 64 file/UNIX patterns. A task in two
sandboxes, one that executed files of both, is held to the rules of
each.

## Autonomous LLM agent profile (`llm-agent.toml`)

`llm-agent.toml` confines autonomous LLM agent runtimes (`/usr/local/bin/llm-agent*`):

- restricts socket families to `["inet", "inet6", "unix"]`;
- blocks the cloud metadata and credential endpoints: instance metadata
  (`169.254.169.254/32`, `fd00:ec2::254/128`), the ECS task and EKS Pod
  Identity endpoints (`169.254.170.2/32`, `169.254.170.23/32`,
  `fd00:ec2::23/128`), Alibaba Cloud (`100.100.100.200/32`) and Oracle
  Cloud (`192.0.0.192/32`);
- denies reading or renaming credential and secret files (`*.pem`,
  `id_rsa*`, `id_ed25519*`, `.env*`, `*credentials*`, `token`), and
  denies creating, renaming or writing key and SSH authorization files
  (`*.pem`, `id_rsa*`, `id_ed25519*`, `authorized_keys`);
- denies connecting to container-runtime UNIX sockets (`docker.sock`,
  `*/docker.sock`, `*containerd*`, `crio.sock`);
- denies `ptrace` (`deny_ptrace = true`).

It has no `exec` rule, so the agent executes any file. A package built
from this input holds the `llm-agent` sandbox alone: the Apache and
PHP-FPM sandboxes of `sandbox.toml` are not in it, and a target that
takes it in place of the default package no longer confines them.

Build the LLM agent profile with:

```sh
shirudo bpm build upatches/app-sandbox --version 1.0.0 \
	--rodata-input sandbox=upatches/app-sandbox/llm-agent.toml \
	--keys-dir <keys>
```

`gen_policy.py` turns the input TOML into the `sandbox_policy` variable
of the upatch when `shirudo bpm build` runs, and fails the build for a
sandbox the Beefile declares no policy for, a network, port, cgroup ID
or pattern it cannot read and a table or key it does not know. Read back
what a build holds with:

```sh
shirudo bpm info data app-sandbox-<version>.bee upatches/app-sandbox.upatch --json
```

## Build and publish

Build in a directory that holds shirudo's BPF headers and a `vmlinux.h`
(see `Documentation/start/guides/publish-package.rst`):

```sh
shirudo bpm build upatches/app-sandbox --version 1.0.0 --keys-dir <keys>
shirudo bpm push app-sandbox-1.0.0.bee oci://<registry>/<namespace>/app-sandbox --keys-dir <keys>
shirudo bpm tree append app-sandbox-1.0.0.bee oci://<registry>/<tree> --keys-dir <keys>
```

The Beefile has a tree entry without a selector, with the advisories
above as its `fixes`, so every node that syncs the tree loads the
upatch; on a node without the applications it labels nothing and
restricts nothing. Add a selector to load it only where they run:

```toml
[upatches.tree.selector.labels]
role = ["web"]
```

`tools/put-shields`, and `make shields` with it, publishes the package
with the other shields of `upatches/`.

`--rodata-input sandbox=<file>` builds with other rules for the
policies of the Beefile, and `shirudo bpm config update` signs new rules
into a package already built, without compiling it again.

## What a load does

The load labels each path of the Beefile that exists on the target with
its policy bit, in the `security.bpf.shirudo.policy` xattr. shirudo
gives a task the bits of every file it executes, and its children
inherit them, so a task enters a sandbox at its next `execve()` of a
labeled file: restart the application after the first load. An unload
leaves the labels, which restrict nothing once the upatch is gone.

Every refusal is `EACCES`.

## Try it with Apache

`demo/` in the source of this package holds a web server to try the
`apache` sandbox on: Apache httpd with PHP from the official
`php:8.4-apache` image, a site on port 8443 and `attack.php`, which
does from inside PHP what an attacker would next. `demo/build.sh` writes
the image's file system to an archive, and `demo/apache.sh` unpacks it
on a target and runs Apache from it in a chroot, with `/usr/sbin/apache2`
a hard link to its binary. `Documentation/start/guides/system-hardening.rst`
walks through it.

## Limits

- A path that does not exist at the load is not labeled, and a file
  that replaces a labeled one, as a package upgrade does, is a new file
  without the label, whether a path or a pattern named it. Load the upatch again after the application is
  installed or upgraded.
- The file rules name files, not their contents: a descriptor that was
  open before the task entered the sandbox, or that another process
  passes to it, keeps its open mode.
- The IP network and port rules cover `connect()` and the address of
  `sendmsg()` and `sendto()` on IPv4 and IPv6 sockets; `families` covers
  `socket()`, and `deny.unix` covers `unix_stream_connect` and
  `unix_may_send`. What a task receives or accepts on an already bound
  listening socket passes.
- Root outside a sandbox can remove nothing of it, as only shirudo's
  runtime sets the label, but a task that root starts from an unlabeled
  file is in no sandbox.

## Kernels and cost

The programs keep no state of their own: they read the task's policy
bits and the rules, which never change after the load, so they are
right on every preemption model.

A task in no sandbox pays at most one task-storage lookup at an active
hook, and none on read-only `file_open`, `ptrace_access_check`, UNIX
socket hooks or non-raw `socket()` unless a loaded sandbox enables the
corresponding gate in `sandbox_policy`.
