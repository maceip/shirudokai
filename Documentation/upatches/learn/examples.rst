..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Example packages
================

The tree ships packages under :src:`upatches/`: ``kernel-obs``, a
complete observability package with arena tables, serializers, decoders
and generated ``.rodata``, in ``kernel-cve`` three small CVE
detectors exported from a mitigation campaign and one CVE mitigation,
each a package of its own, and ``app-sandbox``, which enforces with
policy labels and generated ``.rodata``.

kernel-obs
----------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Item
     - Content
   * - Package
     - ``kernel-obs``, from :src:`upatches/kernel-obs/Beefile`
   * - upatch
     - ``kernel-obs``, built from ``kernel-obs.bpf.c``, which includes
       ``obs_exec.bpf.c``, ``obs_net.bpf.c``, ``obs_dns.bpf.c``,
       ``obs_priv.bpf.c`` and ``obs_file.bpf.c``
   * - Attach kinds
     - ``lsm`` and ``lsm.s`` hooks for processes, files, sockets,
       credentials, mounts, modules and ``bpf()``; ``cgroup_skb/ingress``
       and ``cgroup_skb/egress`` for packets and DNS
   * - Tables
     - ``exec``, ``net``, ``socket``, ``listen``, ``watch``, ``dns``,
       ``priv`` and ``file``: one ``obs_table.h`` instance each, all in the
       arena ``obs_i_arena``, each with a serializer and a log decoder
   * - Counters
     - ``watch_stat``, a per-CPU array with a metric decoder
   * - Test-run program
     - ``shirudo_test__kernel_obs`` allocates every table in the arena at
       load
   * - Generated ``.rodata``
     - ``obs_watch_v4`` and ``obs_watch_v6``, generated from
       ``watch.list`` by ``gen_watch_rodata.py``
   * - Enforces
     - nothing, every hook observes

``kernel-obs`` is the reference for the conventions in
:doc:`/upatches/write/maps-arenas-serializers` and
:doc:`/upatches/write/decoders`: the double-buffered
tables, the one-entry maps that name the tables, the arena association,
the page header and the timestamp conversion in the decoders.

Its ``README.md`` is what ``shirudo bpm info`` prints for the package.
It follows here as it ships. Where it tells a target to add a key with
``bpm key add``, note that a production target takes its keys and
repositories from its signed config image and refuses local key changes.
:doc:`/operate/run/deliver-packages` describes that setup.

.. include:: ../../../upatches/kernel-obs/README.md
   :parser: myst_parser.sphinx_

kernel-cve
----------

:src:`upatches/kernel-cve/` holds four detectors in
``sources/<slug>/observability/``, two mitigations in
``sources/<slug>/mitigation/``, ``manifest.json``, and one Beefile per
shield, ``<shield>.bee``. Each source compiles with CO-RE against the
target's ``vmlinux.h`` and maps ``__x86_64__``, ``__aarch64__`` and
``__riscv`` to the ``__TARGET_ARCH_*`` macro ``bpf_tracing.h`` reads.

Each Beefile builds a package named after its shield with one upatch
and one ``[upatches.tree]`` entry of the same name. The entry's
``fixes`` names the CVE, and its selector names the Kconfig option of
the driver, qdisc, protocol or subsystem the shield guards. They are
the shields :src:`tools/put-shields` publishes, as
:doc:`/upatches/publish/publishing` shows.

.. list-table::
   :header-rows: 1
   :widths: 34 26 40

   * - Source
     - Hook
     - ``hits`` counts calls where
   * - ``cve-2025-71093-e1000-tbi-detector.bpf.c``
     - ``kprobe/e1000_tbi_should_accept``
     - the frame length is 0
   * - ``cve-2026-31431-copyfail-detector.bpf.c``
     - ``lsm/socket_sendmsg``, ``fexit/aead_recvmsg``
     - an ``AF_ALG`` socket fed by ``MSG_SPLICE_PAGES`` fails in
       ``aead_recvmsg``
   * - ``cve-2026-31675-netem-detector.bpf.c``
     - ``kprobe/netem_enqueue``
     - the packet's linear head is empty
   * - ``cve-2026-63984-rpl-detector.bpf.c``
     - ``kprobe/ipv6_rpl_srh_decompress``
     - ``n + 1`` exceeds 127, the bound the fix introduces

Each detector counts every call in a per-CPU ``activity`` counter and the
calls that match its predicate in ``hits`` with atomic increments safe
under preemptible RCU. None of them refuses anything. The ``kprobe``
detectors need a target with ``CONFIG_KPROBES`` and
``CONFIG_KPROBE_EVENTS``. ``manifest.json`` marks the campaign
predicates as ``source_derived_unvalidated``: derived from the fix, not
checked against an exploit.

:doc:`/upatches/learn/kernel-fix-tutorial` takes the RPL detector from its fix
to a package, as an ``fentry`` program.

The directory also holds two mitigations for CVE-2026-31431:
``cve-2026-31431-af-alg-block.bee`` builds
``sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/cve-2026-31431-af-alg-block.bpf.c``
to refuse every ``AF_ALG`` socket at ``lsm/socket_create`` with
``EPERM``, while ``cve-2026-31431-alg-splice-block.bee`` builds
``sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/cve-2026-31431-alg-splice-block.bpf.c``
to refuse only ``MSG_SPLICE_PAGES`` sends on ``AF_ALG`` sockets at
``lsm/socket_sendmsg`` with ``EACCES``. Both select
``CONFIG_CRYPTO_USER_API_AEAD`` alone and load on every architecture.
:src:`tools/put-shields` publishes them with the detectors. Beside the
sources, ``reproducer/cve-2026-31431-repro.py`` splices a file's page
cache through a pipe into an ``AF_ALG`` aead socket and reports whether
the bug corrupted it; ``t3115-af-alg-block`` drives it to check the
socket mitigation.

app-sandbox
-----------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Item
     - Content
   * - Package
     - ``app-sandbox``, from :src:`upatches/app-sandbox/Beefile`
   * - upatch
     - ``app-sandbox``, built from ``app-sandbox.bpf.c``: fifteen ``lsm``
       programs and no state of its own
   * - Policy labels
     - one ``[[upatches.policy]]`` table per sandbox, ``apache``,
       ``php-fpm`` and ``llm-agent``, each a bit and the executables
       that put a task in the sandbox, those of PHP-FPM by the pattern
       ``/usr/sbin/php-fpm*``
   * - Generated data
     - ``sandbox_policy``, which ``gen_policy.py`` writes from
       ``sandbox.toml`` and the policy bits of the Beefile
   * - Tree entry
     - ``app-sandbox``, without a selector, with ``fixes`` naming the
       PHP2Shell advisories, CVE-2026-109618 and CVE-2026-109619, which
       its two sandboxes contain rather than close

A task that executed a file of a sandbox carries its policy bit in
``shirudo_task_policy``, and so do its children. The programs read that
bit and the rules of ``sandbox_policy``, and refuse with ``EACCES``:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Hook
     - Refuses, for a task in a sandbox
   * - ``lsm.s/bprm_check_security``
     - executing a file that carries neither the sandbox's bit nor one
       its ``exec`` rule names
   * - ``lsm/socket_connect``, ``lsm/socket_sendmsg``
     - an IPv4 or IPv6 peer outside its ``network`` and ``ports`` rules
       or matching ``deny.network`` or ``deny.ports``
   * - ``lsm/socket_create``
     - a socket family outside ``families``, or a raw or packet socket
       when network or port rules apply
   * - ``lsm/unix_stream_connect``, ``lsm/unix_may_send``
     - a UNIX peer matching a ``deny.unix`` path or name pattern
   * - ``lsm/ptrace_access_check``
     - ``ptrace`` when ``deny_ptrace = true``
   * - ``lsm/inode_create``, ``lsm/inode_mkdir``, ``lsm/inode_mknod``,
       ``lsm/inode_symlink``, ``lsm/inode_link``
     - a new name that matches a ``deny.create`` pattern
   * - ``lsm/inode_rename``
     - a rename from or to a name that matches a ``deny.rename`` pattern
   * - ``lsm/file_open``, ``lsm/inode_setattr``
     - opening for writing or truncating a name matching ``deny.write``,
       or opening for reading a name matching ``deny.read``

``gen_policy.py`` joins the two halves of a sandbox by its name: it
reads the bit from the Beefile and the rules from ``sandbox.toml``, and
fails the build for rules without a policy table. The package's
``README.md`` describes the rule keys and what the sandboxes do not
cover. ``t9114-app-sandbox`` takes the package from its sources to a
node and back (:ref:`testing-sandbox`), and :src:`tools/put-shields`
publishes it with the shields of ``kernel-cve``.

Related
-------

- :doc:`/upatches/learn/kernel-fix-tutorial` to write a detector of your own
- :doc:`/reference/formats/beefile` for the keys both Beefiles use
