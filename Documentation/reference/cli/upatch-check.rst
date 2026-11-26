..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors, Operators

shirudo upatch check
====================

Verify shield telemetry from observe mode or a ``UPATCH_PROG_ROLE_TEST_RUN``
program before switching a shield to enforcement.

Runs on: any host for snapshot files; target as root with the runtime binary
when ``--test-input`` executes a pinned ``test`` program. Requires: read
access to the snapshot or input files, and runtime authority for
``--test-input``. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo upatch check [<name>] --before <snapshot.json>
                        --after-exploit <snapshot.json>
                        --after-benign <snapshot.json> [--json]
   shirudo upatch check <name> --test-input <file> --benign-input <file>
                        [--counters-map <map>] [--stack-map <map>] [--json]

Description
-----------

``check`` evaluates whether a shield built with :src:`bpf/lib/shield.h`
detected an exploit reproducer without false positives on a benign workload
or skipped runs:

- ``exploit_hits_delta > 0`` between ``before`` and ``after-exploit``
- ``benign_hits_delta == 0`` between ``after-exploit`` and ``after-benign``
- ``missed_runs_delta == 0`` across the run
- monotonic counter values without regression

It also reports the sorted, deduplicated caller stack IDs captured during
the exploit phase so operators can narrow enforcement by call stack.

With ``--test-input <file>``, ``check`` opens the loaded upatch's pinned
``test`` program (``SEC("syscall")`` ``shirudo_test__<id>``), reads its
pinned ``struct shield_counters`` map and missed-run counters before and
after ``BPF_PROG_TEST_RUN`` on ``<file>`` and on the
``--benign-input`` file, and evaluates the resulting snapshots.

A benign phase is required in both forms: a shield that was never shown
a benign workload has not been shown to leave one alone, and ``check``
does not pass it.

``check`` runs no exploit and no workload itself. The snapshots are
what the caller recorded around its own runs, and ``--test-input``
runs the upatch's ``test`` program on a fixed input, not the hook the
shield is attached to.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 20 18 40

   * - Option
     - Argument
     - Default
     - Description
   * - ``--before``
     - ``<snapshot.json>``
     - none
     - Baseline telemetry snapshot before the exploit reproducer.
   * - ``--after-exploit``
     - ``<snapshot.json>``
     - none
     - Telemetry snapshot after the exploit reproducer.
   * - ``--after-benign``
     - ``<snapshot.json>``
     - none
     - Telemetry snapshot after the benign workload.
   * - ``--test-input``
     - ``<file>``
     - none
     - Input passed to ``BPF_PROG_TEST_RUN`` of the loaded upatch's
       ``test`` program for the exploit run.
   * - ``--benign-input``
     - ``<file>``
     - none
     - Input passed to ``BPF_PROG_TEST_RUN`` for the benign run.
       Required with ``--test-input``.
   * - ``--counters-map``
     - ``<map>``
     - ``shield_counters``
     - Name of the pinned ``struct shield_counters`` map for
       ``--test-input``.
   * - ``--stack-map``
     - ``<map>``
     - none
     - Optional pinned hash map of captured ``__u32`` stack IDs.
   * - ``--json``
     - none
     - off
     - Print one JSON verdict object with ``schema``, ``upatch``,
       ``verdict`` (``pass`` or ``fail``), ``ok``, ``checks``, ``deltas``,
       ``stack_ids`` and ``test_run``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Every check passed (``verdict: pass``).
   * - 1
     - A check failed (``verdict: fail``), or a snapshot, pin or
       ``BPF_PROG_TEST_RUN`` call failed.
   * - 2
     - A usage error: missing required inputs, a missing benign snapshot
       or input, ``--test-input`` combined with snapshot files,
       ``--benign-input`` without ``--test-input``, or
       an invalid upatch name.

Examples
--------

Evaluate snapshots captured around an exploit reproducer and a benign
workload:

.. code-block:: console

   operator$ shirudo upatch check cve-shield --before before.json --after-exploit exploit.json --after-benign benign.json
   Upatch:                cve-shield
   Verdict:               PASS
   Checks:
     Exploit detected:    ok (hits_delta=3, activity_delta=5, observed_delta=3, enforced_delta=0)
     Benign clean:        ok (hits_delta=0, activity_delta=145)
     No missed runs:      ok (missed_runs_delta=0)
     Counters monotonic:  ok
   Captured stack IDs:    41, 204

Related
-------

- :doc:`build`
- :doc:`upatch-info`
- :doc:`upatch-map`
