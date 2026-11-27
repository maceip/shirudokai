..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch events
=====================

Consume queued records from the pinned ``BPF_MAP_TYPE_RINGBUF`` maps of a
loaded upatch in a single bounded pass.

Runs on: target, as root with the runtime binary. Requires: a loaded
upatch with at least one pinned ``ringbuf`` map. Changes measured state:
no. It does change the buffer: a record it reads is gone from it.

Usage
-----

.. code-block:: none

   shirudo upatch events <upatch> [<map>] [--max-records=<n>]
                         [--timeout-ms=<ms>] [--json]

Options with a value take it after ``=`` or as the next argument.

Description
-----------

``events`` opens the pinned ``ringbuf`` map ``<map>`` under
``/run/shirudo/bpffs/upatches/<upatch>/maps/``, or every pinned
``ringbuf`` map of ``<upatch>`` in name order when ``<map>`` is omitted,
and drains up to ``--max-records`` samples in one pass:

- No daemon or unbounded loop runs: by default ``--timeout-ms`` is ``0``,
  so ``events`` consumes only what is already queued and exits
  immediately. When ``--timeout-ms`` is positive and the buffer is empty,
  ``events`` waits at most once up to that deadline before draining up to
  ``--max-records`` records.
- Consuming advances the kernel ring buffer consumer position for the
  records read; records beyond ``--max-records`` remain queued in the
  kernel ring buffer for a later invocation, and the output notes
  ``truncated``.
- A record is delivered once, to whichever invocation reads it.
  ``events`` takes an exclusive ``flock`` on the upatch's ``maps`` pin
  directory for the duration of the read, so two invocations on one
  upatch at the same time serialize rather than racing on the consumer
  position.
- When the map's BTF resolves a value type (either ``btf_value_type_id``
  on the map or ``__type(value, ...)`` on its ``SEC(".maps")`` variable),
  each sample at least as large as that type is decoded field by field.
  Untyped maps and shorter variable-length samples are printed as hex
  bytes.
- ``--json`` prints one JSON object
  ``{"schema":1,"upatch":"...","n_records":...,"truncated":...,"records":[...]}``
  whose ``records`` array carries ``upatch``, ``map``, ``size`` and
  either ``btf_type`` plus decoded ``value`` or ``data_hex``.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 22 12 44

   * - Option
     - Argument
     - Default
     - Description
   * - ``--max-records``
     - ``<n>``, 1 to 65536
     - 256
     - Maximum number of records to consume in this invocation.
   * - ``--timeout-ms``
     - ``<ms>``, 0 to 30000
     - 0
     - Maximum milliseconds to wait once when no records are queued.
   * - ``--json``
     - none
     - off
     - Print one JSON object containing the consumed records.

Each option may appear once.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Available records up to the bound were consumed (including ``0``
       records when the ring buffer is empty).
   * - 1
     - The upatch or map pin does not exist, ``<map>`` is not a
       ``ringbuf`` map, ``<upatch>`` has no pinned ``ringbuf`` maps, or
       reading/writing failed.
   * - 2
     - A usage error: missing or invalid ``<upatch>`` or ``<map>``, an
       unknown or repeated option, or an out-of-range ``--max-records``
       or ``--timeout-ms`` value.

Files and environment
---------------------

- Reads and advances the consumer position of pinned ``ringbuf`` maps
  under ``/run/shirudo/bpffs/upatches/<upatch>/maps/``

Examples
--------

Drain available records from every ring buffer map of ``guard-demo``:

.. code-block:: console

   target# shirudo upatch events guard-demo
   Events (1):
     events (24 B): { pid=4242, err=-13, action=ACT_DENY, comm=[ 115, 115, 104, 100, 0, 0, 0, 0 ], ports=[ 22, 443 ] }

Consume at most 64 records from one named ring buffer map as JSON:

.. code-block:: console

   target# shirudo upatch events guard-demo events --max-records=64 --json

Related
-------

- :doc:`upatch-map`
- :doc:`upatch-get`
- :doc:`/operate/run/telemetry`
