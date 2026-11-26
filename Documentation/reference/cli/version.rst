..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

shirudo version
===============

Print the release and the ``SHIRUDO_VERSION_ID`` that ``upatch load
--expect-version-id`` compares against.

Runs on: any host, with any copy of the binary, since the image gate does
not apply. Requires: nothing. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo version [--version-id]

Description
-----------

Without an option, ``version`` prints three lines::

   shirudo (<describe><extraversion>, "<release-name>")
   version-id: <version-id>
   fips: <enabled|disabled>

``<describe>`` is ``git describe`` of the build tree, or the :src:`VERSION`
file outside a git checkout. ``<version-id>`` is a SHA-256 over the git
commit, a dirty-tree flag, a digest of the build configuration
(``config.mk`` and :src:`Makefile.shirudo`) and the ``FIPS`` build flag.
Two builds of one commit with
different build configurations therefore have different ids, for
example an operator package and a target package built on different
hosts or a ``FIPS=1`` build. ``fips`` reports whether OpenSSL's FIPS
default property is active in this process.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 12 12 54

   * - Option
     - Argument
     - Default
     - Description
   * - ``--version-id``
     - none
     - off
     - Print only the version id, on one line.

Exit status
-----------

0, or 2 for a usage error: an unknown option, ``--version-id`` given
twice, or an argument.

Examples
--------

Print the release and the id:

.. code-block:: console

   target# shirudo version
   shirudo (58d3fa7-dirty-rc0, "Social BPF Coding")
   version-id: 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0
   fips: disabled

Print the id alone, to pass to ``--expect-version-id``:

.. code-block:: console

   target# shirudo version --version-id
   58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

Related
-------

- :doc:`upatch-load`
- :doc:`/operate/maintain/upgrade`
