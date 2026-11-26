..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo attest ek-name
======================

Compute the 34-byte SHA-256 TPM object name of a cloud-published
endorsement public key offline.

Runs on: operator host, offline. It uses no TPM. Requires: a cloud
endorsement public key file. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo attest ek-name --ek-pub=<path> [--template=l1|l2] [--json]

Every option takes its value after ``=`` or as the next argument.

Description
-----------

Cloud vTPM control planes publish each instance's endorsement public key
out of band without an endorsement certificate: PEM or DER
``SubjectPublicKeyInfo`` (GCP Shielded VM ``getShieldedInstanceIdentity``,
Azure Trusted Launch) or raw or base64 ``TPM2B_PUBLIC`` (AWS NitroTPM
``GetInstanceTpmEkPub``, Azure Trusted Launch).

``ek-name`` parses RSA-2048 (exponent 65537) and ECC NIST P-256 keys in
any of those formats, builds the canonical TCG endorsement key
``TPMT_PUBLIC`` when the input is ``SubjectPublicKeyInfo`` (or uses the
marshalled ``TPMT_PUBLIC`` of a ``TPM2B_PUBLIC`` input unless
``--template`` overrides it), and prints ``0x000b || SHA-256(TPMT_PUBLIC)``
as 68 lowercase hexadecimal characters.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 24 26 50

   * - Option
     - Argument
     - Description
   * - ``--ek-pub``
     - ``<path>``
     - Required. Cloud endorsement public key in PEM SPKI, DER SPKI, or
       raw or base64 ``TPM2B_PUBLIC`` format.
   * - ``--template``
     - ``l1`` or ``l2``
     - TCG endorsement policy template: ``l1`` selects the standard
       low-range policy
       (``837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa``),
       ``l2`` the high-range SHA-256 policy, PolicyB
       (``ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0``).
       Defaults to ``l1`` for SPKI inputs and to the embedded policy for
       ``TPM2B_PUBLIC`` inputs.
   * - ``--json``
     - none
     - Print one JSON object with ``schema`` (1), ``type`` (``rsa`` or
       ``ecc``), ``template`` (``l1`` or ``l2``) and ``ek_name``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The endorsement key name was printed.
   * - 1
     - Computing or encoding the name failed.
   * - 2
     - A usage error: ``--ek-pub`` missing, unreadable, malformed, not an
       approved RSA-2048 or NIST P-256 endorsement key, or an invalid
       ``--template`` value.

Examples
--------

Compute the endorsement key name of a cloud instance's PEM public key:

.. code-block:: console

   operator$ shirudo attest ek-name --ek-pub=instance-ek.pem

Related
-------

- :doc:`attest`
- :doc:`attest-challenge`
- :doc:`attest-verify`
- :doc:`/operate/run/attest`
