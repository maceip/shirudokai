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

   shirudo attest ek-name --ek-pub=<path> [--json]

Every option takes its value after ``=`` or as the next argument.

Description
-----------

Two cloud control planes publish an instance's endorsement public key
out of band, without an endorsement certificate: GCP as PEM
``SubjectPublicKeyInfo`` and AWS as base64 of a DER
``SubjectPublicKeyInfo``:

.. code-block:: console

   operator$ aws ec2 get-instance-tpm-ek-pub --key-type rsa-2048 --key-format der --query KeyValue --output text > instance-ek.b64
   operator$ gcloud compute instances get-shielded-identity <instance> --format='value(encryptionKey.ekPub)' > instance-ek.pem

``ek-name``, ``attest challenge --ek-pub`` and ``attest verify
--ek-pub`` accept the raw base64 DER ``KeyValue`` output directly. AWS
``--key-format tpmt`` and ``--key-type ecc-sec-p384`` are not supported.
On AWS NitroTPM, the target presents its RSA key with ``shirudo attest
--ek-rsa``.

Azure publishes none. A Trusted Launch VM's vTPM holds no endorsement
certificate, and neither the instance view nor the instance metadata
service returns the key; they say only that the vTPM is enabled. An
operator can read the key on the VM when provisioning it
(``tpm2_readpublic -c 0x81010001 -f pem``) and keep it in an inventory.
That pins the key as ``--ek-name`` does: it proves that the same TPM
answers later, not that Azure vouches for it.

``ek-name`` parses RSA-2048 (exponent 65537) and ECC NIST P-256 keys in
any of those formats, builds the canonical TCG low-range endorsement key
``TPMT_PUBLIC`` (L-1 for RSA, L-2 for ECC, under PolicyA) when the
input is ``SubjectPublicKeyInfo`` (or uses the marshalled
``TPMT_PUBLIC`` of a ``TPM2B_PUBLIC`` input), and prints
``0x000b || SHA-256(TPMT_PUBLIC)`` as 68 lowercase hexadecimal
characters.

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
   * - ``--json``
     - none
     - Print one JSON object with ``schema`` (1), ``type`` (``rsa`` or
       ``ecc``), ``template`` (``l1`` or ``l2`` for PolicyA, ``h1`` or
       ``h2`` for PolicyB) and ``ek_name``.

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
     - A usage error: ``--ek-pub`` missing, unreadable, malformed, or not
       an approved RSA-2048 or NIST P-256 endorsement key.

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
