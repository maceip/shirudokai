..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo attest challenge
========================

Make a credential challenge that only the TPM holding both the target's
endorsement key and its attestation key can answer.

Runs on: operator host, offline. It computes the credential in software
and uses no TPM. Requires: an evidence document from the target. Changes
measured state: no.

Usage
-----

.. code-block:: none

   shirudo attest challenge --evidence=<evidence> (-o <challenge> | --output=<challenge>)
                            (--ek-ca=<bundle> | --ek-pub=<path> | --ek-name=<name> |
                             --trust-presented-ek)
                            [--ak-name=<name>]

Every option takes its value after ``=`` or as the next argument, and
``-o`` is ``--output``.

Description
-----------

Enrollment pins the target's attestation key. ``challenge`` binds that key
to the target's endorsement key:

#. It reads the attestation and endorsement keys from the evidence. With
   ``--ak-name`` the attestation key must be that one, and with
   ``--ek-name`` the endorsement key.
#. It checks that the endorsement key's name matches its public area and
   that the key has the TCG default template under the endorsement
   policy.
#. It decides whether to trust the endorsement key:

   - With ``--ek-ca``, the endorsement certificate in the evidence must
     describe the key and chain to an issuer in the PEM bundle.
   - With ``--ek-pub``, the endorsement key in the evidence must use an
     approved TCG endorsement template and carry the exact RSA-2048
     modulus or NIST P-256 coordinates of the cloud-published key.
   - With ``--ek-name``, the pinned name vouches for the key.
   - With ``--trust-presented-ek``, the key is accepted as presented.

   Without any of the four, the check fails.
#. It makes a random 32-byte credential, protects it for the endorsement
   key and the attestation key name, writes the challenge to ``--output``
   with mode 0600 and prints ``challenge: <path>`` and
   ``credential: <hex>``.

Give the challenge to ``shirudo attest --challenge=<challenge>`` on the
target. Its evidence then carries the recovered credential, and
``attest verify --expect-credential=<hex> --ak-name=<name>`` checks it.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 24 26 50

   * - Option
     - Argument
     - Description
   * - ``--evidence``
     - ``<evidence>``, a file
     - Required. Evidence from the target.
   * - ``--output``, ``-o``
     - ``<challenge>``, a path
     - Required. Where to write the challenge.
   * - ``--ak-name``
     - ``<name>``, 68 hex characters
     - The attestation key the challenge is for.
   * - ``--ek-ca``
     - ``<bundle>``, PEM file
     - Issuers the endorsement certificate must chain to.
   * - ``--ek-pub``
     - ``<path>``
     - Cloud-published endorsement public key (PEM SPKI, DER SPKI, or raw
       or base64 ``TPM2B_PUBLIC``).
   * - ``--ek-name``
     - ``<name>``, 68 hex characters
     - An endorsement key name known out of band.
   * - ``--trust-presented-ek``
     - none
     - Accept an endorsement key that nothing vouches for.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The challenge was written.
   * - 1
     - A check failed (``verdict: fail``), or the challenge could not be
       written.
   * - 2
     - A usage error: ``--evidence`` or ``--output`` missing, an unknown
       option, an option given twice, a value missing, empty or invalid,
       or an argument. An unreadable evidence file, or evidence that
       carries no endorsement key.

Examples
--------

Make a challenge for a target whose TPM vendor roots you hold:

.. code-block:: console

   operator$ shirudo attest challenge --evidence=ev.json --ak-name=<ak-name> --ek-ca=<tpm-vendor-roots> --output=challenge.json

``<ak-name>`` is ``.ak.name`` of the evidence (:doc:`attest`) and
``<tpm-vendor-roots>`` a PEM bundle of the TPM manufacturers' issuing
certificates.

Related
-------

- :doc:`attest`
- :doc:`attest-verify`
- :doc:`attest-ek-name`
- :doc:`/operate/run/attest`
