# tpmtotp - attest computer boot state to phone via TOTP

This is a small collection of tools for allowing "remote attestation" between
a computer and a phone via TOTP.

## sealtotp

Generates a TOTP token, seals it against the TPM using the state of PCRs 0-5
and 7, saves it to the file given as the first argument and prints an ANSI QR
code

## unsealtotp

Takes the file given as the first argument, unseals it with the TPM and
prints a TOTP value.

## usage

sealtotp and unsealtotp both use libtpm to talk to the TPM directly, and so
will not run if a TPM service daemon such as Trousers is running. In
addition, they need access to /dev/tpm0 and so will normally need to be run
as root. To use, do the following:

./sealtotp totpblob

and enrol the QR code in an app like Google Authenticator. Copy totpblob and
unsealtotp (and its dependencies) into your initrd and run

./unsealtotp totpblob

in your boot process before requesting the disk decryption
passphrase. Verify that the value matches the value on your phone before
typing any passphrase.

## requirements

sealtotp requires libqrencode. unsealtotp requires liboath.

## limitations

The TPM policy measurement does not currently include the initrd or kernel
that you are booting, since grub lacks support for performing the initial
measurement of these objects. This results in the following vulnerability:

1) Shim will be measured into PCR[4]

2) Shim will verify that the next stage loader is signed with a trusted key

3) The next stage loader will verify that the kernel is signed with a
trusted key

4) The initrd will be loaded without any verification, and so will be able
to unseal the TOTP value while still providing a malicious codebase

Avoiding this requires either signature validation of the initrd
(problematic, as these are typically generated on the local system) or for
the second stage loader (typically grub) to gain support for measuring its
payloads into the TPM.

An attacker who is able to perform DMA-based attacks may be able to boot the
system, attach a DMA-capable device and extract the valid TOTP secret from
RAM. This will allow them to spoof legitimate boots later on. This can be
avoided by ensuring that your kernel and hardware support and enable an
IOMMU, or by adding support to the kernel to allow enumeration of
DMA-capable external devices to be deferred until later.

Sufficiently malicious firmware may still be able to extract the TOTP secret
from system RAM and exfiltrate it such that an attacker can later spoof
legitimate boots on a compromised system. Of course, any such sufficiently
malicious firmware is also capable of modifying your OS at runtime, so
you've already lost.

## TODO

Move sealtotp over to the tspi API in order to allow it to coexist with
Trousers.

Add support for migration of sealed data to new PCR values in order to
support bootloader updates.

Add TPM support to grub.

Get distributions to turn on iommus.

Modify the kernel to allow delayed enumeration of DMA-capable external
devices.