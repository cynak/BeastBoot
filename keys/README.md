# Signing keys

`make keys` (build/keygen.sh) creates a local Secure Boot signing key here:

- `beast-boot.key` — private key (PEM). **Never commit or share it.** Git ignores it.
- `beast-boot.crt` — certificate (PEM), used by `sbsign`.
- `beast-boot.cer` — the same certificate in DER form. The build copies it to
  the drive as `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`.

Anyone who holds the private key can sign code that machines with this key
enrolled will trust. Keep it offline for release builds. See docs/SECURE_BOOT.md.
