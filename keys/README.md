# Signing keys

`make keys` (build/keygen.sh) creates local Secure Boot signing keys here:

- `beast-boot-ca.key` — the private key of your local CA (PEM). **Never commit or
  share it.** Git ignores it. Only `build/keygen.sh leaf` reads it.
- `beast-boot.crt`, `beast-boot.cer` — the CA certificate (PEM and DER). The build
  copies the `.cer` to the drive as `ENROLL_THIS_KEY_IN_MOKMANAGER.cer`: it is the one
  certificate a computer enrolls.
- `beast-boot-grub.key/.crt`, `beast-boot-kernel.key/.crt`,
  `beast-boot-wimboot.key/.crt` — one signing key and certificate per signed file
  (GRUB, the helper's kernel, wimboot), issued by the CA. The build signs with these.

Anyone who holds a private key here can sign code that machines with this CA
certificate enrolled will trust. For release builds the CA key stays offline and only
the three signing keys are given to the signing job. See docs/SECURE_BOOT.md and
docs/RELEASING.md section 3.
