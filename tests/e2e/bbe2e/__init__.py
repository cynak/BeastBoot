"""beast-booter end-to-end test harness.

Modules:
  env      paths, tool discovery, KVM detection, timeouts
  serial   BEAST: record parser and a small VT100 screen emulator
  qemu     QEMU launcher (BIOS / UEFI / UEFI + Secure Boot) with serial capture
  images   drive images: installer wrapper, partition parsing, data-partition writers
  stubs    stand-in boot images used by the harness self-test
"""
