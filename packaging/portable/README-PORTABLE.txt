%%# Template for README.txt in every portable package; packaging/portable/build.py
%%# renders it. "%% if <os> ..." / "%% end" keep a block only for those OSes
%%# (linux, windows, macos); @NAME@ values are filled in; "%%#" lines are dropped.
BeastBoot @VERSION@ - portable package for @TARGET_NAME@
@TEST_WARNING@
BeastBoot makes a multi-boot USB drive: copy ISO files onto it and pick one
from a boot menu (BIOS and UEFI; Secure Boot stays on). This folder is the
whole program: nothing is installed, nothing is downloaded while it runs, and
deleting the folder removes it.

START
%% if linux
  GUI   double-click "BeastBooter" (or run ./BeastBooter in a terminal).
        beast-boot.desktop does the same from a file manager; on GNOME
        right-click it > "Allow Launching" first. It only works inside this
        folder (copy it elsewhere and edit Exec= to an absolute path).
  CLI   ./beast-boot --help
        sudo ./beast-boot install --device /dev/sdX
        ./beast-boot install --image my.img --size 8G      (no root needed)

  Admin rights: the window runs as you. Only writing a USB drive needs root,
  so for that one step the GUI asks for your password (polkit/pkexec, or the
  sudo prompt). The CLI needs sudo for --device, not for --image.
%% end
%% if windows
  GUI   double-click "BeastBooter.cmd". A console window flashes up and closes;
        the BeastBooter window stays.
  CLI   open a terminal in this folder:
          beast-boot.cmd --help
          beast-boot.cmd install --device \\.\PhysicalDrive2
          beast-boot.cmd install --image my.img --size 8G   (no admin needed)

  Admin rights: the window runs as you. Only writing a USB drive needs
  administrator rights, so for that one step Windows shows a UAC prompt
  ("Do you want to allow this app to make changes"; the program shown is
  the bundled runtime\pythonw.exe, publisher unknown because it is not
  signed). For the CLI, writing a --device needs a terminal started with
  "Run as administrator".

  SmartScreen: this package is not code signed. If Windows shows "Windows
  protected your PC", check the download first (below), then click
  "More info" > "Run anyway". Easier: before unpacking, right-click the .zip >
  Properties > tick "Unblock" > OK, then unpack it (PowerShell:
  Unblock-File .\@ARCHIVE@).
%% end
%% if macos
  GUI   double-click "BeastBooter" (BeastBooter.app). The first time, see
        "Gatekeeper" below.
  CLI   ./beast-boot.command --help            (double-click shows the help)
        sudo ./beast-boot.command install --device /dev/disk4
        ./beast-boot.command install --image my.img --size 8G
                                              (image files: no admin needed)

  Admin rights: the window runs as you. Only writing a USB drive needs
  administrator rights, so for that one step macOS asks for an administrator
  password. The CLI needs sudo for --device, not for --image.

  Gatekeeper: this app is not signed or notarized by Apple, so macOS refuses
  the first double-click ("cannot be opened because Apple cannot check it" or
  "Apple could not verify..."). Check the download first (below), then:
    macOS 14 and older: right-click (Control-click) BeastBooter > Open > Open.
    macOS 15 and newer: try to open it once, then System Settings > Privacy &
                        Security > "Open Anyway" (and confirm).
    Or in Terminal, for the whole folder:
      xattr -dr com.apple.quarantine "/path/to/@TOP@"
  Writing NTFS is not possible on macOS: choose exFAT (default) or FAT32.
%% end


CHECK THE DOWNLOAD FIRST
  1. Compare the archive's SHA-256 with the published SHA256SUMS file:
%% if linux
       sha256sum -c --ignore-missing SHA256SUMS
%% end
%% if macos
       shasum -a 256 @ARCHIVE@
       (compare with its line in SHA256SUMS)
%% end
%% if windows
       PowerShell:
         Get-FileHash .\@ARCHIVE@ -Algorithm SHA256
       (compare with its line in SHA256SUMS)
%% end
  2. Check every unpacked file against PACKAGE-MANIFEST.json with any Python 3:
%% if windows
       python verify-package.py
     No Python? Use the bundled one, but only after step 1:
       runtime\python.exe -I -S -B verify-package.py
%% end
%% if linux
       python3 verify-package.py
     Or use the bundled Python, but only after step 1:
       runtime/bin/python3 -I -S -B verify-package.py
%% end
%% if macos
       python3 verify-package.py
     Or use the bundled Python, but only after step 1:
       BeastBooter.app/Contents/Resources/runtime/bin/python3 -I -S -B verify-package.py
%% end
     It recomputes the SHA-256 of every file, checks the boot files against
     payload/dist/manifest.json, and reports anything missing or added.
     Always give the bundled Python -B: without it, Python writes .pyc files
     into the package, and the check then fails (rightly: Python would run
     those instead of the .py files). If that happened, unpack it again.


WHAT IS INSIDE
%% if macos
  BeastBooter.app/Contents/
    Info.plist              app description (bundle id, version, minimum macOS)
    MacOS/BeastBooter       sh script that starts the GUI
    Resources/runtime/      Python @PYTHON@ (see below), unmodified
    Resources/app/          the BeastBoot program: plain .py source files
    Resources/payload/dist/ the boot files written to the USB drive, with
                            manifest.json (origin + SHA-256 of each)
    Resources/payload/sbom/ software bill of materials (if built with one)
    Resources/docs/         SECURE_BOOT.md and PORTABLE.md
    Resources/VERSION       version number
  beast-boot.command      sh script for the command line
%% end
%% if linux
  BeastBooter, beast-boot sh scripts: GUI and command line
  beast-boot.desktop      starts the GUI from a file manager
  runtime/                  Python @PYTHON@ (see below), unmodified
  app/                      the BeastBoot program: plain .py source files
  payload/dist/             the boot files written to the USB drive, with
                            manifest.json (origin + SHA-256 of each)
  payload/sbom/             software bill of materials (if built with one)
  docs/                     SECURE_BOOT.md and PORTABLE.md
  VERSION                   version number
%% end
%% if windows
  BeastBooter.cmd           starts the GUI (runtime\pythonw.exe, no console)
  beast-boot.cmd          command line (runtime\python.exe)
  runtime\                  Python @PYTHON@ (see below), unmodified
  app\                      the BeastBoot program: plain .py source files
  payload\dist\             the boot files written to the USB drive, with
                            manifest.json (origin + SHA-256 of each)
  payload\sbom\             software bill of materials (if built with one)
  docs\                     SECURE_BOOT.md and PORTABLE.md
  VERSION                   version number
%% end
  PACKAGE-MANIFEST.json     SHA-256 and origin of every file in this package
  verify-package.py         checks the files against PACKAGE-MANIFEST.json
  LICENSE                   GNU GPL v3 (BeastBoot)
  README.txt                this file

  The launchers only run the bundled runtime on app/beast_booter_launch.py
  (with -s -E -B -S: no user site-packages, no PYTHON* variables, no .pyc
  files, no site-packages or .pth files) and point it at the bundled boot
  files (BEAST_BOOTER_DIST). You can read every one of them.

  The runtime is the official python-build-standalone build
    @RUNTIME_ASSET@
    SHA-256 @RUNTIME_SHA256@
  (release @PBS_RELEASE@, https://github.com/astral-sh/python-build-standalone),
  copied without changes, except that its bytecode caches (__pycache__/*.pyc)
  are left out; PACKAGE-MANIFEST.json lists them. The package holds no
  bytecode at all: Python runs the .py files. The runtime's licences are in
  the runtime folder.


MORE
%% if macos
  Documentation: BeastBooter.app/Contents/Resources/docs/PORTABLE.md (this
  package) and SECURE_BOOT.md (Secure Boot and the BeastBoot key), and
  docs/ARCHITECTURE.md in the source tree.
%% end
%% if linux windows
  Documentation: docs/PORTABLE.md (this package) and docs/SECURE_BOOT.md
  (Secure Boot and the BeastBoot key) in this folder, and
  docs/ARCHITECTURE.md in the source tree.
%% end
  BeastBoot is free software under the GNU GPL, version 3 or later.
