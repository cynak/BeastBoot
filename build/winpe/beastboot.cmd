@echo off
rem BeastBoot Windows PE start-up script (build/winpe/beastboot.cmd).
rem
rem The boot menu boots the ISO's sources\boot.wim with wimboot and injects
rem these files into X:\Windows\System32:
rem   winpeshl.ini    runs this script instead of the image's default shell
rem   beastboot.cmd   this script
rem   beastmount.exe  attaches an ISO read-only (VirtDisk API; setup mode only)
rem   beastboot.txt   the drive's GRUB environment block (grub/grubenv on the
rem                   ESP) with three lines the menu wrote with save_env:
rem                     bb_winpe_iso=/path/to/the.iso   (on the data partition)
rem                     bb_winpe_mode=setup | pe
rem                     bb_winpe_uuid=XXXX-XXXX   (the data partition's volume
rem                       serial; the drive that has the ISO path must match it,
rem                       so another disk with the same path is not used)
rem
rem setup: find the data partition (the drive that has the ISO path), attach
rem        the ISO read-only (beastmount.exe: diskpart attaches only VHD/VHDX
rem        files, and Setup's Windows PE has no PowerShell or storage WMI
rem        provider), find its drive letter (the new drive with
rem        sources\install.wim/.esd/.swm), start Windows Setup from it and
rem        check that Setup runs from that drive.
rem pe:    start the image's normal shell (WinRE's recovery UI, or startnet.cmd).
rem
rem Tests: when a disk labelled BBTEST is attached, progress lines are appended
rem to \RESULT.TXT on it (tests/e2e/REAL_ISOS.md), in this order:
rem   winpe-ok
rem   iso-found <data letter>:\path\to.iso
rem   iso-mounted <L>: <L>:\sources\install.wim   (only after that file was found)
rem   setup-started <L>:\setup.exe
rem   setup-running   (only after a Setup process from <L>: was seen running)
rem   setup-process <its path>
rem or, at any point, "fail <reason>: <plain words>". With BBTEST the script
rem then powers the PC off (the end of a test case) instead of waiting.
rem On any failure the script says what failed and opens a command prompt;
rem closing it restarts the PC (as Windows PE always does).
rem
rem The script never writes to the data partition and never changes a disk.

setlocal EnableExtensions DisableDelayedExpansion
title BeastBoot
set "BB_SYS=%SystemDrive%\Windows\System32"
set "BB_ENV=%BB_SYS%\beastboot.txt"
set "BB_DRIVES=C D E F G H I J K L M N O P Q R S T U V W Y Z"
set "BB_LOG="
set "BB_ISO="
set "BB_MODE="
set "BB_DATA="
set "BB_UUID="
set "BB_SRC="
set "BB_INST="
set "BB_PROC="
echo.
echo BeastBoot: Windows PE started.

rem UTF-8, so non-ASCII ISO names in beastboot.txt read correctly (if chcp exists)
chcp 65001 >nul 2>&1

if exist "%BB_ENV%" (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%BB_ENV%") do (
    if /i "%%a"=="bb_winpe_iso" set "BB_ISO=%%b"
    if /i "%%a"=="bb_winpe_mode" set "BB_MODE=%%b"
    if /i "%%a"=="bb_winpe_uuid" set "BB_UUID=%%b"
  )
)
if not defined BB_MODE set "BB_MODE=pe"

call :find_bbtest
if /i "%BB_MODE%"=="setup" goto setup
if /i "%BB_MODE%"=="pe" goto pe
set "BB_MSG=unknown-mode: the boot menu asked for mode %BB_MODE%, which this script does not know (update the drive's boot files)"
call :log winpe-ok
goto fail

rem ---------------------------------------------------------------- pe mode
:pe
call :log winpe-ok
if defined BB_LOG goto test_end
rem WinRE's recovery UI first, if the image has it. It can also return at once
rem (the image is not a recovery environment), so a shell always follows:
rem when this script ends, Windows PE restarts the PC.
if exist "%SystemDrive%\sources\recovery\recenv.exe" (
  echo BeastBoot: starting the recovery environment.
  "%SystemDrive%\sources\recovery\recenv.exe"
)
echo BeastBoot: starting the Windows PE shell. Close it to restart the PC.
if exist "%BB_SYS%\startnet.cmd" (
  cmd /k "%BB_SYS%\startnet.cmd"
) else (
  cmd /k
)
exit /b 0

rem ------------------------------------------------------------- setup mode
:setup
rem A custom winpeshl.ini means Windows PE does not run wpeinit itself
rem (Plug and Play devices, network, drive letters): run it first.
echo BeastBoot: initialising Windows PE (wpeinit)...
wpeinit
if not defined BB_LOG call :find_bbtest
call :log winpe-ok

if not defined BB_ISO (
  set "BB_MSG=no-iso-path: the boot menu did not say which ISO to use (%BB_ENV% has no bb_winpe_iso line); update the drive's boot files"
  goto fail
)
set "BB_ISO=%BB_ISO:/=\%"
if not "%BB_ISO:~0,1%"=="\" set "BB_ISO=\%BB_ISO%"
set "BB_SAY=BeastBoot: looking for %BB_ISO% ..."
call :say

rem USB drives can take a few seconds to get a drive letter
for /l %%i in (1,1,20) do if not defined BB_DATA (
  call :find_data
  if not defined BB_DATA call :sleep 2
)
if not defined BB_DATA (
  set "BB_MSG=iso-not-found: no drive has %BB_ISO%. Is the BeastBoot drive still connected? Windows reads its data partition when it is exFAT, NTFS or FAT32"
  goto fail
)
set "BB_LINE=iso-found %BB_DATA%%BB_ISO%"
call :logline
echo BeastBoot: found the ISO on %BB_DATA%

rem Drives that already have Windows install media (not the ISO's)
for %%d in (%BB_DRIVES%) do call :mark_old %%d

if not exist "%BB_SYS%\beastmount.exe" (
  set "BB_MSG=no-mount-tool: beastmount.exe is missing, and this Windows PE has no built-in way to attach an ISO; update the drive's boot files"
  goto fail
)
echo BeastBoot: attaching the ISO read-only...
"%BB_SYS%\beastmount.exe" "%BB_DATA%%BB_ISO%"
if errorlevel 1 (
  set "BB_MSG=attach-failed: Windows could not open %BB_DATA%%BB_ISO% as a disc image (message above). The file may be damaged or incomplete: check it against the checksum Microsoft publishes"
  goto fail
)

for /l %%i in (1,1,15) do if not defined BB_SRC (
  call :find_new_media
  if not defined BB_SRC call :sleep 1
)
if not defined BB_SRC (
  set "BB_MSG=no-media: the ISO is attached, but no new drive with sources\install.wim or install.esd appeared; is it a Windows installation ISO?"
  goto fail
)
call :log iso-mounted %BB_SRC% %BB_INST%
echo BeastBoot: the ISO is drive %BB_SRC% (%BB_INST%)

set "BB_SETUP=%BB_SRC%\setup.exe"
if not exist "%BB_SETUP%" set "BB_SETUP=%BB_SRC%\sources\setup.exe"
if not exist "%BB_SETUP%" (
  set "BB_MSG=no-setup: drive %BB_SRC% has no setup.exe, so this ISO cannot install Windows from here"
  goto fail
)
call :log setup-started %BB_SETUP%
echo BeastBoot: starting Windows Setup (%BB_SETUP%)...
start "" "%BB_SETUP%"

rem Proof that Setup runs from the attached ISO: a setup.exe, setuphost.exe or
rem setupprep.exe process whose program file is on %BB_SRC% (tasklist shows
rem only names, and the RAM disk X: has a setup.exe of its own).
for /f "delims=" %%p in ('%BB_SYS%\beastmount.exe --running %BB_SRC% 60') do set "BB_PROC=%%p"
if not defined BB_PROC (
  set "BB_MSG=setup-not-running: Windows Setup (%BB_SETUP%) did not start, or it closed at once"
  goto fail
)
call :log setup-running
call :log setup-process %BB_PROC%
echo BeastBoot: Windows Setup is running (%BB_PROC%).
if defined BB_LOG goto test_end

rem Wait until Setup has ended (cancelled; after a full install Setup restarts
rem the PC itself), then leave a command prompt.
:wait_setup
call :sleep 5
%BB_SYS%\beastmount.exe --running %BB_SRC% 0 >nul 2>&1 && goto wait_setup
echo.
echo BeastBoot: Windows Setup has ended. Close this window to restart the PC.
cmd /k
exit /b 0

rem ---------------------------------------------------------------- helpers
:fail
call :log fail
echo.
echo BeastBoot: could not start Windows Setup.
setlocal EnableDelayedExpansion
echo   !BB_MSG!
endlocal
echo.
if defined BB_LOG (
  call :sleep 10
  goto test_end
)
echo A command prompt opens: you can look around (dir, diskpart), or close it
echo to restart the PC.
cmd /k
exit /b 1

rem Tests only (a disk labelled BBTEST is attached): power off, which ends the
rem test case. Setup stays on screen for a moment first.
:test_end
echo BeastBoot: test disk BBTEST found: powering off in 20 seconds.
call :sleep 20
wpeutil shutdown
cmd /k
exit /b 0

rem :log WORDS - append WORDS to RESULT.TXT on BBTEST ("fail": fail BB_MSG)
rem :logline - the same for the line in BB_LINE (for lines with user data:
rem ISO names may contain & % ! ( ), which "call" would expand or split)
:log
set "BB_LINE=%*"
if /i "%~1"=="fail" set "BB_LINE=fail %BB_MSG%"
:logline
if not defined BB_LOG exit /b 0
setlocal EnableDelayedExpansion
>>"!BB_LOG!" echo(!BB_LINE!
endlocal
exit /b 0

:find_bbtest
for %%d in (%BB_DRIVES%) do if not defined BB_LOG call :is_bbtest %%d
exit /b 0

:is_bbtest
vol %1: 2>nul | find /i "BBTEST" >nul || exit /b 0
set "BB_LOG=%1:\RESULT.TXT"
exit /b 0

:find_data
for %%d in (%BB_DRIVES%) do if not defined BB_DATA if exist "%%d:%BB_ISO%" call :is_data %%d && set "BB_DATA=%%d:"
exit /b 0

rem :is_data L - L: is the data partition: its volume serial (last word of the
rem last line of "vol", in any language) is the one the menu saved. The NTFS
rem serial is 64 bits and "vol" shows 32 of them (XXXX-XXXX): that must occur
rem in the saved one. Without a saved serial (older menu) any drive is taken.
:is_data
if not defined BB_UUID exit /b 0
set "BB_VL="
set "BB_VS="
for /f "delims=" %%l in ('vol %1: 2^>nul') do set "BB_VL=%%l"
if defined BB_VL for %%t in (%BB_VL%) do set "BB_VS=%%t"
if not defined BB_VS exit /b 1
set "BB_VS=%BB_VS:-=%"
set "BB_UN=%BB_UUID:-=%"
setlocal EnableDelayedExpansion
set "BB_T=!BB_UN:%BB_VS%=!"
if "!BB_T!"=="!BB_UN!" (endlocal & exit /b 1)
endlocal & exit /b 0

rem :has_media L - L: has sources\install.wim/.esd/.swm (the file in BB_INST)
:has_media
set "BB_INST="
for %%f in (install.wim install.esd install.swm) do if not defined BB_INST if exist "%1:\sources\%%f" set "BB_INST=%1:\sources\%%f"
if defined BB_INST exit /b 0
exit /b 1

:mark_old
call :has_media %1 && set "BB_OLD_%1=1"
exit /b 0

:find_new_media
for %%d in (%BB_DRIVES%) do if not defined BB_SRC call :check_new %%d
exit /b 0

:check_new
if defined BB_OLD_%1 exit /b 0
call :has_media %1 || exit /b 0
set "BB_SRC=%1:"
exit /b 0

rem :say - echo BB_SAY (text with user data) without expanding it again
:say
setlocal EnableDelayedExpansion
echo(!BB_SAY!
endlocal
exit /b 0

rem :sleep SECONDS (Windows PE has no timeout.exe; ping 127.0.0.1 works only once
rem the network stack runs, so beastmount.exe waits where it is there: setup mode)
:sleep
if exist "%BB_SYS%\beastmount.exe" (
  "%BB_SYS%\beastmount.exe" --sleep %~1
  exit /b 0
)
set /a BB_N=%~1+1
ping -n %BB_N% 127.0.0.1 >nul 2>&1
exit /b 0
