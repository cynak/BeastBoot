@echo off
rem BeastBoot Windows PE start-up script (build/winpe/beastboot.cmd).
rem
rem The boot menu boots the ISO's sources\boot.wim with wimboot and injects
rem these files into X:\Windows\System32:
rem   winpeshl.ini    runs this script instead of the image's default shell
rem   beastboot.cmd   this script
rem   beastmount.exe  attaches an ISO read-only (VirtDisk API; setup mode only)
rem   beastboot.txt   the drive's GRUB environment block (grub/grubenv on the
rem                   ESP) with two lines the menu wrote with save_env:
rem                     bb_winpe_iso=/path/to/the.iso   (on the data partition)
rem                     bb_winpe_mode=setup | pe
rem
rem setup: find the data partition (the drive that has the ISO path), attach
rem        the ISO read-only (beastmount.exe: diskpart attaches only VHD/VHDX
rem        files, and Setup's Windows PE has no PowerShell or storage WMI
rem        provider), find its drive letter (the new drive with
rem        sources\install.wim/.esd/.swm) and start Windows Setup from it.
rem pe:    start the image's normal shell (WinRE's recovery UI, or startnet.cmd).
rem
rem Tests: when a disk labelled BBTEST is attached, progress lines are appended
rem to \RESULT.TXT on it: winpe-ok, iso-mounted <letter>:, setup-started, or
rem fail <reason>. On any failure the script says what failed and opens a
rem command prompt; closing it restarts the PC (as Windows PE always does).
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
set "BB_SRC="
echo.
echo BeastBoot: Windows PE started.

rem UTF-8, so non-ASCII ISO names in beastboot.txt read correctly (if chcp exists)
chcp 65001 >nul 2>&1

if exist "%BB_ENV%" (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%BB_ENV%") do (
    if /i "%%a"=="bb_winpe_iso" set "BB_ISO=%%b"
    if /i "%%a"=="bb_winpe_mode" set "BB_MODE=%%b"
  )
)
if not defined BB_MODE set "BB_MODE=pe"

call :find_bbtest
if /i "%BB_MODE%"=="setup" goto setup
if /i "%BB_MODE%"=="pe" goto pe
set "BB_MSG=unknown-mode %BB_MODE%"
call :log winpe-ok
goto fail

rem ---------------------------------------------------------------- pe mode
:pe
call :log winpe-ok
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
  set "BB_MSG=no-iso-path: %BB_ENV% names no ISO (bb_winpe_iso)"
  goto fail
)
set "BB_ISO=%BB_ISO:/=\%"
if not "%BB_ISO:~0,1%"=="\" set "BB_ISO=\%BB_ISO%"
echo BeastBoot: looking for %BB_ISO% ...

rem USB drives can take a few seconds to get a drive letter
for /l %%i in (1,1,20) do if not defined BB_DATA (
  call :find_data
  if not defined BB_DATA call :sleep 2
)
if not defined BB_DATA (
  set "BB_MSG=iso-not-found: no drive has %BB_ISO% (is the BeastBoot drive connected, and its data partition readable here: exFAT, NTFS or FAT32?)"
  goto fail
)
echo BeastBoot: found the ISO on %BB_DATA%

rem Drives that already have Windows install media (not the ISO's)
for %%d in (%BB_DRIVES%) do call :mark_old %%d

if not exist "%BB_SYS%\beastmount.exe" (
  set "BB_MSG=no-mount-tool: beastmount.exe is missing, and this Windows PE has no built-in way to attach an ISO"
  goto fail
)
echo BeastBoot: attaching the ISO read-only...
"%BB_SYS%\beastmount.exe" "%BB_DATA%%BB_ISO%"
if errorlevel 1 (
  set "BB_MSG=attach-failed: could not attach %BB_DATA%%BB_ISO% read-only (see the message above)"
  goto fail
)

for /l %%i in (1,1,15) do if not defined BB_SRC (
  call :find_new_media
  if not defined BB_SRC call :sleep 1
)
if not defined BB_SRC (
  set "BB_MSG=no-media: the ISO is attached, but no new drive with sources\install.wim or install.esd appeared"
  goto fail
)
call :log iso-mounted %BB_SRC%
echo BeastBoot: the ISO is drive %BB_SRC%

set "BB_SETUP=%BB_SRC%\setup.exe"
if not exist "%BB_SETUP%" set "BB_SETUP=%BB_SRC%\sources\setup.exe"
if not exist "%BB_SETUP%" (
  set "BB_MSG=no-setup: %BB_SRC% has no setup.exe"
  goto fail
)
call :log setup-started
echo BeastBoot: starting Windows Setup (%BB_SETUP%)...
start "" /wait "%BB_SETUP%"
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
echo A command prompt opens: you can look around (dir, diskpart), or close it
echo to restart the PC.
cmd /k
exit /b 1

rem :log WORDS - append WORDS to RESULT.TXT on BBTEST ("fail": fail BB_MSG)
:log
if not defined BB_LOG exit /b 0
set "BB_LINE=%*"
if /i "%~1"=="fail" set "BB_LINE=fail %BB_MSG%"
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
for %%d in (%BB_DRIVES%) do if not defined BB_DATA if exist "%%d:%BB_ISO%" set "BB_DATA=%%d:"
exit /b 0

:has_media
if exist "%1:\sources\install.wim" exit /b 0
if exist "%1:\sources\install.esd" exit /b 0
if exist "%1:\sources\install.swm" exit /b 0
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

rem :sleep SECONDS (Windows PE has no timeout.exe)
:sleep
set /a BB_N=%~1+1
ping -n %BB_N% 127.0.0.1 >nul 2>&1
exit /b 0
