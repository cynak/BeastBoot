@echo off
rem beast-booter portable (Windows): start the GUI. Double-click this file.
rem
rem Runs only what is in this folder: the bundled Python (runtime\), the
rem installer sources (app\) and the verified boot files (payload\dist).
rem Nothing is installed. The window runs as you; Windows shows an
rem administrator (UAC) prompt only for the step that writes the USB drive.
rem
rem pythonw.exe has no console, and "start" returns at once, so this console
rem window closes immediately.
rem   -s  ignore per-user Python packages    -E  ignore PYTHON* variables
rem   -B  write no .pyc files into this folder -S  no site-packages, no .pth files
setlocal
set "BB_HERE=%~dp0"
set "BEAST_BOOTER_DIST=%BB_HERE%payload\dist"
set "TCL_LIBRARY="
set "TK_LIBRARY="
start "" "%BB_HERE%runtime\pythonw.exe" -s -E -B -S "%BB_HERE%app\beast_booter_launch.py" --gui %*
endlocal
