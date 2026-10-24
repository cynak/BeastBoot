@echo off
rem beast-booter portable (Windows): the command line interface.
rem
rem   beast-booter.cmd --help
rem   beast-booter.cmd install --device \\.\PhysicalDrive2   (from a terminal
rem                                     opened with "Run as administrator")
rem   beast-booter.cmd install --image my.img --size 8G     (image files: no admin)
rem
rem Runs only what is in this folder (runtime\, app\, payload\dist); installs nothing.
rem   -s  ignore per-user Python packages    -E  ignore PYTHON* variables
rem   -B  write no .pyc files into this folder -S  no site-packages, no .pth files
setlocal
set "BB_HERE=%~dp0"
set "BEAST_BOOTER_DIST=%BB_HERE%payload\dist"
set "TCL_LIBRARY="
set "TK_LIBRARY="
"%BB_HERE%runtime\python.exe" -s -E -B -S "%BB_HERE%app\beast_booter_launch.py" %*
exit /b %ERRORLEVEL%
