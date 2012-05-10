@echo off
setlocal
set TESTDIR=%~dp0unittest
set XYZZYHOME=%TESTDIR%\..
"%XYZZYHOME%\xyzzy.exe" -q -l "%TESTDIR%\run-all.l"
