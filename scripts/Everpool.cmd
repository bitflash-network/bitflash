@echo off
rem Everpool helper: list, mine and create Everpool pools (everpool.ps1).
rem Add -testnet after the file name to use the test network.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0everpool.ps1" %*
pause
