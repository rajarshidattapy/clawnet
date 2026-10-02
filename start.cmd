@echo off
rem Double-click or run from cmd: starts the ClawForge stack (see start.ps1 for options).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
