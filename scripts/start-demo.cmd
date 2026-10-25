@echo off
rem Double-click to start Bastion locally. Add -Attack to also run the red-team agent, -Stop to stop.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-demo.ps1" %*
