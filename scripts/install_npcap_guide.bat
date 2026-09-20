@echo off
echo ===================================================
echo   NIDS - Windows Npcap Setup Guide
echo ===================================================
echo.
echo Low-level live packet capture on Windows requires
echo the Npcap driver.
echo.
echo Step 1: Download Npcap installer from https://npcap.com
echo Step 2: Run the installer as Administrator.
echo Step 3: IMPORTANT: Check the option:
echo         "Install Npcap in WinPcap API-compatible Mode"
echo Step 4: Complete the installer and restart the NIDS backend.
echo.
echo Opening Npcap official download page...
start https://npcap.com/#download
pause
