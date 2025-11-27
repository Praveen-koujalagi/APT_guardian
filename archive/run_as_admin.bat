@echo off
echo Requesting administrator privileges...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    echo.
    echo Running packet capture test...
    python test_packet_capture.py
    echo.
    echo Test completed. Press any key to exit...
    pause >nul
) else (
    echo Administrator privileges required for packet capture.
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
)

