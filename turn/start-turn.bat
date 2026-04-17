@echo off
REM Start TURN server for 4Messenger
REM Make sure turnserver is installed and in PATH
REM Update turnserver.conf with your public IP and generate certificates

echo Starting TURN server...
turnserver -c turnserver.conf

pause