@echo off

set SERVICE_NAME=dohclient

sc delete "%SERVICE_NAME%"  

pause

@echo on