@echo off
echo First argument: %1

netsh advfirewall firewall add rule name="BLOCK IP ADDRESS - %1" dir=in action=block remoteip=%1