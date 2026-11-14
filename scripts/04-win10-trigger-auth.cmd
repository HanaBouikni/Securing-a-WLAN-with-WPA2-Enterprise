@echo off
:: Windows 10 client - run as Administrator
:: Forces a new 802.1X authentication on Ethernet0 and shows the result
sc config dot3svc start= auto
net stop dot3svc
net start dot3svc
netsh interface set interface "Ethernet0" admin=disable
netsh interface set interface "Ethernet0" admin=enable
timeout /t 10 >nul
netsh lan show interfaces
