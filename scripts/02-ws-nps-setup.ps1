# WS-NPS (192.168.100.30) - run in an elevated PowerShell, after joining lab.local
Install-WindowsFeature -Name NPAS -IncludeManagementTools

# Register NPS in AD (adds the computer account to "RAS and IAS Servers")
netsh nps add registeredserver domain=lab.local server=WS-NPS.lab.local

# RADIUS ports
New-NetFirewallRule -DisplayName "Allow RADIUS 1812" -Direction Inbound -Protocol UDP -LocalPort 1812 -Action Allow
New-NetFirewallRule -DisplayName "Allow RADIUS 1813" -Direction Inbound -Protocol UDP -LocalPort 1813 -Action Allow

# RADIUS client (can also be done in nps.msc)
netsh nps add client name="AP-Kali" address="192.168.100.60" state=enable sharedsecret="Secret@1234"

# Restart and check that NPS listens
net stop ias
net start ias
netstat -ano | findstr :1812

# Export the NPS configuration (policies, clients) for backup / review
netsh nps export filename="C:\nps-config.xml" exportPSK=YES
