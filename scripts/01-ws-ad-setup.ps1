# WS-AD (192.168.100.10) - run in an elevated PowerShell
# Step 1: network + hostname (the machine restarts)
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.100.10
Rename-Computer -NewName "WS-AD" -Restart

# Step 2: install AD DS, then promote to DC of lab.local with the Server Manager wizard
# Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Step 3 (after promotion): OU, users, group
Import-Module ActiveDirectory
New-ADOrganizationalUnit -Name "Etudiants" -Path "DC=lab,DC=local"

foreach ($u in "student1","student2") {
    New-ADUser -Name $u -SamAccountName $u -UserPrincipalName "$u@lab.local" `
        -Path "OU=Etudiants,DC=lab,DC=local" `
        -AccountPassword (ConvertTo-SecureString "Pass@1234" -AsPlainText -Force) `
        -Enabled $true
}

New-ADGroup -Name "WLANUsers" -GroupScope Global -Path "OU=Etudiants,DC=lab,DC=local"
Add-ADGroupMember -Identity "WLANUsers" -Members "student1","student2"

# Group that allows NPS to read user dial-in properties (was missing on this domain)
New-ADGroup -Name "RAS and IAS Servers" -GroupScope DomainLocal -Path "CN=Users,DC=lab,DC=local"
Add-ADGroupMember -Identity "RAS and IAS Servers" -Members "WS-NPS$"

# Verification
Get-ADUser -Filter * -SearchBase "OU=Etudiants,DC=lab,DC=local" | Select-Object Name, Enabled
net group WLANUsers /domain
