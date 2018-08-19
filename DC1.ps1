# DC1 Config

# Setup Server
$ipAddress = @{
    InterfaceAlias = 'Ethernet'
    IPAddress = '10.10.1.10'
    AddressFamily = 'IPv4'
    PrefixLength = 24
    DefaultGateway = '10.10.1.254'
}
New-NetIPAddress @ipAddress
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 127.0.0.1,8.8.8.8
New-NetFirewallRule –DisplayName “Allow ICMPv4-In” –Protocol ICMPv4
New-NetFirewallRule –DisplayName “Allow ICMPv4-Out” –Protocol ICMPv4 –Direction Outbound
Rename-Computer DC1 -Restart

# Install ADDS
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName corp.contoso.com -ForestMode Win2012R2 -InstallDNS

# Configure DNS
Add-DnsServerPrimaryZone -NetworkId 10.10.1.0/24 -ReplicationScope Forest

# Install DHCP
Install-WindowsFeature DHCP -IncludeManagementTools
Netsh DHCP Add SecurityGroups
Restart-Service DhcpServer
Add-DhcpServerInDC -DnsName dc1.corp.contoso.com
Add-DhcpServerv4Scope -name "Corpnet" -StartRange 10.10.1.100 -EndRange 10.10.1.150 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -DnsDomain corp.contoso.com -DnsServer 10.10.1.10 -Router 10.10.1.254
Set-DHCpServerv4OptionValue -OptionId 4 -Value 10.10.1.10

# Create OU's
New-ADOrganizationalUnit -Name "Corp Admins"
New-ADOrganizationalUnit -Name "Corp Security Groups"
New-ADOrganizationalUnit -Name "Corp Servers"
New-ADOrganizationalUnit -Name "Corp Users"
New-ADOrganizationalUnit -Name "Corp Workstations"
New-ADOrganizationalUnit -Name "MDT"

# Add Admin user
New-ADUser -Name a-cwestwater -AccountPassword (read-host "Set user password" -assecurestring) -ChangePasswordAtLogon $false -DisplayName "Westwater, Colin (Admin)" -EmailAddress a-cwestwater@corp.contoso.com -Enabled $true -GivenName Colin -PasswordNeverExpires $true -Path "OU=Corp Admins,DC=Corp,DC=Contoso,DC=com" -SamAccountName a-cwestwater -Surname Westwater -UserPrincipalName a-cwestwater@corp.contoso.com
Add-ADPrincipalGroupMembership -Identity a-cwestwater -MemberOf "CN=Enterprise Admins,CN=Users,DC=corp,DC=contoso,DC=com","CN=Domain Admins,CN=Users,DC=corp,DC=contoso,DC=com"

# Add Non-Admin user
New-ADUser -Name cwestwater -AccountPassword (read-host "Set user password" -assecurestring) -ChangePasswordAtLogon $false -DisplayName "Westwater, Colin" -EmailAddress cwestwater@corp.contoso.com -Enabled $true -GivenName Colin -PasswordNeverExpires $true -Path "OU=Corp Users,DC=Corp,DC=Contoso,DC=com" -SamAccountName cwestwater -Surname Westwater -UserPrincipalName cwestwater@corp.contoso.com

# Import GPOs from SCT
New-GPO -Name "MSFT Windows Server 2012 R2 Domain Controller Baseline"
Import-GPO -BackupId 631572F1-2CE9-481D-8FAB-A1553A4DBD56 -Path C:\Temp\GPOs -TargetName "MSFT Windows Server 2012 R2 Domain Controller Baseline"
New-GPO -Name "MSFT Windows Server 2012 R2 Member Server Baseline"
Import-GPO -BackupId AB1A03CA-A251-4FDC-9C95-3BFE14EF9A54 -Path C:\Temp\GPOs -TargetName "MSFT Windows Server 2012 R2 Member Server Baseline"

# Link GPOs
New-GPLink -Name "MSFT Windows Server 2012 R2 Domain Controller Baseline" -Target "OU=Domain Controllers,DC=Corp,DC=Contoso,DC=com" -LinkEnabled Yes
New-GPLink -Name "MSFT Windows Server 2012 R2 Domain Controller Baseline" -Target "OU=Corp Admins,DC=Corp,DC=Contoso,DC=com" -LinkEnabled Yes
New-GPLink -Name "MSFT Windows Server 2012 R2 Member Server Baseline" -Target "OU=Corp Servers,DC=Corp,DC=Contoso,DC=com" -LinkEnabled Yes
New-GPLink -Name "MSFT Windows Server 2012 R2 Member Server Baseline" -Target "OU=Corp Admins,DC=Corp,DC=Contoso,DC=com" -LinkEnabled Yes

# Redirect new computer and user objects
redircmp "OU=MDT,DC=Corp,DC=Contoso,DC=com"
redirusr "OU=Corp Users,DC=Corp,DC=Contoso,DC=com"
