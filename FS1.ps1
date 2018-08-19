# FS1 Config

# Setup Server
$ipAddress = @{
    InterfaceAlias = 'Ethernet'
    IPAddress = '10.10.1.20'
    AddressFamily = 'IPv4'
    PrefixLength = 24
    DefaultGateway = '10.10.1.254'
}
New-NetIPAddress @ipAddress

$dnsAddress = @{
    InterfaceAlias = 'Ethernet'
    ServerAddresses = '10.10.1.10'
}
Set-DnsClientServerAddress @dnsAddress

New-NetFirewallRule –DisplayName “Allow ICMPv4-In” –Protocol ICMPv4
New-NetFirewallRule –DisplayName “Allow ICMPv4-Out” –Protocol ICMPv4 –Direction Outbound

# Add to Domain
Add-Computer -DomainName corp.contoso.com -NewName FS1 -OUPath "OU=Corp Servers,DC=Corp,DC=Contoso,DC=com" -Restart