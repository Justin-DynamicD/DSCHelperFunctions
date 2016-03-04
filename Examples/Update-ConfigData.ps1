#This parameter hastable contains common locations for "stuff".  Most of these variables are "defaulted" in the functions.
$Parameters = @{
    PullServerConfiguration = "$env:PROGRAMFILES\WindowsPowershell\DscService\Configuration"
    CertStore = "$env:PROGRAMFILES\WindowsPowershell\DscService\NodeCertificates"
    PasswordData = "$env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml"
    GUIDData = "$env:PROGRAMFILES\WindowsPowershell\DscService\DSCNodes.csv"
    }


#Sample Configuration data for consumption
$ConfigurationData = @{ 
    AllNodes = @(
        @{ 
            NodeName = '*'
            DomainName = "lab.contoso.com"
        },
        
        @{ 
            NodeName = "dc-01"
            Service = 'ActiveDirectory'
            Role = 'PDC'
            DNSServerAddresses = "192.168.1.102","127.0.0.1"
        },

        @{ 
            NodeName = "dc-02"
            Service = 'ActiveDirectory'
	        Role = 'RODC'
            DNSServerAddresses = "192.168.1.100","127.0.0.1"
        }

    ); 
}

#Each function in action, updating info with certificate, passwords and GUID information
$ConfigurationData = Update-ConfigurationDataCertificates -ConfigurationData $ConfigurationData -CertStore $Parameters.CertStore
$ConfigurationData = Update-ConfigurationDataPasswords -ConfigurationData $ConfigurationData -PasswordData $Parameters.PasswordData
$ConfigurationData = Update-ConfigurationDataNames -ConfigurationData $ConfigurationData -GUIDData $Parameters.GUIDData

#3 functions are seperate as different companies will have different needs. WMF5 ConfigurationName users, for example, will never convert nodenames to GUID.