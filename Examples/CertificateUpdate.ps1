Configuration Meta
{
    Node $AllNodes.NodeName {
        LocalConfigurationManager {
            CertificateId = $Node.Thumbprint
            RebootNodeIfNeeded = $true
            AllowModuleOverwrite = $true
            RefreshMode = "Pull"
            RefreshFrequencyMins = 15
            ConfigurationModeFrequencyMins = 30
            ConfigurationMode = "ApplyAndAutoCorrect"
            DownloadManagerCustomData = @{ServerURL = 'https://dsc.contoso.com:8080/PSDSCPullServer.svc'}
            }
        }
}

$Nodes = @{
    AllNodes = @(
	@{
        NodeName = "Server01"
        }
	);
   }

#Build Configuration
$Nodes = Update-ConfigurationDataCertificates -ConfigurationData $Nodes
Meta -ConfigurationData $Nodes

#By adding the extra "Update-ConfigurationDataCertificates" function, thumbprint and certificatefile info is added to the data so that passwords can be encrypted in the mof.
