function Install-DSCHelperStores
{
<#
.Synopsis
Simple install function that creates default folders and files if needed
.DESCRIPTION
This functioncreates a certificate storage share and sample passwordXML file for use by the remaining functions. Generally, this will only ever be run once.
.EXAMPLE
Install-DSCHelperStores

Creates two new folders in $env:PROGRAMFILES\WindowsPowershell\DscService\:"NodeCertficates" and "Management".  "NodeCertificates" is shared, and a sample passwords.xml is placed in management.
.PARAMETER CertStore
The location for the certificates to be placed.
The default path if not defiend is $env:PROGRAMFILES\WindowsPowershell\DscService\NodeCertificates
.PARAMETER PasswordData
The location for the passwordxml file.
The default file is $env:PROGRAMFILES\WindowsPowershell\DscService\Management\passwords.xml
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][Alias("PullServerCertStore")][String]$CertStore = "$env:PROGRAMFILES\WindowsPowershell\DscService\NodeCertificates",
        [Parameter(Mandatory=$false)][Alias("XMLFile")][String]$PasswordData = "$env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml",
        [Parameter(Mandatory=$false)][Alias("CSVFile")][String]$GUIDData = "$env:PROGRAMFILES\WindowsPowershell\DscService\DSCNodes.csv"
        )

    Begin {
        [bool]$IsValid=$true
        [string]$Domain=(Get-WmiObject -Class Win32_NTDomain).DomainName
        $Domain = $Domain.Trim()
    }#End Begin Block

    Process {
    If($CertStore -and !(Test-Path -Path ($CertStore))) {
        try {
            Write-Verbose "Creating Folder $Certstore"
            New-Item ($CertStore) -type directory -force -ErrorAction STOP | Out-Null

            Write-Verbose "Creating SMB Share"
            New-SmbShare -Name "CertStore" -Path $CertStore -ChangeAccess Everyone | Out-Null

            Write-Verbose "Setting permssions for Domain Computers"
            $acl = get-acl $CertStore
            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
            $propagation = [system.security.accesscontrol.PropagationFlags]"None"
            $rule = new-object System.Security.AccessControl.FileSystemAccessRule("$Domain\Domain Computers","Modify",$inherit,$propagation,"Allow")
            $acl.SetAccessRule($rule)
            set-acl $CertStore $acl
            }
        catch {
            $E = $_.Exception.GetBaseException()
            $E.ErrorInformation.Description
            }
        }#End Create Missing CertStore
    Else {write-verbose "$certstore already exists"}

    If($PasswordData -and !(Test-Path -Path ($PasswordData))) {
        Write-Verbose "File not found, creating dummy file"
        $FilePath = Split-Path $PasswordData
        
        #If missing, create the folder structure
        If (!(Test-Path -Path $FilePath)) {
            Try {
                write-verbose "Creating password parent directory"
                New-Item ($FilePath) -type directory -force -ErrorAction STOP | Out-Null
                }
            Catch {
                $E = $_.Exception.GetBaseException()
                $E.ErrorInformation.Description
                write-verbose "error creating directory $FilePath"
                break
                }
            }#End Parent Folder Creation

        #Try to create the sample xml
        Try {
            Write-Verbose "Creating file $PasswordData"
            $xmlWriter = New-Object System.XMl.XmlTextWriter($PasswordData,$Null)
            #Set Format 
            $xmlWriter.Formatting = 'Indented'
            $xmlWriter.Indentation = 1
            $XmlWriter.IndentChar = "`t"
            #Create
            $xmlWriter.WriteStartDocument()
            #Start New Element array
            $xmlWriter.WriteStartElement('Credentials')
            #Add Stuff to it
            $xmlWriter.WriteStartElement('Variable')
            $xmlWriter.WriteAttributeString('Name', 'DomainAdminCredentials')
            $xmlWriter.WriteAttributeString('User','Contoso\Administrator')
            $xmlWriter.WriteAttributeString('Password','Password')
            #End specific Entry
            $xmlWriter.WriteEndElement()
            #End larger element
            $xmlWriter.WriteEndElement()
            #Write to disk and let it go
            $xmlWriter.Flush()
            $xmlWriter.Close()
            }
        Catch {
            write-error "Error creating sample xml File"
            break
            }
        }#End Create Missing PasswordData
    Else {write-verbose "$PasswordData already exists"}

    If($GUIDData -and !(Test-Path -Path ($GUIDData))) {
        Write-Verbose "File not found, creating dummy file"
        $FilePath = Split-Path $GUIDData
        
        #If missing, create the folder structure
        If (!(Test-Path -Path $FilePath)) {
            Try {
                write-verbose "Creating csv parent directory"
                New-Item ($FilePath) -type directory -force -ErrorAction STOP | Out-Null
                }
            Catch {
                $E = $_.Exception.GetBaseException()
                $E.ErrorInformation.Description
                write-verbose "error creating directory $FilePath"
                break
                }
            }#End Parent Folder Creation

        #Try to create the sample csv
        Try {
            Write-Verbose "Creating file $GUIDData"
            #Need to create a custom object to add to the arraylist
            $newentry = new-object PSObject
            $newentry | Add-Member -Type NoteProperty -Name NodeName -Value "Node1"
            $newentry | Add-Member -Type NoteProperty -Name NodeGUID -Value "12345678-1234-1234-1234-1234567890ab"
            $newentry | export-csv -Path $GUIDData -Force
            }
        Catch {
            write-error "Error creating sample csv File"
            break
            }
        }#End Create Missing GUIDData
    Else {write-verbose "$GUIDData already exists"}

    }#End Process Block
}

function Update-ConfigurationDataCertificates
{
<#
.Synopsis
Function that adds Certificate parameters to nodes in a hashtable
.DESCRIPTION
Function is designed to assist DSC automation by dynamically matching nodes in configurationdata with certificates of the same name in a specified directory.  The function ouputs a modified hashtable with thumbprint and certificatefile parameters added.  When used with the DSCResource cLCMCertManager, it can create a complete Certificate management solution.
.EXAMPLE
$updatedlabhosts = Update-ConfigurationDataCertificates -ConfigurationData $LabHosts

The above command takes the configurationdata "$Labhosts" and updates it to include certificate signing information.
.PARAMETER ConfigurationData
The configurationdata hashtable to update.
.PARAMETER CertStore
The path to the current collection of certificates.  Certificaets are assumed to be saved with a matching filename to the NodeName (plus .cer).
The default path checked if not defiend is $env:PROGRAMFILES\WindowsPowershell\DscService\NodeCertificates
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][HashTable]$ConfigurationData,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Alias("PullServerCertStore")][String]$CertStore = "$env:PROGRAMFILES\WindowsPowershell\DscService\NodeCertificates"
    )

    Begin {
        #Gather Certifcate List from the CertStore, and stage the initial return data
        $FoundCerts = (get-childitem $certstore -File -Filter *.cer).BaseName
        $ReturnData = $ConfigurationData
    }


    Process {
        #Update each Node with certificate information if found
        $ReturnData.AllNodes | ForEach-Object -Process {
        $CurrNode = $_.NodeName
        If (($FoundCerts -contains $CurrNode) -and ($CurrNode -ne "*")) {
            
            #Set the filename
            $CertificateFile = $CertStore+'\'+$CurrNode+'.cer'

            #Create X509Certificate2 object that will represent the certificate, then import into it
            $CertPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2    
            $CertPrint.Import($CertificateFile)
            $Thumbprint = $CertPrint.Thumbprint

            #Update the Record
            If ($Thumbprint) {
                $_.Thumbprint = $Thumbprint
                $_.CertificateFile = $CertificateFile
                }
            Else {
                write-error "There was an error retrieving the certificate thumbprint"
                }
            }
        }#End Per-Object Crawl
    }

    End {
        return $ReturnData
    }
}

function Update-ConfigurationDataPasswords
{
<#
.Synopsis
Function that imports usernames and passwords from an XMLfile and stores them in the "*" node for consumption
.DESCRIPTION
Function is designed to assist DSC automation by importing passwords from an XML file into the wildcard node of a configuration.  This allows passwords to be stores seperate from the main configuration script
.EXAMPLE
$updatedlabhosts = Update-ConfigurationDataPasswords -ConfigurationData $LabHosts

The above command takes the configurationdata "$Labhosts" and updates it to include all passwords in the password log.
.PARAMETER ConfigurationData
The configurationdata hashtable to update.
.PARAMETER PasswordData
The path to the current password XML file.  For guidance, Install-DSCHelperStores can create a "sample".
The default file checked if not defiend is $env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][HashTable]$ConfigurationData,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Alias("XMLFile")][String]$PasswordData = "$env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml"
    )

    Begin {
        #Load ConfigurationData into memory and execute updates
        $ReturnData = $ConfigurationData
        $Wildcardinjection = $null
    }#End Begin Block

    Process {
        #Seperate Wilcard information from the rest of configuration
        IF ($ReturnData.AllNodes.Where({$_.NodeName -eq "*"})) {
            $Returndata.AllNodes | ForEach-Object { IF ($_.NodeName -eq "*") {$Wildcardinjection= $_}}
            $ReturnData.AllNodes = $ReturnData.AllNodes.Where{($_.NodeName -ne "*")}
            }
        Else {
            #Create Missing Wildcard
            $Wildcardinjection = @{}
            $Wildcardinjection.NodeName = "*"
            }
    
        #Merge Passwords into Wildcard
        $Wildcardinjection+=Import-PasswordXML -XMLFile $PasswordData
        $ReturnData.AllNodes+=$Wildcardinjection
    }#End process block

    End {
        Return $ReturnData
    }
}

function Update-ConfigurationDataNames
{
<#
.Synopsis
Function that imports NodeNames and associated GUIDs from a CSVfile and then updates ConfigurationData accordingly
.DESCRIPTION
Function allows admins to use "friendly" names for nodes, and transltes them into GUIDs for use by DSC.  Capable of replacing found translations as well as generating new GUIDs for new entries if flag is set.
.EXAMPLE
$updatedlabhosts = Update-ConfigurationDataNames -ConfigurationData $LabHosts

The above command takes the configurationdata "$Labhosts" and updates it to use GUID entries stored in a csv.
.PARAMETER ConfigurationData
The configurationdata hashtable to update.
.PARAMETER GUIDData
The path to the current .csv file.  Install-DSCHelperStores can be used to create a file for guidance
The default file checked if not defiend is $env:PROGRAMFILES\WindowsPowershell\DscService\DSCNodes.csv
.PARAMETER Update
Tells the function to generate a new GUID and update the CSV file if a Node is missing
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][HashTable]$ConfigurationData,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Alias("CSVFile")][String]$GUIDData = "$env:PROGRAMFILES\WindowsPowershell\DscService\DSCNodes.csv",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Switch]$Update = $false
    )

    Begin {
        #Load ConfigurationData and node information into memory
        $ReturnData = $ConfigurationData
        [System.Collections.ArrayList]$DSCNodes = Import-Csv -path $GUIDData
        [bool]$DSCNodesFileNeedsUpdating = $false
    }#End Begin Block

    Process {
        #Check each nodename for an equivelant thumbprint
        $ReturnData.AllNodes | ForEach-Object -Process {
            $OrigName = $_.NodeName
            If ($DSCNodes.NodeName -contains $OrigName) {
                $NewGuid = ($DSCNodes | Where {$_.NodeName -eq $OrigName}).NodeGuid
                $_.NodeName = $NewGuid
                Write-Verbose -Message "Updated $OrigName to $NewGUID"
                }#End Match Found
            ElseIf ($Update -and ($OrigName -ne "*")) {
                $DSCNodesFileNeedsUpdating = $true
                $NewGuid = [string][guid]::NewGuid()
                $_.NodeName = $NewGuid
                #Need to create a custom object to add to the arraylist
                $newentry = new-object PSObject
                $newentry | Add-Member -Type NoteProperty -Name NodeName -Value $OrigName
                $newentry | Add-Member -Type NoteProperty -Name NodeGUID -Value $NewGUID
                $DSCNodes.add($newentry) | Out-Null
                Write-Verbose -Message "created missing entry for $OrigName and $NewGUID"
                }#End update Missing Entry
            }#End crawling each Node
    }#End process block

    End {
        If ($DSCNodesFileNeedsUpdating) {
            Write-Verbose -Message "committing changes to $GUIDData"
            $DSCNodes | export-csv -Path $GUIDData -Force
            }
        Return $ReturnData
    }#End Block
}

Function Import-PasswordXML
{
<#
.Synopsis
Takes the contents of an xml file and  either returns credential objects or stores them as variables in the current session
.DESCRIPTION
This function is primarily designed to assist Update-ConfigurationDataPasswords, but is allowed to be called direclty for other uses
.EXAMPLE
Import-PasswordXML -XMLFile "C:\passwords.xml"

This will return one pscredential object per username/password combination found in passwords.xml
.EXAMPLE
Import-PasswordXML -XMLFile "C:\passwords.xml" -ToSession

This will create pscredential per username/password combination and store it as a varable in the current session.
.PARAMETER XMLFile
The path to the current password XML file.  If the file does not exist, the module will attempt to create a "sample" for population.
The default file checked if not defiend is $env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml
.PARAMETER ToSession
Switch that toggles if the object is returned directly or stored as a variable in the current session
#>
[cmdletBinding()]
param(
    [Parameter(Mandatory=$false)][String]$XMLFile = "$env:PROGRAMFILES\WindowsPowershell\DscService\passwords.xml",
    [Parameter(Mandatory=$false)][Switch]$ToSession
    )

    begin {
        #Check if XMLFile is missing
        IF (!(Test-Path -Path $XMLFile)) {
            Write-Error "File not found, cannot continue"
            Break
            }#End Create XML If
    }#End Begin block

    Process {
        #Generate Password Variables from XMLData
        Write-Verbose -Message "Loading Passwords from xml..."
        $Passwords = @{}
        $Config = [XML](Get-Content $XMLFile)
        $Config.Credentials | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
        $SecurePass = ConvertTo-SecureString $_.Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential $_.User, $SecurePass
        If ($ToSession) {    
            $PSCmdlet.SessionState.PSVariable.Set($_.Name, $cred)
            }
        Else {
            $Passwords.add($_.Name, $cred)
            }
        } #End ForEach Loop
    }#End process block

    End {
        #Return Hashtable
        If (!$ToSession) {return $Passwords}
    }#End End Block
}
