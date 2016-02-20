# DSCHelperFunctions
Collection of functions to help create more dynamic ConfigurationData for DSC use when generating MOFs.

The original pupose was to make available a function that worked with the cLCMCertManager DSC resource to make certificate management a reality.  It now also includes a method for importing passwords into the configurationdatahash as well, as well as a simple install function that creates a sample password.xml to use as a source and SMB share as a certificate desitnation.

If MOF generation is automated, the functions here can help form a fully-automated maintenance strategy by dynamically updating and pushing meta configuration with the "best matched" thumbprint, as well as encrypting the main mof with the appropriate public certificate.    Please see my blog for a more complete example of the DSC Resource and function working in tandem.
