# Update-FortigateSSLCert
This script does not incorporate Posh-ACME or Let's Encrypt renewal.  It simply takes an existing PFX, uploads it to a Fortigate and sets it as the HTTPS and SSL-VPN certificate.

### Script Platform

This script utilizes the Fortigate API. Therefore, it should be compatible with any current operating system capable in running Powershell.  For testing and it's production use, only Windows machines have actively been used.
If running Windows 7 SP1, 8.1 2008 R2 SP1, 2012, or 2012 R2, you must first install PowerShell 5.1, available at [https://aka.ms/WMF5Download](https://aka.ms/WMF5Download).

#### PowerShell version

This script is designed to run on PowerShell 5.1 or greater.  There have been issues on some PowerShell Core, so it is recommended not to use PowerShell Core at this time.  

### Create Secure Password
Powershell allows you to create a secure string that can only be decoded on the same machine it was encoded on.  This provides a little more security than just saving the password in plain text on the device.  This only needs to be done once for each password.

```powershell
# Fortigate administrator user password
Read-Host "Enter Password" -AsSecureString | ConvertFrom-SecureString | Out-File ".\password.txt"

# Certificate PFX Password
Read-Host "Enter Password" -AsSecureString | ConvertFrom-SecureString | Out-File ".\pfxpassword.txt"
```

### Normal Use
To normally run it, where:
FDQN or IP - needs to be either the IP address of the Fortigate or a resolvable FQDN
username - needs to be a user with administrative-level access
.\password.txt - needs to reference the same file created earlier
fg.example.com - needs to be the same FQDN that the certificate is created for

```powershell
$Fortigate = "<FQDN or IP of Fortigate>"
$CertPath = "Path to PFX file"
$CertPassword = (gc .\pfxpassword.txt | ConvertTo-SecureString)
.\Update-FortigateLECert.ps1 -Fortigate $Fortigate -Credential $(New-Object pscredential 'username',(gc .\password.txt | ConvertTo-SecureString)) -CertPath $CertPath -CertPassword $CertPassword
```
