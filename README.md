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
$Fortigate = "<IP or FQDN of Fortigate>"
$User = "<username>"
$PasswordFile = "<path to password file>"
$CertPath = "<path to PFX certificate file>"
$PFXPasswordFile = "<path to PFX password file>"
$CertName = "<name of certificate to be displayed on Fortigate (optional)>"

```powershell
$Fortigate = "fg.example.com"
$User = "administrator"
$PasswordFile = "C:\Password.txt"
$CertPath = "C:\certificate.pfx"
$PFXPasswordFile = "C:\certificatePassword.txt"
$CertName = "Certificate2022"

.\Update-FortigateLECert.ps1 -Fortigate $Fortigate -Credential $(New-Object pscredential $User,(gc $PasswordFile | ConvertTo-SecureString)) -CertPath $CertPath -CertPassword $PFXPasswordFile -CertName $CertName
```
