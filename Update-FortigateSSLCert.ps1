<#
.SYNOPSIS
This is a simple Powershell Core script to update Fortigate SSL certificate with a LetsEncrypt cert

.DESCRIPTION
This script uploads, and then adds it to a Fortigate over SSH. This is designed to be ran consistently.

.EXAMPLE
$Fortigate = "<IP or FQDN of Fortigate>"
$User = "<username>"
$PasswordFile = "<path to password file>"
$CertPath = "<path to PFX certificate file>"
$PFXPasswordFile = "<path to PFX password file>"
$CertName = "<name of certificate to be displayed on Fortigate (optional)>"
.\Update-FortigateFileCert.ps1 -Fortigate $Fortigate -Credential $(New-Object pscredential $User, (gc $PasswordFile | ConvertTo-SecureString)) -CertPath $CertPath -CertPassword (gc $PFXPasswordFile | ConvertTo-SecureString) -CertName $CertName

.LINK
https://github.com/northeastnebraskanetworkconsortium/Update-FortigateSSLCert

#>


Param(
    [string]$Fortigate,
    [Parameter(ParameterSetName = "SecureCreds")]
    [pscredential]$Credential,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [string]$Username,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [String]$Password,
    [String]$CertPath,
    [Security.SecureString]$CertPassword,
    [String]$CertName = $(get-date -Format 'yyyy-MM-dd')
)

function Connect-Fortigate {
    Param(
        $Fortigate,
        $Credential
    )

    $postParams = @{username=$Credential.UserName;secretkey=$Credential.GetNetworkCredential().Password}
    try{
        Write-Verbose "Authenticating to 'https://$Fortigate/logincheck' with username: $($Credential.UserName)" | Out-File $LogFile -Append
        #splat arguments
        $splat = @{
            Uri = "https://$Fortigate/logincheck";
            SessionVariable = "session";
            Method = 'POST';
            Body = $postParams
        }
        if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}

        $authRequest = Invoke-WebRequest @splat
    }catch{
        Write-Verbose "Failed to authenticate to Fortigate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to authenticate to Fortigate with error: `n`t$_"
    }
    Write-Verbose "Authentication successful!" | Out-File $LogFile -Append
    $csrftoken = ($authRequest.Headers['Set-Cookie'].split(";") | where {$_ -like "*ccsrftoken=*"}).split('"')[1]

    Set-Variable -Scope Global -Name "FgtServer" -Value $Fortigate
    Set-Variable -Scope Global -Name "FgtSession" -Value $session
    Set-Variable -Scope Global -Name "FgtCSRFToken" -Value $csrftoken
}

function Invoke-FgtRestMethod {
    Param(
        $Endpoint,
        [ValidateSet("Default","Delete","Get","Head","Merge","Options","Patch","Post","Put","Trace")]
        $Method = "Get",
        $Body = $null
    )

    Write-Verbose "Building Headers" | Out-File $LogFile -Append
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type','application/x-www-form-urlencoded')
    # Add csrf cookie
    $headers.Add('X-CSRFTOKEN',$FgtCSRFToken)

    $splat = @{
        Headers = $headers;
        Uri = "https://$FgtServer/api/v2/$($Endpoint.TrimStart('/'))";
        WebSession = $FgtSession;
        Method = $Method;
        Body = $body | ConvertTo-Json
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    return Invoke-RestMethod @splat
}

function Disconnect-Fortigate {
    Write-Verbose "Building Headers" | Out-File $LogFile -Append
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type','application/x-www-form-urlencoded')
    # Add csrf cookie
    $headers.Add('X-CSRFTOKEN',$FgtCSRFToken)
    
    # logout
    $splat = @{
        Headers = $headers;
        Uri = "https://$FgtServer/logout";
        WebSession = $fgtSession;
        Method = "GET"
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    $logoutRequest = Invoke-RestMethod @splat

    Remove-Variable -Scope Global -Name "FgtServer"
    Remove-Variable -Scope Global -Name "FgtSession" 
    Remove-Variable -Scope Global -Name "FgtCSRFToken"
    return $logoutRequest
}

function Upload-FgtCertificate {
    Param(
        $CertificatePath,
        $CertName,
        $PfxPassword
    )
    $newCertParams = @{
        type = 'pkcs12'
        certname=$CertName
        password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
        scope='global'
        file_content = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CertificatePath))
    }
    Write-Verbose "Uploading Certificate" | Out-File $LogFile -Append
    try{
        Invoke-FgtRestMethod -Endpoint "/monitor/vpn-certificate/local/import/" -Body $newCertParams -Method "Post"
    }catch{
        Write-Verbose "Failed to upload certificate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to upload certificate with error:`n`t$_"
    }
}

function Update-FgtAdminCert {
    Param(
        $CertName
    )
    $body = @{'admin-server-cert' = $CertName}
    Invoke-FgtRestMethod -Endpoint "/cmdb/system/global" -Body $body -Method "Put"
}

function Update-FgtSslVpnCert{
    Param(
        $CertName
    )
    $body = @{'servercert' = $CertName}
    Invoke-FgtRestMethod -Endpoint "/cmdb/vpn.ssl/settings" -Body $body -Method "Put"
}

$LogFile = '.\UpdateFortigate.log'
Get-Date | Out-File $LogFile -Append
Write-Output "Starting Certificate Renewal for $($Fortigate)" | Out-File $LogFile -Append

if($CertPath){
    Write-Output "...Renewal Complete!" | Out-File $LogFile -Append

    if($PSCmdlet.ParameterSetName -eq "PlainTextPassword"){
        Write-Warning "You shouldn't use plaintext passwords on the commandline" | Out-File $LogFile -Append
        $Credential = New-Credential -Username $env:FGT_USER -Password $env:FGT_PASS
    }

    Connect-Fortigate -Fortigate $Fortigate -Credential $Credential
    Write-Output "Updating the LetsEncrypt Certificate on the FGT" | Out-File $LogFile -Append
    Upload-FgtCertificate -CertificatePath $CertPath -CertName $certname -PfxPassword $CertPassword
    Write-Output "Updating the Admin certificate on the FGT" | Out-File $LogFile -Append
    ## this command fails every first time with "The response ended prematurely" - no idea why, but it works, so I don't really care
    try{
        Update-FgtAdminCert -CertName $CertName
    }catch{}
    Write-Output "Updating the SSLVPN certificate on the FGT" | Out-File $LogFile -Append
    Update-FgtSslVpnCert -CertName $CertName
    Disconnect-Fortigate

}else{
    Write-Output "No need to update certificate!" | Out-File $LogFile -Append
}
