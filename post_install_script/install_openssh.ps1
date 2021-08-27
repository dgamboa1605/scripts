param (
    [bool]$SkipGetUserMetaData = $False,
    [string]$ProxyServer,
    [string]$ProxyPort,
    [string]$BypassUrls,
    [string]$CustomerId,
    [string]$APIClientID,
    [string]$APIClientSecret,
    [string]$ResourceLocation,
    [string]$ADDomainName,
    [string]$ADServerName,
    [string]$ActiveDirectoryUserName,
    [string]$ActiveDirectoryPassword,
    [string]$PreferredDnsServer
)
##############################################################################################
#  Joins client to Active Directory Domain, Downloads connector and installs it.
##############################################################################################
Function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level
    )
    switch($Level) {
        'Error' {
            $LogLevel = 'ERROR'
        }
        'Warn' {
            $LogLevel = 'WARN'
        }
        'Info' {
            $LogLevel = 'INFO'
        }
    }
    $Stamp = (Get-Date).toString("yyyy-MM-dd HH:mm:ss")
    $Line = "$Stamp $LogLevel $Message"

    If ($LogFile) {
        Add-Content $LogFile -Value $Line
    } Else {
        Write-Output $Line
    }
}

Function Set-Proxy($Server, $Port, $BypassUrls) {
    Write-Log -Level Info "Configuring Proxy"
    try {
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyServer -Value "$($Server):$($Port)"
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -Value 1
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyOverride -Value "$($BypassUrls)"
    } catch {
        $string_err = $_ | Out-string
        Write-Log -Level Error "Cannot set Proxy $string_err"
    }
    Write-Log -Level Info "Proxy Configured on: $($Server):$($Port) Bypass-List $($BypassUrls)"
}

Function Set-Trusted-Sites($TrustedSites) {
    #Setting IExplorer settings
    Write-Log -Level Info "Now configuring IE Trusted Sites"
    try {
        ForEach ($TrustedSite in $TrustedSites) {
            #Navigate to the Domains folder in the registry
            $location = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
            set-location $location

            $regKeyPath = "$location\$TrustedSite"

            #Create a Registry Key with the website name if it not exist
            If (!(Test-Path $regKeyPath)) {
                #Create a new Registry Key with the website name
                new-item $TrustedSite/ -Force

                #open the created Registry Key
                set-location $TrustedSite/

                #add new value to the Registry Key
                new-itemproperty . -Name https -Value 2 -Type DWORD -Force

                Write-Log -Level Info "Added Trusted Site $TrustedSite to the Registry"
            } Else {
                Write-Log -Level Info "Already added Trusted Site $TrustedSite"
            }
        }
    } catch {
        $string_err = $_ | Out-string
        Write-Log -Level Info "Cannot add TrustedSites to the Registry $string_err"
    }
    Write-Log -Level Info "Finished adding Trusted Sites"
    # Set back to the c: drive
    c:
}

Function DownloadOenSshTool {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$downloadPath,
            [Parameter(Mandatory=$true)][System.Uri]$downloadsUri,
            [Parameter(Mandatory=$true)][string]$proxyUri

        )
        Write-Log -Level Info "Downloading to $downloadPath"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            Invoke-WebRequest -Method GET -Uri $downloadsUri -OutFile $downloadPath -Proxy $proxyUri -Verbose
            Expand-Archive 'c:\Program Files\openssh.zip' 'C:\Program Files\'
            cd 'C:\Program Files\./OpenSSH-Win64\'
            powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
            New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
            netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=sshd
            Start-Service sshd
            Powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false'
            Set-Service sshd -StartupType Automatic
            Set-Service ssh-agent -StartupType Automatic
        } catch [System.Net.WebException] {
            $string_err = $_ | Out-String
            Write-Log -Level Error $string_err
            Throw "Unable to download tool $_"
        }
        If (Test-Path $downloadPath) {
            Write-Log -Level Info "Tool downloaded successfully from $downloadsUri to $downloadPath"
        } Else {
            Write-Log -Level Error "Unable to download tool from $downloadsUri to $downloadPath"
            Throw "Unable to download tool from $downloadsUri to $downloadPath"
        }
}

Function Get-CustomerResourceLocations {
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CustomerId,
        [Parameter(Mandatory=$true)][string] $ClientId,
        [Parameter(Mandatory=$true)][string] $ClientSecret,
        [Parameter(Mandatory=$true)][string] $TrustUri,
        [Parameter(Mandatory=$false)][System.Uri] $registryServiceBaseUri = "https://registry.citrixworkspacesapi.net",
        [Parameter(Mandatory=$false)][switch]$ReturnPSObject,
        [Parameter(Mandatory=$true)][string]$proxyUri
    )
    $ErrorActionPreference = "Stop"

    #GET Auth Header
    $registryServiceUri = New-Object -TypeName System.Uri -ArgumentList $registryServiceBaseUri, "$CustomerId/resourcelocations"
    $AuthHeader = New-BearerAuthHeaderFromSecureClient -ClientId $ClientId -ClientSecret $ClientSecret -TrustUri $TrustUri -proxyUri $proxyUri
    Write-Log -Level Info $AuthHeader.Authorization

    #Get Customer resource location
    $getResponse = $null
    try {
        $getResponse = Invoke-RestMethod -Method GET -Uri $registryServiceUri -Headers $AuthHeader -ContentType "application/json" -Proxy $proxyUri -Verbose
    }
    catch [System.Net.WebException] {
        $string_err = $_ | Out-String
        Write-Log -Level Error "Registry endpoint failed: $string_err"
    }

    If (-not $getResponse) {
        Write-Log -Level Warn "No response from endpoint $registryServiceUri" -Verbose
    }

    If ($ReturnPSObject) {
        return $getResponse
    } Else {
        Write-Log -Level Info (ConvertTo-Json $getResponse)
    }
}

Function New-BearerAuthHeaderFromSecureClient {
    <#
        .SYNOPSIS
            Creates a bearer authorization header using a customer's secure client (ID & secret)
        .DESCRIPTION
            This command calls New-BearerAuthHeaderValue function to create a new bearer token.
            Then return the authorization header CWSAuth bearer=<bearer>.
        .PARAMETER  ClientId
            A client id for the customer
        .PARAMETER  ClientSecret
            A corresponding client secret of the client id specified.
        .PARAMETER  TrustUri
            The trust url.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $ClientId,

        [Parameter(Mandatory=$true)]
        [string] $ClientSecret,

        [Parameter(Mandatory=$true)]
        [string] $TrustUri,

        [Parameter(Mandatory=$true)]
        [string]$proxyUri
    )
    $BearerAuthHeaderValue  = New-BearerAuthHeaderValue -ClientId $ClientId -ClientSecret $ClientSecret -TrustUri $TrustUri -proxyUri $proxyUri
    return @{"Authorization" = $BearerAuthHeaderValue}
}

Function New-BearerAuthHeaderValue {
    <#
        .SYNOPSIS
            Create a new bearer token using a Customer's Secure Client
        .DESCRIPTION
            This command contacts trust URI to obtain a bearer token.
        .PARAMETER  ClientId
            A client id for the customer
        .PARAMETER  ClientSecret
            A corresponding client secret of the client id specified.
        .PARAMETER  TrustUri
            The trust url.
        .PARAMETER Timeout
            The Invoke-RestMethod timeout used when contacting the trust url.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $ClientId,

        [Parameter(Mandatory=$true)]
        [string] $ClientSecret,

        [Parameter(Mandatory=$true)]
        [string] $TrustUri,

        [Parameter(Mandatory=$false)]
        [Int] $Timeout = 300,

        [Parameter(Mandatory=$true)]
        [string]$proxyUri
    )

    $endPoint = "root/tokens/clients"
    $trustUri = "$TrustUri/$endPoint"

    $Body = @{
        clientId = $ClientId
        clientSecret = $ClientSecret
    }
    Write-Log -Level Info "[Body]: $(ConvertTo-Json $Body)"

    try {
        $response = Invoke-RestMethod -Uri $trustUri -Method "Post" -Body (ConvertTo-Json $Body) -ContentType application/json -TimeoutSec $Timeout -Proxy $proxyUri -Verbose
    } catch [System.Net.WebException] {
        $string_err = $_ | Out-String
        Write-Log -Level Error "Trust endpoint failed: $string_err"
        throw $_
    }
    Write-Log -Level Info "[Response] $(ConvertTo-Json $response)"

    $BearerAuthHeaderValue = "CWSAuth bearer=`"$($response.token)`""

    return $BearerAuthHeaderValue
}

Function Set-Dns {
    $PreferredDnsServer = $args[0]
    $Interface = Get-WmiObject Win32_NetworkAdapterConfiguration

    #Print initial configuration
    $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
    Write-Log -Level Info "Initial DNS Search Order: $dnsServers"

    #Verify if DNS is alreadu set
    If($Interface.DNSServerSearchOrder.contains($PreferredDnsServer)) {
        Write-Log -Level Info "Dns is already set to $PreferredDnsServer"
        return
    }
    $ComputerName = $env:COMPUTERNAME
    $ValidIp = [bool]($PreferredDnsServer -as [ipaddress])

    If($ValidIp) {
        Write-Log -Level Info "Registering DNS $PreferredDnsServer for $ComputerName"
        $result = $Interface.SetDNSServerSearchOrder($PreferredDnsServer)
        Write-Log -Level Info "DNS Registered Result: $result"
        $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
        Write-Log -Level Info "Modified DNS Search Order: $dnsServers"
    } Else {
        Write-Log -Level Error "Incorrect Preferred Dns Server $PreferredDnsServer"
        exit 1
    }
}

Function Join-Domain {
    <#
        .PARAMETER  ADDomainName
            Name of Active Directory Domain
        .PARAMETER  ADServerName
            Server Name where Active Directory Domain is in
        .PARAMETER  ActiveDirectoryUserName
            Active Directory Server's UserName
        .PARAMETER ActiveDirectoryPassword
            Active Directory Server's Password
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String] $ADDomainName,
        [Parameter(Mandatory=$true)][String] $ADServerName,
        [Parameter(Mandatory=$true)][String] $ActiveDirectoryUserName,
        [Parameter(Mandatory=$true)][String] $ActiveDirectoryPassword
    )

    #Verify if already Joined
    If((Get-WmiObject Win32_ComputerSystem).Domain -eq $ADDomainName){
        Write-Log -Level Info "Already Joined to the Domain $ADDomainName"
        return $true
    }

    $Credential = New-Object System.Management.Automation.PSCredential(
        $ActiveDirectoryUserName,
        (ConvertTo-SecureString -String $ActiveDirectoryPassword -AsPlainText -Force)
    )
    try{
        $AddComputer = Add-Computer -DomainName $ADDomainName -Server $ADServerName -Credential $Credential -ErrorAction Stop -PassThru -Verbose
        Write-Log -Level Info "Added Computer $AddComputer"
        Write-Log -Level Info "Joined to the Domain $ADDomainName"
        return $true
    } catch {
        $string_err = $_ | Out-string
        Write-Log -Level Error $string_err
        exit 1
    }
}

Function Disable-ieESC {
    Write-Log -Level Info "Entering Disable-ieESC"
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Write-Log -Level Info "IE Enhanced Security Configuration (ESC) has been disabled."
}

Function Get-NumberRestOfString {
    Param ($Rest)
    $Rest | Select-String -Pattern "^(?<num>\d+),(?<rest>.+)" |
    ForEach-Object {
        $num, $rest = $_.Matches[0].Groups['num', 'rest']
        return [int]$num.Value, $rest.Value
    }
}

Function Get-UserMetaData {
    $endpoint = "https://api.service.softlayer.com/rest/v3.1/SoftLayer_Resource_Metadata/getUserMetadata"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -Verbose

        Write-Log -Level Info "Request made to $endpoint for UserMetadata"
        Write-Log -Level Info "The Response StatusCode is $($response.StatusCode) and StatusDescription is $($response.StatusDescription)"
        return $response
   } catch {
       Write-Log -Level Error ("Request to web service failed: $endpoint " + $_)
       return $null
   }
}

Function Get-Arguments {
    $response = Get-UserMetaData
    if ($null -eq $response) {
        Write-Log -Level Info "Setting Bypass Proxy for api.service.softlayer.com and retry request"
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyOverride -Value "api.service.softlayer.com"
        $response = Get-UserMetaData
    }
    if ($null -eq $response) {
        exit 1
    }
    If ($response.StatusCode -ne 200 -OR $response.StatusDescription -ne "OK") {
        Write-Log -Level Error "Invalid response from web service: $endpoint"
        Write-Log -Level Error "The Response StatusCode is $($response.StatusCode) and StatusDescription is $($response.StatusDescription)"
        exit 1
    }
    $InputString = $response.Content
    $count, $rest = Get-NumberRestOfString($InputString.substring(1,$InputString.length-2))
    Write-Log -Level Info "User metadata argument count: $count"
    $arraysize = $count-1
    $lengths = @(0..$arraysize)
    for ($i = 0; $i -lt $count; $i++){
        $length, $rest = Get-NumberRestOfString($rest)
        $lengths.SetValue($length, $i)
    }
    $strings = @(0..$arraysize)
    $i = 0
    $start = 0
    foreach($length in $lengths)
    {
        $strings.SetValue($rest.Substring($start, $length), $i++)
        $start += $length
    }
    return $strings
}

Function Sync-Time {
    w32tm /config /manualpeerlist:servertime.service.softlayer.com /syncfromflags:MANUAL
    Stop-Service w32time
    Start-Service w32time
    Start-Sleep -s 10
}

Function Ping-Citrix-AgentHub {
    try {
        $apiurl = "https://agenthub.citrixworkspacesapi.net/root/ping"
        $apiping = Invoke-WebRequest $apiurl -UseBasicParsing -Verbose
        Write-Log -Level Info "Citrix Workspace Ping Response for $apiurl : $($apiping.StatusDescription) ($($apiping.StatusCode))"
    } catch {
        $string_err = $_ | Out-string
        Write-Log -Level Error $string_err
    }
}

Function Get-SpecifiedResourceLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$CustomerResourceLocations
    )
    $AvailableResourceLocations = $CustomerResourceLocations.items."name"
    Write-Log -Level Info "The Available Resource Locations $AvailableResourceLocations"

    $ResourceLocation = [System.Web.HttpUtility]::UrlDecode($ResourceLocation)
    $SpecifiedResourceLocation = $customerResourceLocations.items | Where-Object {$_.name -eq $ResourceLocation}

    If ($SpecifiedResourceLocation) {
        Write-Log -Level Info "Customer ResourceLocation $SpecifiedResourceLocation and the id $($SpecifiedResourceLocation.id)"
        return $SpecifiedResourceLocation
    } Else {
        Throw "Unable to find a resource location named $ResourceLocation"
    }
}

Function Citrix-Connector-Installation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$ConnectorInstallationArgs,
        [Parameter(Mandatory=$true)]$ConnectorInstaller,
        [Parameter(Mandatory=$true)]$ConnectorInstallerName
    )
    Write-Log -Level Info "** Installing... $ConnectorInstaller with arguments $ConnectorInstallationArgs ."
    $process = Start-Process $ConnectorInstaller $ConnectorInstallationArgs -Wait -Passthru

    If ($process.ExitCode -eq 0) {
        Write-Log -Level Info "$ConnectorInstallerName Installation Complete"
    } ElseIf ($process.ExitCode -eq 1603) {
        Write-Log -Level Info "An unexpected error occured while installing $ConnectorInstallerName. Exit code: $($process.ExitCode)"
    } ElseIf ($process.ExitCode -eq 2) {
        Write-Log -Level Info "A prerequiste check failed while installing $ConnectorInstallerName. Exit code: $($process.ExitCode)"
    } Else {
        Write-Log -Level Error "Unable to Install $ConnectorInstallerName.  Exit code: $($process.ExitCode)"
    }
}

############################################################################################
# Main
############################################################################################
$LogFile = "$HOME\Desktop\OpenSshInstallation.log"
$TrustUri = "https://trust.citrixworkspacesapi.net"
$DownloadPath = "C:\Program Files\openssh.zip"
$DownloadUri = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v1.0.0.0/OpenSSH-Win64.zip"
$ConnectorInstallerName = "cwcconnector.exe"
$ScriptName = $MyInvocation.MyCommand.Name
$OSVersion = [System.Environment]::OSVersion.Version
$DotNet = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
$UserName  = [Environment]::UserName
$TrustedSites = @(
    "*.citrixworkspacesapi.net",
    "*.citrixnetworkapi.net",
    "*.cloud.com",
    "*.blob.core.windows.net",
    "*.nssvc.net",
    "*.servicebus.windows.net",
    "*.xendesktop.net",
    "*.citrixdata.com",
    "*.sharefile.com",
    "*.digicert.com",
    "*.azureedge.net",
    "*.citrixdata.com",
    "login.citrixonline.com",
    "*github.com"
)
Write-Log -Level Info "----------------------------------------"
Write-Log -Level Info "Started executing $ScriptName"
Write-Log -Level Info "----------------------------------------"
Write-Log -Level Info "Script Version: 2021.04.19-1"
Write-Log -Level Info "Current User: $UserName"
Write-Log -Level Info "The OS Version is $OSVersion"
Write-Log -Level Info ".Net version $($DotNet.version)"
Write-Log -Level Info ".Net release $($DotNet.release)"
Write-Log -Level Info "Host Version $($Host.Version)"

if (-not $SkipGetUserMetaData) {
    $ProxyServer, $ProxyPort, $BypassUrls, $CustomerId, $APIClientID, $APIClientSecret, $ResourceLocation, $ADDomainName, `
    $ADServerName, $ActiveDirectoryUserName, $ActiveDirectoryPassword, $PreferredDnsServer = Get-Arguments
}

$proxyUri = "http://$($ProxyServer):$($ProxyPort)"

Write-Log -Level Info "The ProxyUri is $proxyUri"

try {
    #Set DNS
    Set-Dns $PreferredDnsServer

    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
    $networkConfig.SetDnsDomain("")
    $networkConfig.SetDynamicDNSRegistration($true)
    ipconfig /registerdns
    Start-Sleep -s 5

    #Disable IE-ESC
    Disable-ieESC

    #Join Active Directory Domain
    $DomainJoined = Join-Domain -ADDomainName $ADDomainName -ADServerName $ADServerName -ActiveDirectoryUserName $ActiveDirectoryUserName -ActiveDirectoryPassword $ActiveDirectoryPassword
    Write-Log -Level Info "Domain Joined $DomainJoined"

    #Synchronize Time
    Sync-Time

    Set-Proxy -Server $ProxyServer -Port $ProxyPort -BypassUrls $BypassUrls

    Set-Trusted-Sites $TrustedSites
    #Proxy settings flow to IE from Registry
    Start-Sleep -s 5
    Start-Process iexplore.exe  -WindowStyle Hidden
    Start-Sleep -s 4
    Stop-Process -Name "iexplore"

    Start-Sleep -s 2
    $ProxyBeforeImport=netsh winhttp show proxy
    #Proxy settings flow from IE to system
    $ImportProxy=cmd /c netsh winhttp import proxy source=ie
    Start-Sleep -s 5
    #Proxy settings visble in Powershell?
    $ProxyAfterImport=netsh winhttp show proxy
    Write-Log -Level Info "Proxy Before netsh $ProxyBeforeImport"
    Write-Log -Level Info "netsh output $ImportProxy"
    Write-Log -Level Info "Proxy After netsh $ProxyAfterImport"

    Ping-Citrix-AgentHub
    #Registry update as we do not want system to be rebooted before Cloud Connector Install. Better to reboot after Domain join but this works.
    reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v PendingFileRenameOperations /f
    #Download Connector
    DownloadOenSshTool -downloadPath $DownloadPath -downloadsUri $DownloadUri -proxyUri $proxyUri

    If ($DomainJoined) {
        Write-Log -Level Info "Restarting Computer"
        Restart-Computer
    }

} catch {
    $string_err = $_ | Out-string
    Write-Log -Level Error $string_err
}
