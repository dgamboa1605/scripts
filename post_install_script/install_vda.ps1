#ps1_sysnative

#############################################################################
# © Copyright IBM Corp. 2021, 2021

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################
param (
    [Parameter(Mandatory=$false)][string]$VdaExeName,
    [Parameter(Mandatory=$false)][string]$preferredDnsServer
)

<#
.SYNOPSIS
    Sets DNS to Active Directory domain IP address.

.DESCRIPTION
    This script sets the DNS to the IP address of the Active Directory server that is in the
    same zone.

.NOTES
    This script is executed post server deployment by Cloudbase-Init.
#>

Function Write-Log {
    <#
    .SYNOPSIS
        Writes log message to log file.

    .DESCRIPTION
        This function accepts a log message and optional log level,
        then adds a timestamped log message to the log file.

    .PARAMETER $Message
        Message string that will be added to the log file.

    .PARAMETER $Level
        Optional log level parameter that must be "Error", "Warn", or "Info".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]
        $Level
    )

    $LevelValue = @{Error = "Error"; Warn = "Warning"; Info = "Information"}[$Level]
    $LogFile = $env:SystemDrive + "\IBMCVADInstallation.log"
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    Add-Content $LogFile -Value "$Stamp $LevelValue $Message"
}

Function Check-Vda-Installed{
    Write-Log -Level Info "Checking if VDA is isntalled"
    $app = Get-WmiObject -Class Win32_Product | where vendor -eq "Citrix Systems, Inc." | Select Name
    $res = $true
    if ($app -eq $null) {
        $res = $false
    }
    Write-Log -Level Info "VDA is isntalled: $res"
    return $res
}

Function Write-Environment {
    <#
    .SYNOPSIS
        Writes header to the log file.

    .DESCRIPTION
        This function writes a header to the log file to capture general information about the
        script execution environment.
    #>
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Started executing $($MyInvocation.ScriptName)"
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Script Version: 2022.02.07-1"
    Write-Log -Level Info "Current User: $env:username"
    Write-Log -Level Info "Hostname: $env:computername"
    Write-Log -Level Info "The OS Version is $env:OSVersion.Version"
    Write-Log -Level Info "Host Version $($Host.Version)"
    $DotNet = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    Write-Log -Level Info ".NET version/release $($DotNet.version)/$($DotNet.release)"
}

Function Set-Dns {
    <#
    .SYNOPSIS
        Sets preferred DNS.
    .DESCRIPTION
        This function sets the preferred IP address for DNS.
    .PARAMETER $PrefferedDNSServer
        IP Address to set as preferred DNS address.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $PreferredDnsServer
    )

    $Interface = Get-WmiObject Win32_NetworkAdapterConfiguration
    $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
    Write-Log -Level Info "Initial DNS Search Order: $dnsServers"

    if ($Interface.DNSServerSearchOrder.contains($PreferredDnsServer)) {
        Write-Log -Level Info "Dns is already set to $PreferredDnsServer"
        return
    }

    if ([bool]($PreferredDnsServer -as [ipaddress])) {
        Write-Log -Level Info "Registering DNS $PreferredDnsServer"
        $result = $Interface.SetDNSServerSearchOrder($PreferredDnsServer)
        Write-Log -Level Info "DNS Registered Result: $result"
        $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
        Write-Log -Level Info "Modified DNS Search Order: $dnsServers"
    } else {
        Write-Log -Level Error "Incorrect Preferred Dns Server $PreferredDnsServer"
        exit 1
    }
}

Function Download-Vda {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$vdaExeName
        )
        $downloadsUri = "https://github.com/llgamboll/scripts/raw/main/vda_installer/$vdaExeName"
        $downloadPath = "$HOME\Downloads\$vdaExeName"

        Write-Log -Level Info "Downloading $vdaExeName"
        Write-Log -Level Info "Downloading to $downloadPath"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            Invoke-WebRequest -Method GET -Uri $downloadsUri -OutFile $downloadPath -Verbose
        } catch [System.Net.WebException] {
            $string_err = $_ | Out-String
            Write-Log -Level Error $string_err
            Throw "Unable to download installer $_"
        }
        If (Test-Path $downloadPath) {
            Write-Log -Level Info "Tool downloaded successfully from $downloadsUri to $downloadPath"
        } Else {
            Write-Log -Level Error "Unable to download tool from $downloadsUri to $downloadPath"
            Throw "Unable to download tool from $downloadsUri to $downloadPath"
        }
}

Function Install-Vda {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$vdaExeName
        )

    Write-Log -Level Info "Installing VDA"
    $vda_path = "$HOME\Downloads\$vdaExeName"
    $isVdaExist = Test-Path $vda_path
    if (!$isVdaExist) {
        Write-Log -Level Error "The VDA Exexutable file is not present in the Downloads folder, Please download or move the VDA Executable file to Downloads"
        exit 1
    }

    $arguments = @(
        "/components VDA"
        "/mastermcsimage"
        "/logpath $HOME\Desktop"
        "/includeadditional"
        '"Citrix Supportability Tools,Citrix Profile Management,Citrix Profile Management WMI Plugin"'
        "/enable_hdx_ports"
        "/quiet"
        "/noreboot"
    )

    $process = Start-Process $vda_path $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Log -Level Info "The VDA Installation is Successful"
    } elseif ($process.ExitCode -eq 3) {
        Write-Log -Level Info "The VDA Installation is Partially Successful, Reboot Required after the Windows Update"
    } else {
        Write-Log -Level Error "The VDA Installation is UnSuccessful Please check the installation log file located on the Desktop, Exit Code : $($process.ExitCode)"
    }
}

Function Windows-Update {
    Write-Log -Level Info "Installing Windows Update"
	Install-PackageProvider -Name NuGet -Force
	Set-PSRepository PSGallery -InstallationPolicy Trusted
    if ((Get-Module -ListAvailable | Where {$_.Name -eq 'PSWindowsUpdate'}) -eq $null) {
        Write-Log -Level Info "PSWindowsUpdate module not installed, installing now."
        Install-Module PsWindowsUpdate -Verbose -ErrorAction Stop
    } else {
        Write-Log -Level Info "PSWindowsUpdate module is already installed."
    }

    Write-Log -Level Info "Installing Windows Updates, server will be rebooted automatically if required"
    Get-WindowsUpdate -Verbose
    Install-WindowsUpdate -AcceptAll -AutoReboot
    Write-Log -Level Info "Windows Updates Installed"
}

#
# MAIN
#
Write-Environment

if ($preferredDnsServer -ne "") {
    Set-Dns -preferredDnsServer $preferredDnsServer
}
$res = Check-Vda-Installed

if ($res -eq $false){
    $citrixLogs = "$HOME\Desktop\Citrix\XenDesktop Installer\XenDesktop Installation.log"
    if (Test-Path $citrixLogs){
        Write-Log -Level Info "Reboot windows to complete install VDA"
        shutdown /r /t 60
    }else{
        if ($VdaExeName -ne "") {
            Download-Vda -vdaExeName $VdaExeName
            Install-Vda -vdaExeName $VdaExeName
            Windows-Update
        } else {
            Write-Log -Level Info "VDA is not yet installed, manually run this script with the VDA Executable file name as an argument to Install VDA"
        }
    }
}else {
    Write-Log -Level Info "Installing Windows Updates, server will be rebooted automatically if required"
    Get-WindowsUpdate -Verbose
    Install-WindowsUpdate -AcceptAll -AutoReboot
    Write-Log -Level Info "Windows Updates Installed"
}
