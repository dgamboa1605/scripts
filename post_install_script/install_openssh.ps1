[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest https://github.com/PowerShell/Win32-OpenSSH/releases/download/v1.0.0.0/OpenSSH-Win64.zip -OutFile "c:\Program Files\openssh.zip"
Expand-Archive 'c:\Program Files\openssh.zip' 'C:\Program Files\'
cd 'C:\Program Files\./OpenSSH-Win64\'
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=sshd
Start-Service sshd
Powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false'
Set-Service sshd -StartupType Automatic
Set-Service ssh-agent -StartupType Automatic
