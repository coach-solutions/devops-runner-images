################################################################################
##  File:  Install-DockerLinux.ps1
##  Desc:  Install docker in Ubuntu in WSL 2.
################################################################################

Write-Host "Configure Ubuntu distribution for Docker"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Type "DWord" -Value 1

$dockerUser = 'dockerlinux'
$dockerPassword = 'P@ssw0rd' #[System.GUID]::NewGuid().ToString().ToUpper()
$dockerSecurePassword = ConvertTo-SecureString $dockerPassword -AsPlainText -Force

$params = @{
    Name        = $dockerUser
    Password    = $dockerSecurePassword
    FullName    = 'Docker Linux'
    Description = 'Docker user account.'
}
New-LocalUser @params
Add-LocalGroupMember -Group "Administrators" -Member $dockerUser

$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $dockerUser, $dockerSecurePassword

New-Item -Path "C:\" -Name "DockerLinux" -ItemType "Directory"
$taskScript = @'
function WaitUntilServices($searchString, $status)
{
    # Get all services where DisplayName matches $searchString and loop through each of them.
    foreach($service in (Get-Service -DisplayName $searchString))
    {
        # Wait for the service to reach the $status or a maximum of 30 seconds
        $service.WaitForStatus($status, '00:00:15')
    }
}

WaitUntilServices "Hyper-V Virtual Machine Management" "Running"
WaitUntilServices "WSL Service" "Running"

& "C:\Program Files\WSL\wsl.exe" '-u' 'root' '-d' 'Ubuntu' '-e' '/bin/bash'
'@
$taskScript | Out-File -FilePath C:\DockerLinux\Startup.ps1

Invoke-Command -Credential $cred -Computer localhost -ScriptBlock {

    wsl.exe --update

    wsl.exe --install Ubuntu -n --web-download
    ubuntu.exe install --root
    wsl.exe --set-version Ubuntu 2

    # apt install -y isn't enough to be truly noninteractive
    $env:DEBIAN_FRONTEND = "noninteractive"
    $env:WSLENV += ":DEBIAN_FRONTEND"

    # update software
    Write-Host "Update Ubuntu"

    wsl.exe -u root -d Ubuntu apt-get update
    wsl.exe -u root -d Ubuntu apt-get full-upgrade -y
    wsl.exe -u root -d Ubuntu apt-get autoremove -y
    wsl.exe -u root -d Ubuntu apt-get autoclean
    wsl.exe -u root -d Ubuntu echo '"[boot]"' '|' tee /etc/wsl.conf '>' /dev/null
    wsl.exe -u root -d Ubuntu echo '"systemd=true"' '|' tee -a /etc/wsl.conf '>' /dev/null
    wsl.exe --shutdown  # instead of 'reboot'

    # install docker
    Write-Host "Install Docker"

    wsl.exe -u root -d Ubuntu apt-get install ca-certificates curl openssh-server -y
    wsl.exe -u root -d Ubuntu install -m 0755 -d /etc/apt/keyrings
    wsl.exe -u root -d Ubuntu curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    wsl.exe -u root -d Ubuntu chmod a+r /etc/apt/keyrings/docker.asc
    wsl.exe -u root -d Ubuntu echo '"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable"' '|' tee /etc/apt/sources.list.d/docker.list '>' /dev/null
    wsl.exe -u root -d Ubuntu apt-get update
    wsl.exe -u root -d Ubuntu apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    wsl.exe -u root -d Ubuntu systemctl enable docker.service
    wsl.exe -u root -d Ubuntu systemctl enable containerd.service
    wsl.exe -u root -d Ubuntu systemctl enable ssh.service

    # expose docker to windows
    wsl.exe -u root -d Ubuntu useradd -c'docker user' -m -s /bin/bash dockerssh
    wsl.exe -u root -d Ubuntu passwd -d dockerssh
    wsl.exe -u root -d Ubuntu usermod -a -G docker dockerssh
    wsl.exe -u root -d Ubuntu echo 'PermitEmptyPasswords yes' '|' tee -a /etc/ssh/sshd_config '>' /dev/null
    wsl.exe -u root -d Ubuntu echo 'StrictModes yes' '|' tee -a /etc/ssh/sshd_config '>' /dev/null
    wsl.exe -u root -d Ubuntu echo 'ssh' '|' tee -a /etc/securetty '>' /dev/null
    wsl.exe --shutdown
    wsl.exe -u root -d Ubuntu ln -s /mnt/c /c
    wsl.exe -u root -d Ubuntu ln -s /mnt/d /d
    ssh.exe -o StrictHostKeyChecking=accept-new 'dockerssh@localhost' echo Done
    Copy-Item "${Env:USERPROFILE}\.ssh\known_hosts" "${Env:ALLUSERSPROFILE}\ssh\ssh_known_hosts"
    Remove-Item "${Env:USERPROFILE}\.ssh\known_hosts"

    # set docker host variable
    $Env:DOCKER_HOST = "ssh://dockerssh@localhost"
    $Env:COMPOSE_CONVERT_WINDOWS_PATHS = 1
    [Environment]::SetEnvironmentVariable("DOCKER_HOST", "ssh://dockerssh@localhost", "Machine")
    [Environment]::SetEnvironmentVariable("COMPOSE_CONVERT_WINDOWS_PATHS", "1", "Machine")

    # set automatic start of the distribution
    Write-Host "Setup automatic start of Ubuntu distribution"
    $wslStartAction = New-ScheduledTaskAction 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument 'C:\DockerLinux\Startup.ps1'
    $wslStartupTrigger = New-ScheduledTaskTrigger -AtStartup
    $wslStartupSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 31)
    $principal = New-ScheduledTaskPrincipal -RunLevel Highest $Env:USERNAME -LogonType S4U
    $task = New-ScheduledTask -Action $wslStartAction -Principal $principal -Trigger $wslStartupTrigger -Settings $wslStartupSettings
    Register-ScheduledTask 'Start-Docker-Wsl-On-Boot' -InputObject $task
    Start-ScheduledTask 'Start-Docker-Wsl-On-Boot'

}
