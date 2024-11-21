################################################################################
##  File:  Install-DockerLinux.ps1
##  Desc:  Install docker in Ubuntu in WSL 2.
################################################################################

Write-Host "Configure Ubuntu distribution for Docker"

# setup directory with install and startup scripts
New-Item -Path "C:\" -Name "DockerLinux" -ItemType "Directory"
$installScript = @'
& "C:\Program Files\WSL\wsl.exe" '--update' > 'C:\DockerLinux\install.log'
New-Item -Path $Env:USERPROFILE -Name "DockerLinux" -ItemType "Directory" -Force
& "C:\Program Files\WSL\wsl.exe" '--import' 'Docker' "$Env:USERPROFILE\DockerLinux" 'C:\DockerLinux\docker.tar' >> 'C:\DockerLinux\install.log'
'@
$installScript | Out-File -FilePath C:\DockerLinux\Install.ps1

$startupScript = @'
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
WaitUntilServices "User Profile Service" "Running"

Start-ScheduledTask -TaskPath '\DockerLinux\' 'Run-Docker-Wsl'
Start-Sleep -Seconds 3

$timeout = 30 ##  seconds
$timer =  [Diagnostics.Stopwatch]::StartNew()
while (((Get-ScheduledTask -TaskName 'Run-Docker-Wsl' -TaskPath '\DockerLinux\').State -eq 'Ready') -and ($timer.Elapsed.TotalSeconds -lt $timeout))
{
    Write-Verbose -Message "Re-run scheduled task..."
    
    Start-ScheduledTask -TaskPath '\DockerLinux\' 'Run-Docker-Wsl'
    Start-Sleep -Seconds 3
}
$timer.Stop()
'@
$startupScript | Out-File -FilePath C:\DockerLinux\Startup.ps1

$runScript = @'
& "C:\Program Files\WSL\wsl.exe" '-u' 'root' '-d' 'Docker' 'mount' '--make-shared' '/mnt/c'
& "C:\Program Files\WSL\wsl.exe" '-u' 'root' '-d' 'Docker' '-e' '/bin/bash'
'@
$runScript | Out-File -FilePath C:\DockerLinux\Run.ps1

# install WSL msi
$wslDownloadUrl = Resolve-GithubReleaseAssetUrl `
    -Repo "microsoft/WSL" `
    -Version "latest" `
    -UrlMatchPattern "wsl.*.x64.msi"
Install-Binary -Url $wslDownloadUrl

wsl.exe --install Ubuntu -n --web-download

$wslTries = 0
while ($wslTries -lt 3)
{
    try
    {   
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
        wsl.exe -u root -d Ubuntu apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y '2>&1' '||' echo Failure '1>&2'
        wsl.exe -u root -d Ubuntu systemctl enable docker.service '2>&1' '||' echo Failure '1>&2'
        wsl.exe -u root -d Ubuntu systemctl enable containerd.service '2>&1' '||' echo Failure '1>&2'
        wsl.exe -u root -d Ubuntu systemctl enable ssh.service '2>&1' '||' echo Failure '1>&2'
        
        # expose docker to windows
        wsl.exe -u root -d Ubuntu useradd -c'docker user' -m -s /bin/bash dockerssh
        wsl.exe -u root -d Ubuntu passwd -d dockerssh '2>&1' '||' echo Failure '1>&2'
        wsl.exe -u root -d Ubuntu usermod -a -G docker dockerssh
        wsl.exe -u root -d Ubuntu echo 'PermitEmptyPasswords yes' '|' tee -a /etc/ssh/sshd_config '>' /dev/null
        wsl.exe -u root -d Ubuntu echo 'StrictModes yes' '|' tee -a /etc/ssh/sshd_config '>' /dev/null
        wsl.exe -u root -d Ubuntu echo 'ssh' '|' tee -a /etc/securetty '>' /dev/null
        wsl.exe --shutdown
        wsl.exe -u root -d Ubuntu ln -s /mnt/c /c
        wsl.exe -u root -d Ubuntu ln -s /mnt/d /d
        wsl.exe -u root -d Ubuntu mount --make-shared /mnt/c

        break
    }
    catch
    {
        $wslTries = $wslTries + 1

        If ($wslTries -ge 3)
        {
            throw 'Failed updating and installing Ubuntu and Docker'
        }

        Write-Host 'Failed updating and installing Ubuntu and Docker - retrying...'
        wsl.exe --unregister Ubuntu
    }
}

ssh.exe -o StrictHostKeyChecking=accept-new 'dockerssh@localhost' echo Done
Copy-Item "${Env:USERPROFILE}\.ssh\known_hosts" "${Env:ALLUSERSPROFILE}\ssh\ssh_known_hosts"
Remove-Item "${Env:USERPROFILE}\.ssh\known_hosts"

# set docker host variable
$Env:DOCKER_HOST = "ssh://dockerssh@localhost"
$Env:COMPOSE_CONVERT_WINDOWS_PATHS = 1
[Environment]::SetEnvironmentVariable("DOCKER_HOST", "ssh://dockerssh@localhost", "Machine")
[Environment]::SetEnvironmentVariable("COMPOSE_CONVERT_WINDOWS_PATHS", "1", "Machine")

# export distro
wsl.exe --export Ubuntu 'C:\DockerLinux\docker.tar'

# remove Ubuntu installation
wsl.exe --unregister Ubuntu
$ubuntuPackageName = (Get-AppxPackage | Where-Object { $_.Name -eq 'CanonicalGroupLimited.Ubuntu' }).PackageFullName
Remove-AppxPackage $ubuntuPackageName

# install distribution
Write-Host "Install Ubuntu distribution for Docker"

$dockerUser = 'dockerlinux'
$dockerPassword = [System.GUID]::NewGuid().ToString().ToUpper()
$dockerSecurePassword = ConvertTo-SecureString $dockerPassword -AsPlainText -Force

$params = @{
    Name        = $dockerUser
    Password    = $dockerSecurePassword
    FullName    = 'Docker Linux'
    Description = 'Docker user account.'
}
New-LocalUser @params
Add-LocalGroupMember -Group "Administrators" -Member $dockerUser

$wslInstallAction = New-ScheduledTaskAction 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument 'C:\DockerLinux\Install.ps1'
$wslInstallSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 31)
$principal = New-ScheduledTaskPrincipal -RunLevel Highest $dockerUser -LogonType InteractiveOrPassword
$task = New-ScheduledTask -Action $wslInstallAction -Principal $principal -Settings $wslInstallSettings
Register-ScheduledTask 'Install-Docker-Wsl' -TaskPath '\DockerLinux\' -User $dockerUser -Password $dockerPassword -InputObject $task
Start-ScheduledTask -TaskPath '\DockerLinux\' 'Install-Docker-Wsl'

$timeout = 300 ##  seconds
$timer =  [Diagnostics.Stopwatch]::StartNew()
while (((Get-ScheduledTask -TaskName 'Install-Docker-Wsl' -TaskPath '\DockerLinux\').State -ne 'Ready') -and ($timer.Elapsed.TotalSeconds -lt $timeout))
{
    Write-Verbose -Message "Waiting on scheduled task..."
    Start-Sleep -Seconds  3   
}
$timer.Stop()

Get-Content 'C:\DockerLinux\install.log'

# set automatic start of the distribution
Write-Host "Setup automatic start of Docker distribution"

$wslRunAction = New-ScheduledTaskAction 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument 'C:\DockerLinux\Run.ps1'
$wslRunSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 31)
$principal = New-ScheduledTaskPrincipal -RunLevel Highest $dockerUser -LogonType InteractiveOrPassword
$task = New-ScheduledTask -Action $wslRunAction -Principal $principal -Settings $wslRunSettings
Register-ScheduledTask 'Run-Docker-Wsl' -TaskPath '\DockerLinux\' -User $dockerUser -Password $dockerPassword -InputObject $task

$wslStartAction = New-ScheduledTaskAction 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument 'C:\DockerLinux\Startup.ps1'
$wslStartupTrigger = New-ScheduledTaskTrigger -AtStartup
$wslStartupSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 31)
$principal = New-ScheduledTaskPrincipal -RunLevel Highest $dockerUser -LogonType InteractiveOrPassword
$task = New-ScheduledTask -Action $wslStartAction -Principal $principal -Trigger $wslStartupTrigger -Settings $wslStartupSettings
Register-ScheduledTask 'Start-Docker-Wsl-On-Boot' -TaskPath '\DockerLinux\' -User $dockerUser -Password $dockerPassword -InputObject $task
Start-ScheduledTask -TaskPath '\DockerLinux\' 'Start-Docker-Wsl-On-Boot'

$timeout = 90 ##  seconds
$sshExitCode = 255
$timer =  [Diagnostics.Stopwatch]::StartNew()
while ((((Get-ScheduledTask -TaskName 'Start-Docker-Wsl-On-Boot' -TaskPath '\DockerLinux\').State -ne 'Ready') `
    -or ((Get-ScheduledTask -TaskName 'Run-Docker-Wsl' -TaskPath '\DockerLinux\').State -ne 'Running') `
    -or $sshExitCode -ne 0) `
    -and ($timer.Elapsed.TotalSeconds -lt $timeout))
{
    Write-Verbose -Message "Waiting on scheduled task..."
    Start-Sleep -Seconds  3
    ssh.exe -o StrictHostKeyChecking=accept-new 'dockerssh@localhost' echo Connection Ok
    $sshExitCode = $LASTEXITCODE
}
$timer.Stop()

If ($sshExitCode -ne 0)
{
    throw 'Failed to start Docker linux distribution'
}
