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
$pwsh_exe = (Get-Command pwsh.exe).Source.Replace('C:\', '/mnt/c/').Replace('\', '/')
& "C:\Program Files\WSL\wsl.exe" '-u' 'dockerssh' '-d' 'Docker' '/mnt/c/DockerLinux/npipe_socket_adapter.py' '--verbose' 'socket-to-npipe' '-p' "$pwsh_exe" '-s' '/var/run/docker.sock' '-n' 'docker_engine' '2>&1' > C:\DockerLinux\sock.log
'@
$runScript | Out-File -FilePath C:\DockerLinux\Run.ps1

$pipeAdapterScript = @'
#!/usr/bin/python3
# Modified version of https://github.com/0xJonas/npipe_socket_adapter
# This script is distributed under the MIT license.
# See the full license text at the end of the file.

import argparse
import asyncio
import logging
import signal
import subprocess

CONNECTION_SENTINEL = b"Connected!\r\n"

SCRIPT_SERVER = """\

$pipeSecurity = New-Object "System.IO.Pipes.PipeSecurity"
$sid = New-Object "System.Security.Principal.SecurityIdentifier" -ArgumentList @( [System.Security.Principal.WellKnownSidType]::WorldSid, $null )
$accessRule = New-Object "System.IO.Pipes.PipeAccessRule" -ArgumentList @(
    $sid,
    [System.IO.Pipes.PipeAccessRights]::ReadWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
);
$pipeSecurity.AddAccessRule($accessRule)

$pipe = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create(
    "{pipe_name}",
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.NamedPipeServerStream]::MaxAllowedServerInstances,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous,
    0,
    0,
    $pipeSecurity    
)

$pipe.WaitForConnection()
Write-Output "Connected!"
[System.threading.Tasks.Task]::WaitAny(@(
    [System.Console]::OpenStandardInput().CopyToAsync($pipe),
    $pipe.CopyToAsync([System.Console]::OpenStandardOutput())
))
$pipe.Close()
"""

SCRIPT_CLIENT = """\
$pipe = New-Object "System.IO.Pipes.NamedPipeClientStream" -ArgumentList @(
    ".",
    "{pipe_name}",
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::Asynchronous
)
$pipe.Connect()
[System.threading.Tasks.Task]::WaitAny(@(
    [System.Console]::OpenStandardInput().CopyToAsync($pipe),
    $pipe.CopyToAsync([System.Console]::OpenStandardOutput())
))
$pipe.Close()
"""


logger = logging.getLogger("npipe-socket-adapter")
connection_id = 0


async def copy_to_async(reader, writer):
    wait_closed_task = asyncio.create_task(writer.wait_closed())
    while True:
        read_task = asyncio.create_task(reader.read(1024))
        done, _ = await asyncio.wait(
            [read_task, wait_closed_task], return_when=asyncio.FIRST_COMPLETED
        )

        if wait_closed_task in done:
            # Writer was closed
            read_task.cancel()
            break
        elif read_task in done:
            data = read_task.result()
            if data:
                writer.write(data)
                await writer.drain()
            else:
                # reader.read() returned an empty bytes object, so the reader was closed.
                break


def _setup_stop_task():
    event = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGINT, event.set)
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, event.set)
    return asyncio.create_task(event.wait())


async def serve_named_pipe(pipe_name, powershell_exe, callback):
    async def serve_single(proc):
        global connection_id
        nonlocal pipe_free
        cid = connection_id
        connection_id += 1
        logger.info("New connection: %d.", cid)

        callback_task = asyncio.create_task(callback(proc.stdout, proc.stdin))
        done, _ = await asyncio.wait(
            [callback_task, should_terminate], return_when=asyncio.FIRST_COMPLETED
        )
        if should_terminate in done:
            callback_task.cancel()
            proc.terminate()
        await proc.wait()
        logger.info("Connection closed: %d.", cid)
        if pipe_free is not None:
            pipe_free.set()

    logger.info("Serving named pipe %s.", pipe_name)

    should_terminate = _setup_stop_task()

    # Event to signal that the pipe is definitely free.
    # Used to not unnecessarily try connecting to the pipe in a loop.
    pipe_free = None
    while True:
        if pipe_free is not None:
            await pipe_free
            pipe_free = None

        proc = await asyncio.create_subprocess_exec(
            powershell_exe,
            "-NonInteractive",
            "-NoProfile",
            "-Command",
            SCRIPT_SERVER.format(pipe_name=pipe_name),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # Put each subprocess into a new process group.
            # This is used to streamline the code for graceful shutdown.
            # Ctrl+C normally sends SIGINT to the entire process group, which
            # would also stop the subprocesses, while `kill <pid>` sends SIGTERM
            # only to the Python process. Putting each subprocess into its own
            # group means that the signals send by Ctrl+C and `kill <pid>` are both
            # only received by the Python process, and the Python process is in charge
            # of stopping its subprocesses.
            start_new_session=True,
        )
        wait_for_connection_task = asyncio.create_task(
            proc.stdout.readexactly(len(CONNECTION_SENTINEL))
        )

        done, _ = await asyncio.wait(
            [wait_for_connection_task, should_terminate],
            return_when=asyncio.FIRST_COMPLETED,
        )
        if should_terminate in done:
            logger.info("Interrupt received.")
            wait_for_connection_task.cancel()
            proc.terminate()
            await proc.wait()
            break

        if wait_for_connection_task.result() == CONNECTION_SENTINEL:
            asyncio.create_task(serve_single(proc))
        else:
            logger.error("Unable to open named pipe server stream.")
            proc.terminate()
            await proc.terminate()
            pipe_free = asyncio.Event()


async def connect_to_named_pipe(pipe_name, powershell_exe, reader, writer):
    proc = await asyncio.create_subprocess_exec(
        powershell_exe,
        "-NonInteractive",
        "-NoProfile",
        "-Command",
        SCRIPT_CLIENT.format(pipe_name=pipe_name),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    logger.info("Connected to named pipe %s.", pipe_name)
    await asyncio.gather(
        copy_to_async(reader, proc.stdin), copy_to_async(proc.stdout, writer)
    )
    await proc.wait()


async def serve_unix_socket(socket_name, callback):
    async def logging_callback(reader, writer):
        global connection_id
        try:
            cid = connection_id
            connection_id += 1
            logger.info("New connection: %d.", cid)
            await callback(reader, writer)
        finally:
            logger.info("Connection closed: %d.", cid)

    should_terminate = _setup_stop_task()
    server = await asyncio.start_unix_server(logging_callback, socket_name)
    logger.info("Serving UNIX socket %s", socket_name)
    async with server:
        server_task = asyncio.create_task(server.serve_forever())
        done, _ = await asyncio.wait(
            [server_task, should_terminate],
            return_when=asyncio.FIRST_COMPLETED,
        )
        if should_terminate in done:
            logger.info("Interrupt received.")
            server_task.cancel()


async def connect_to_unix_socket(socket_name, reader, writer):
    (socket_reader, socket_writer) = await asyncio.open_unix_connection(socket_name)
    logger.info("Connected to UNIX domain socket %s.", socket_name)
    await asyncio.gather(
        copy_to_async(reader, socket_writer), copy_to_async(socket_reader, writer)
    )
    socket_reader.feed_eof()
    socket_writer.close()


def main():
    parser = argparse.ArgumentParser(
        description="Adapter to convert between Windows named pipes and UNIX domain sockets, in the context of WSL 2."
    )
    parser.add_argument(
        "direction",
        help="""\
Whether to expose an existing Windows named pipe as a UNIX domain socket (npipe-to-socket),
or to expose an existig UNIX domain socket as a Windows named pipe (socket-to-npipe)""",
        choices=["npipe-to-socket", "socket-to-npipe"],
    )
    parser.add_argument(
        "--npipe",
        "-n",
        help=r"Name of the named pipe. The name must NOT include the leading '\\.\pipe\'",
        required=True,
    )
    parser.add_argument(
        "--socket", "-s", help="Name of the UNIX domain socket.", required=True
    )
    parser.add_argument(
        "-p",
        "--powershell",
        help="""\
Location of the Powershell executable to use.
Powershell is used to convert a connection to a named pipe
to standard IO streams.""",
        default="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    )
    parser.add_argument(
        "--verbose", "-v", help="Enable verbose output.", action="store_true"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(message)s",
            level=logging.INFO,
        )

    if args.direction == "npipe-to-socket":
        asyncio.run(
            serve_unix_socket(
                args.socket,
                lambda r, w: connect_to_named_pipe(args.npipe, args.powershell, r, w),
            )
        )
    elif args.direction == "socket-to-npipe":
        asyncio.run(
            serve_named_pipe(
                args.npipe,
                args.powershell,
                lambda r, w: connect_to_unix_socket(args.socket, r, w),
            )
        )


if __name__ == "__main__":
    main()


# MIT License
#
# Copyright (c) 2024 Jonas Rinke
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
'@
$pipeAdapterScript.Replace("`r`n", "`n") | Out-File -FilePath C:\DockerLinux\npipe_socket_adapter.py

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
$Env:COMPOSE_CONVERT_WINDOWS_PATHS = 1
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
    if (Test-Path 'C:\DockerLinux\sock.log') { Get-Content 'C:\DockerLinux\sock.log' }

    throw 'Failed to start Docker linux distribution'
}
