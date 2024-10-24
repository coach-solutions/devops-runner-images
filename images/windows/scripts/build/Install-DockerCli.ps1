################################################################################
##  File:  Install-Docker.ps1
##  Desc:  Install Docker CLI.
################################################################################

Write-Host "Get latest Moby release"
$toolsetVersion = (Get-ToolsetContent).docker.components.docker
$mobyVersion = (Get-GithubReleasesByVersion -Repo "moby/moby" -Version "${toolsetVersion}").version
$dockerceUrl = "https://download.docker.com/win/static/stable/x86_64/"
$dockerceBinaries = Invoke-WebRequest -Uri $dockerceUrl -UseBasicParsing

Write-Host "Check Moby version $mobyVersion"
$mobyRelease = $dockerceBinaries.Links.href -match "${mobyVersion}\.zip" | Select-Object -Last 1
if (-not $mobyRelease) {
    Write-Host "Release not found for $mobyLatestRelease version"
    $versions = [regex]::Matches($dockerceBinaries.Links.href, "docker-(\d+\.\d+\.\d+)\.zip") | Sort-Object { [version] $_.Groups[1].Value }
    $mobyRelease = $versions | Select-Object -ExpandProperty Value -Last 1
    Write-Host "Found $mobyRelease"
}
$mobyReleaseUrl = $dockerceUrl + $mobyRelease

Write-Host "Download Moby $mobyRelease..."
$mobyArchivePath = Invoke-DownloadWithRetry $mobyReleaseUrl
Expand-Archive -Path $mobyArchivePath -DestinationPath $env:TEMP
$dockerPath = "$env:TEMP\docker\docker.exe"
$dockerdPath = "$env:TEMP\docker\dockerd.exe"

Write-Host "Install Docker CLI"
Copy-Item $dockerPath "C:\Windows\System32\docker.exe"
Copy-Item $dockerdPath "C:\Windows\System32\dockerd.exe"

# Fix AZ CLI DOCKER_COMMAND_ERROR
# cli.azure.cli.command_modules.acr.custom: Could not run 'docker.exe' command.
# https://github.com/Azure/azure-cli/issues/18766
New-Item -ItemType SymbolicLink -Path "C:\Windows\SysWOW64\docker.exe" -Target "C:\Windows\System32\docker.exe"

Write-Host "Download latest buildx"
$cliPluginsDir = "C:\ProgramData\docker\cli-plugins"
New-Item -Path $cliPluginsDir -ItemType Directory -Force
$buildxDownloadUrl = Resolve-GithubReleaseAssetUrl `
    -Repo "docker/buildx" `
    -Version "latest" `
    -UrlMatchPattern "buildx-v*.windows-amd64.exe"
Invoke-DownloadWithRetry -Url $buildxDownloadUrl -Path "$cliPluginsDir\docker-buildx.exe"

docker.exe buildx install

Invoke-PesterTests -TestFile "Docker" -TestName "Docker"
