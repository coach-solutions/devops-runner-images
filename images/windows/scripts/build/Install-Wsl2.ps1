################################################################################
##  File:  Install-Wsl2.ps1
##  Desc:  Install WSL 2.
################################################################################

Write-Host "Configure WSL 2"
$wslDownloadUrl = Resolve-GithubReleaseAssetUrl `
    -Repo "microsoft/WSL" `
    -Version "latest" `
    -UrlMatchPattern "wsl.*.x64.msi"

Install-Binary -Type MSI -Url $wslDownloadUrl
