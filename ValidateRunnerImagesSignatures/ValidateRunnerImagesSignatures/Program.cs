﻿using System.Diagnostics;
using System.Text.RegularExpressions;
using ValidateRunnerImagesSignatures;

var curDir = Environment.CurrentDirectory;
var repoDir = Path.GetFullPath(Path.Combine(curDir, "..", "..", "..", "..", ".."));
var buildDir = Path.Combine(repoDir, @"images\windows\scripts\build");
var verifyScript = GatherPowerShell.GatherScriptParts(buildDir);

var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempDir);

var helperFunctions = $@"Import-Module {repoDir}\images\windows\scripts\helpers\ImageHelpers.psm1" + @"
$ErrorActionPreference = ""Stop""

if ( -not(Get-Module -ListAvailable -Name PowerHTML)) {
    Install-Module PowerHTML -Scope CurrentUser -Force
} 
  
if ( -not(Get-Module -Name PowerHTML)) {
    Import-Module PowerHTML
} 

function Validate-Install-Binary {
    Param
    (
        [Parameter(Mandatory, ParameterSetName = ""Url"")]
        [String] $Url,
        [Parameter(Mandatory, ParameterSetName = ""LocalPath"")]
        [String] $LocalPath,
        [ValidateSet(""MSI"", ""EXE"")]
        [String] $Type,
        [String[]] $InstallArgs,
        [String[]] $ExtraInstallArgs,
        [String[]] $ExpectedSignature,
        [String] $ExpectedSHA256Sum,
        [String] $ExpectedSHA512Sum
    )

    if ($PSCmdlet.ParameterSetName -eq ""LocalPath"") {
        if (-not (Test-Path -Path $LocalPath)) {
            throw ""LocalPath parameter is specified, but the file does not exist.""
        }
        if (-not $Type) {
            $Type = ([System.IO.Path]::GetExtension($LocalPath)).Replace(""."", """").ToUpper()
            if ($Type -ne ""MSI"" -and $Type -ne ""EXE"") {
                throw ""LocalPath parameter is specified, but the file extension is not .msi or .exe. Please specify the Type parameter.""
            }
        }
        $filePath = $LocalPath
    } else {
        if (-not $Type) {
            $Type = ([System.IO.Path]::GetExtension($Url)).Replace(""."", """").ToUpper()
            if ($Type -ne ""MSI"" -and $Type -ne ""EXE"") {
                throw ""Cannot determine the file type from the URL. Please specify the Type parameter.""
            }
            $fileName = [System.IO.Path]::GetFileName($Url)
        } else {
            $fileName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()) + "".$Type"".ToLower()
        }
        $filePath = Invoke-DownloadWithRetry -Url $Url -Path ""${env:Temp}\$fileName""
    }

    if ($PSBoundParameters.ContainsKey('ExpectedSignature')) {
        if ($ExpectedSignature) {
            Test-FileSignature -Path $filePath -ExpectedThumbprint $ExpectedSignature
        } else {
            throw ""ExpectedSignature parameter is specified, but no signature is provided.""
        }
    }

    if ($ExpectedSHA256Sum) {
        Test-FileChecksum $filePath -ExpectedSHA256Sum $ExpectedSHA256Sum
    }

    if ($ExpectedSHA512Sum) {
        Test-FileChecksum $filePath -ExpectedSHA512Sum $ExpectedSHA512Sum
    }

    if ($ExtraInstallArgs -and $InstallArgs) {
        throw ""InstallArgs and ExtraInstallArgs parameters cannot be used together.""
    }
}

function Validate-Install-VisualStudio {
    Param
    (
        [Parameter(Mandatory)] [String] $Version,
        [Parameter(Mandatory)] [String] $Edition,
        [Parameter(Mandatory)] [String] $Channel,
        [Parameter(Mandatory)] [String[]] $RequiredComponents,
        [String] $ExtraArgs = """",
        [Parameter(Mandatory)] [String[]] $SignatureThumbprint
    )

    $bootstrapperUrl = ""https://aka.ms/vs/${Version}/${Channel}/vs_${Edition}.exe""
    $channelUri = ""https://aka.ms/vs/${Version}/${Channel}/channel""
    $channelId = ""VisualStudio.${Version}.Release""
    $productId = ""Microsoft.VisualStudio.Product.${Edition}""

    Write-Host ""Downloading Bootstrapper ...""
    $bootstrapperFilePath = Invoke-DownloadWithRetry $BootstrapperUrl

    # Verify that the bootstrapper is signed by Microsoft
    Test-FileSignature -Path $bootstrapperFilePath -ExpectedThumbprint $SignatureThumbprint
}

function Validate-Remove-Item {
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$Path,

        [Parameter(Position=1, ValueFromRemainingArguments)]
        [string[]]$Remaining
    )

    if ($Path.Contains('\temp\', 'InvariantCultureIgnoreCase')) {
        if ($Remaining -eq $null) {
            & Remove-Item -Path $Path
        } else {
            & Remove-Item -Path $Path @Remaining
        }
    } else {
        Write-Host ""Skipping removing""
    }
}

function Validate-Rename-Item {
    param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Path,

        [Parameter(Mandatory, Position=1)]
        [string]$NewName
    )

    if ($Path.Contains('\temp\', 'InvariantCultureIgnoreCase')) {
        & Rename-Item -Path $Path -NewName $NewName
    } else {
        Write-Host ""Skipping renaming""
    }
}

" + $@"$env:IMAGE_FOLDER = '{tempDir}'
$env:AGENT_TOOLSDIRECTORY = '{tempDir}\tools'
$env:TEMP_DIR = '{tempDir}'
$errorActionOldValue = $ErrorActionPreference
Copy-Item -Path ""{repoDir}\images\windows\toolsets\toolset-2022.json"" -Destination ""$env:IMAGE_FOLDER\toolset.json"" -Force
";

verifyScript = Regex.Replace(verifyScript, @"[""'](?:(?:[cC]:)|(?:\$\(\$env:SystemDrive\)))\\(?<restDir>[^""']*)[""']", m =>
{
    if (m.Value.Contains(tempDir) || m.Value.Contains(buildDir))
        return m.Value;

    var newPath = Path.Combine(tempDir, m.Groups["restDir"].Value);

    string newDir;
    if (Path.HasExtension(newPath))
        newDir = Path.GetDirectoryName(newPath)!;
    else
        newDir = newPath;
    Directory.CreateDirectory(newDir);

    return "'" + newPath + "'";
});

var script = helperFunctions + verifyScript;

script = script.Replace("C:\\Windows\\System32", tempDir);
File.WriteAllText(Path.Combine(tempDir, "verify.ps1"), script);

var process = new Process
{
    StartInfo = new ProcessStartInfo
    {
        FileName = "pwsh.exe",
        Arguments = $"-ExecutionPolicy Bypass -File \"{tempDir}\\verify.ps1\"",
        WorkingDirectory = tempDir,
        UseShellExecute = false,
        CreateNoWindow = false
    }
};

process.Start();
process.WaitForExit();

DirectoryInfo dir = new DirectoryInfo(tempDir);
if (dir.Exists)
{
    SetAttributesNormal(dir);
    dir.Delete(true);
}
void SetAttributesNormal(DirectoryInfo dir)
{
    foreach (var subDir in dir.GetDirectories())
        SetAttributesNormal(subDir);

    foreach (var file in dir.GetFiles())
        file.Attributes = FileAttributes.Normal;
}

Console.ReadLine();