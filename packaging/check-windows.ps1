# Run in a clean Windows test account. Arguments are the two MSI paths and versions.
param(
    [Parameter(Mandatory)][string]$FirstMsi,
    [Parameter(Mandatory)][string]$SecondMsi,
    [Parameter(Mandatory)][version]$FirstVersion,
    [Parameter(Mandatory)][version]$SecondVersion
)
$ErrorActionPreference = 'Stop'
$binDir = Join-Path $env:LOCALAPPDATA 'Programs\PeerTTY'
$binary = Join-Path $binDir 'peertty.exe'
$link = Join-Path ([Environment]::GetFolderPath('Programs')) 'PeerTTY.lnk'
$registry = 'HKCU:\Software\PeerTTY\Installer'
$originalPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$processPath = $env:Path
if ((Test-Path $binDir) -or (Test-Path $link) -or (Test-Path $registry)) {
    throw 'Use a clean test account without an existing PeerTTY installation.'
}
$state = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$key = Join-Path $state 'device.key'

function Invoke-Installer($action, $package) {
    $msi = (Resolve-Path -LiteralPath $package).Path
    $process = Start-Process msiexec.exe -ArgumentList "$action `"$msi`" /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "msiexec $action exited with $($process.ExitCode)" }
}

function Test-Installation($version) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($userPath -split ';' | Where-Object { $_.TrimEnd('\') -eq $binDir })
    if ($entries.Count -ne 1) { throw 'Expected exactly one PeerTTY entry in the user PATH.' }
    $env:Path = "$processPath;$userPath"
    if ((Get-Command peertty.exe).Source -ne $binary) { throw 'The command resolves to a different file.' }
    if ((& peertty.exe --version) -ne "PeerTTY $version") { throw 'Unexpected binary version.' }
    if (-not (Test-Path $link)) { throw 'Start menu shortcut missing.' }
    $shell = New-Object -ComObject WScript.Shell
    if ($shell.CreateShortcut($link).TargetPath -ne $binary) { throw 'Shortcut target differs from the installed executable.' }
    '0' | peertty.exe menu -state-dir $state -stun none | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed menu failed.' }
}

$installed = $null
try {
    Invoke-Installer /i $FirstMsi
    $installed = $FirstMsi
    Test-Installation $FirstVersion
    if (-not (Test-Path $key)) { & $binary keygen -out $key | Out-Null }
    $identity = (Get-FileHash -LiteralPath $key).Hash
    Invoke-Installer /i $SecondMsi
    $installed = $SecondMsi
    Test-Installation $SecondVersion
    $fresh = Join-Path $state 'new-profile'
    '0' | & $binary menu -state-dir $fresh -stun none | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Test-Path (Join-Path $fresh 'device.key'))) { throw 'Idle menu generated a device key.' }
    if ((Get-FileHash -LiteralPath $key).Hash -ne $identity) { throw 'Upgrade changed the device key.' }
    Invoke-Installer /x $installed
    $installed = $null
    if ((Test-Path $binary) -or (Test-Path $link)) { throw 'Uninstall left a program or shortcut.' }
    $finalPath = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if ($finalPath.TrimEnd(';') -ne ([string]$originalPath).TrimEnd(';')) { throw 'Uninstall changed the previous PATH.' }
    if ((Get-FileHash -LiteralPath $key).Hash -ne $identity) { throw 'Uninstall changed the device key.' }
    Write-Output "MSI $FirstVersion -> $SecondVersion passed"
} finally {
    $env:Path = $processPath
    if ($installed) { Invoke-Installer /x $installed }
    if (Test-Path $state) { Remove-Item -LiteralPath $state -Recurse -Force }
}
