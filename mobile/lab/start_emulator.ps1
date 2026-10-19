param(
    [Parameter(Mandatory=$true)][string]$Avd,
    [Parameter(Mandatory=$true)][string]$SystemImage,
    [Parameter(Mandatory=$true)][string]$Out,
    [int]$Port=5560
)
# 仅用于授权测试。启动独立审计模拟器，不使用 root、su、系统代理或系统 CA。
# Emulator 37.1.11: radio -tcpdump + netsim Wi-Fi PCAP must both be preserved.
# QEMU filter-dump on virtio-wifi was tested and DID NOT capture this build's Wi-Fi.
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$outputRoot=[IO.Path]::GetFullPath((Join-Path $root 'output'))
$destination=[IO.Path]::GetFullPath($Out)
if (!$destination.StartsWith($outputRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Out must be a dedicated directory inside this checkout output/'
}
if ($Port -lt 5554 -or $Port -gt 5682 -or ($Port % 2) -ne 0) {
    throw 'Port must be an even emulator console port in 5554..5682'
}
$image=(Resolve-Path -LiteralPath $SystemImage).Path
if (!(Test-Path -LiteralPath (Join-Path $image 'system.img'))) { throw 'system.img absent' }
$online=(& adb devices) -join "`n"
if ($online -match "emulator-$Port\s") { throw 'Selected console port already has an adb device' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$radio=Join-Path $destination 'radio.pcap'
if ((Test-Path -LiteralPath $radio) -or (Test-Path -LiteralPath (Join-Path $destination 'emulator-launch.json'))) {
    throw 'Capture already exists; use a new experiment directory'
}
# Refuse ambiguous argument strings; no shell or executable is composed from user data.
if ($destination -match ',|"' -or $image -match '"' -or $Avd -match '"') {
    throw 'These emulator parameters cannot contain quotes or commas'
}
$arguments=@('-avd', ('"'+$Avd+'"'), '-sysdir', ('"'+$image+'"'),
    '-port', $Port, '-no-window', '-no-audio', '-no-snapshot', '-no-boot-anim',
    '-tcpdump', ('"'+$radio+'"'), '-netsim-args', '"--pcap --logtostderr --verbose"', '-verbose')
$process=Start-Process -FilePath (Get-Command emulator.exe).Source -ArgumentList $arguments `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $destination 'emulator.log') `
    -RedirectStandardError (Join-Path $destination 'emulator-error.log')
$record=@{pid=$process.Id;serial="emulator-$Port";avd=$Avd;system_image=$image;
    radio_capture=$radio;netsim_artifacts_hint=(Join-Path $env:TEMP 'netsimd');started_at_utc=[DateTime]::UtcNow.ToString('o');
    root_requested=$false;capture_validation='pending_endpoint_controls';
    scope='radio_and_netsim_WiFi_attempted_not_universal_capture_proof';
    artifact_preservation='stop owned emulator; copy netsim artifacts ZIP before starting another session'}
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'emulator-launch.json') -Encoding utf8
$record | ConvertTo-Json
