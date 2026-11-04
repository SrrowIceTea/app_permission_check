# 仅用于授权测试（自有设备与已授权 APK）。所有动作共用本机环境解析。
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$VehicleArguments)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'environment.ps1')
Push-Location $PSScriptRoot
try {
    & $VScanPython -m vehicle @VehicleArguments
    exit $LASTEXITCODE
} finally { Pop-Location }
