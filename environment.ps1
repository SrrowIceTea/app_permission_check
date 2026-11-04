# 当前主机入口；仅用于授权测试。Dot-source: . .\environment.ps1
#
# 2026-09-28 从旧开发机迁到本机后校正。旧机是 OneKyubey 用户 + E:\Android\android-sdk
# + 工程内 .tools\jdk21；本机是 D:\Anroid\SDK + D:\Anroid\JDK，没有 .tools。
# 换机器时只改下面三个 $VScan* 默认值即可，或先设好同名环境变量覆盖。

function Get-VScanSetting([string]$Name, [string]$Default) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name))) { $Default }
    else { [Environment]::GetEnvironmentVariable($Name) }
}

$VScanSdk = Get-VScanSetting 'VSCAN_SDK' "$env:LOCALAPPDATA\Android\Sdk"
$VScanJdk = Get-VScanSetting 'VSCAN_JDK' 'D:\Android\JDK'
# 显式覆盖 > 项目虚拟环境 > 已有实际解释器，禁止回退 WindowsApps 别名。
$VScanDefaultPython = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.venv/Scripts/python.exe')) {
    $VScanDefaultPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
}
$VScanPython = Get-VScanSetting 'VSCAN_PYTHON' $VScanDefaultPython

foreach ($probe in @(@($VScanSdk, 'ANDROID SDK'), @($VScanJdk, 'JDK'), @($VScanPython, 'Python'))) {
    if (-not (Test-Path -LiteralPath $probe[0])) {
        Write-Warning "找不到 $($probe[1])：$($probe[0])（设 VSCAN_SDK / VSCAN_JDK / VSCAN_PYTHON 覆盖）"
    }
}

$env:ANDROID_HOME = $VScanSdk
$env:ANDROID_SDK_ROOT = $VScanSdk
if (Test-Path -LiteralPath $VScanJdk) { $env:JAVA_HOME = $VScanJdk }

# JDK 的本地套接字临时目录必须在纯 ASCII 路径下：工程路径含非 ASCII 会让 NIO 直接失败。
# 目录不存在时 JDK 不报错、只在连本地套接字时炸，所以这里显式建出来。
$VScanTemp = Get-VScanSetting 'VSCAN_TEMP' (Join-Path $PSScriptRoot 'output/java-temp')
New-Item -ItemType Directory -Force -Path $VScanTemp | Out-Null
$env:JAVA_TOOL_OPTIONS = "-Djdk.net.unixdomain.tmpdir=$VScanTemp"

$env:PYTHONUTF8 = '1'
$VScanPythonDir = Split-Path -Parent $VScanPython
$env:PATH = "$VScanSdk\platform-tools;$VScanSdk\emulator;$VScanPythonDir;" +
    (Join-Path $VScanPythonDir 'Scripts') + ';' + $env:PATH

# Gradle 由各工程的 gradlew 包装器提供（发行版已在 ~\.gradle\wrapper\dists 缓存）。
$VScanGradle = (Get-ChildItem -Path (Join-Path $env:USERPROFILE '.gradle\wrapper\dists\gradle-8.13-bin') `
        -Recurse -Filter 'gradle.bat' -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName)
if (-not $VScanGradle) { Write-Warning 'Gradle 8.13 未在 wrapper 缓存中找到；各工程仍可用 gradlew 包装器构建。' }
